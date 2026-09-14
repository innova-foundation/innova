// The v2008 mix round announcement. Kept apart from the legacy structures in nullsend.h,
// which serialize on a live wire until Boundary A.

#ifndef INNOVA_NULLSEND_V2008_H
#define INNOVA_NULLSEND_V2008_H

#include <string>
#include <vector>

#include "key.h"
#include "netbase.h"
#include "serialize.h"
#include "privacy_vnext_ffi.h"
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

/** Whether a name is a v3 onion: 56 base32 characters and the suffix. The OUTPUT frame has
 *  no MAC of its own, so a clearnet endpoint over Tor would put the exit on its path. */
bool IsMixOnionEndpoint(const std::string& strEndpoint);

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

    /** The identifier derived from this announcement's contents. Deriving it means a
     *  different key commitment is a different round, so a coordinator cannot sign
     *  equivocating announcements under one round id. */
    uint256 DerivedRoundId() const;

    /** Sets hashRound from the contents before signing: the identifier is derived, never
     *  maintained alongside what it names. */
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
    MIX_FRAME_NONCE           = 8,   // round one of the joint balance signature
    MIX_FRAME_RESPONSE        = 9,   // round two
    MIX_FRAME_VIEW_SIG        = 10,  // a seat's signature over the view it accepted
    MIX_FRAME_TYPE_MAX        = 10,
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

/** A framed connection. One phase uses one of these and then drops it: reusing a
 *  connection across phases hands the coordinator the input-to-output mapping for
 *  free, whatever the blind signature did. */
class CMixStream
{
public:
    CMixStream();
    ~CMixStream();

    /** Takes ownership of an already-connected socket. */
    void Adopt(SOCKET hSocketIn);
    void Close();
    bool IsOpen() const { return hSocket != INVALID_SOCKET; }

    bool Send(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
              std::string* pstrError = NULL);

    /** Reads until one whole frame is available or nTimeoutMs passes. The timeout bounds the
     *  whole frame, not each recv, and the buffer is bounded by one maximum frame. */
    bool Receive(MixFrameType& nTypeOut, std::vector<unsigned char>& vchPayloadOut,
                 int nTimeoutMs, std::string* pstrError = NULL);

private:
    CMixStream(const CMixStream&);
    CMixStream& operator=(const CMixStream&);

    SOCKET hSocket;
    std::vector<unsigned char> vchBuffer;
};

/** Open one phase's connection through a SOCKS proxy. With fIsolate the dial draws
 *  a fresh username/password pair, so Tor puts this phase on its own circuit and a
 *  new connection from the same host is not the same exit address. */
bool DialMixPhase(const CService& addrProxy, const std::string& strEndpoint, int nPort,
                  bool fIsolate, int nTimeoutMs, CMixStream& streamOut,
                  std::string* pstrError = NULL);

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

/** A field added to the OUTPUT frame must not identify the seat, its session or any per-seat
 *  coordinator-chosen value (assume per-seat views and aborted rounds), and must be integrity
 *  bound, canonically encoded, and validated before the token is consumed. */

/** What a token is signed over: the output key it authorises, and NOTHING ELSE.
 *
 *  An unbound token is a bearer token -- an on-path party rewrites the key in an OUTPUT
 *  frame and keeps the value. Binding the key closes that, and costs no unlinkability,
 *  because the coordinator sees this opening only at registration where the key is what
 *  it is being handed anyway.
 *
 *  The round MUST NOT be in here. A first version hashed the round id too, and that made
 *  the credential a seat tag: a coordinator that hands each seat an announcement differing
 *  only in nTime gives each a different round id, then recovers the seat from an
 *  unauthenticated OUTPUT by trying every id it minted against the key it was handed --
 *  one hash per seat. Rounds are separated by the KEY instead: a token verifies only under
 *  the round's own modulus, so a driver must generate a fresh key per round and never
 *  reuse one. That is a driver obligation this function cannot enforce. */
uint256 MixOutputCredentialHash(const uint256& outputKey);

/** One roster entry: a key image and the session key that committed it. */
struct CMixRosterEntry
{
    uint256 keyImage;
    CPubKey pubkeySession;
};

/** The view a seat signs: the announcement and the frozen roster as (key image, session key)
 *  pairs sorted by key image bytes. A complete certificate does not prove the keys belong to
 *  independent participants. */
uint256 MixViewDigest(const uint256& hashAnnouncement,
                      const std::vector<CMixRosterEntry>& vRoster);

/** Sorted by key image in byte order, the order CloseJoin freezes the set in. Returns
 *  false on a duplicate key image or a duplicate session key: one seat, one of each, and
 *  a roster that repeats either is not a roster of n seats. */
bool BuildMixRoster(const std::vector<CMixRosterEntry>& vIn,
                    std::vector<CMixRosterEntry>& vOut);

/** Milliseconds a reader may still spend on the frame it is assembling; zero past the frame's
 *  deadline. The deadline is per frame, not per recv, so a trickling peer cannot extend it. */
int MixReceiveSliceMs(int64_t nDeadlineMs, int64_t nNowMs);

// The round. Blind signatures make the token unlinkable but not the connection, so these
// rules govern who may send what, when, and under which identity.

enum MixRoundPhase
{
    MIX_PHASE_JOIN = 0,     // collecting inputs; the set is not final
    MIX_PHASE_KEYED,        // input set frozen, blind-signature key handed out
    MIX_PHASE_OUTPUT,       // output-registration window open
    MIX_PHASE_SIGN,         // joint balance signature, two passes
    MIX_PHASE_COMPLETE,
    MIX_PHASE_ABORTED,
};

/** How long the output-registration window stays open. Participants wait a random
 *  interval inside it, and the round publishes nothing until it closes, so arrival
 *  order carries no information. */
static const int64_t MIX_OUTPUT_WINDOW = 120;

class CMixParticipant
{
public:
    CPubKey pubkeySession;
    uint256 keyImage;
    bool fTokenIssued;
    /** This seat's position in the frozen, sorted key image set. The joint signature
     *  reads the nonce points in this order, so both sides must agree on it before
     *  any nonce exists. Set by CloseJoin; -1 until then. */
    int nInputIndex;
    std::vector<unsigned char> vchNonce;
    std::vector<unsigned char> vchResponse;
    /** This seat's signature over the view it accepted. Empty until it signs, and it
     *  signs at most once: a second signature, over any view, is refused. */
    std::vector<unsigned char> vchViewSig;

    CMixParticipant() : fTokenIssued(false), nInputIndex(-1) {}
};

class CMixRound
{
public:
    CMixRound();

    /** fStreamIsolated: every phase dials its own circuit; required unless the operator
     *  explicitly opts out. */
    /** nDenominationIn is the amount every output carries; zero registers no outputs. */
    bool Open(const uint256& hashRoundIn, int nTargetParticipantsIn,
              const std::vector<unsigned char>& vchRSA_N_In,
              const std::vector<unsigned char>& vchRSA_E_In,
              bool fStreamIsolatedIn, bool fAllowUnisolatedIn,
              uint64_t nDenominationIn,
              int64_t nNow, std::string* pstrError = NULL);

    /** Register an input under a session key. The key is the participant's identity
     *  for every later authenticated phase, so a phase may arrive on a fresh
     *  connection -- which is what lets each phase have its own circuit. */
    bool Join(const CPubKey& pubkeySession, const uint256& keyImage,
              std::string* pstrError = NULL);

    /** Freeze the input set. The self-pay index every participant derives its output
     *  at binds the sorted key image set, so nothing may join after this and a
     *  participant lost after it invalidates the index for everyone. */
    bool CloseJoin(int64_t nNow, std::string* pstrError = NULL);

    /** Hand a participant the blind-signature key's token. One per participant:
     *  the token is what authorises an output, and two tokens is two outputs. */
    bool IssueToken(const CPubKey& pubkeySession, std::string* pstrError = NULL);

    /** The frozen roster, sorted by key image in byte order. Empty until CloseJoin. */
    const std::vector<CMixRosterEntry>& Roster() const { return vRoster; }

    /** The digest every seat must sign before it will spend a token. Zero until the
     *  roster is frozen, or if the roster does not hold n distinct seats. */
    uint256 ViewDigest(const uint256& hashAnnouncement) const;

    /** A seat's signature over ViewDigest(hashAnnouncement). Refused before the freeze,
     *  from a key that holds no seat, and a second time from the same seat. This is
     *  coordinator-side bookkeeping only; refusing to sign two views is the seat's job. */
    bool SubmitViewSignature(const CPubKey& pubkeySession,
                             const uint256& hashAnnouncement,
                             const std::vector<unsigned char>& vchSig,
                             std::string* pstrError = NULL);

    /** Whether every seat has signed the SAME view. This is the gate a token issuance
     *  should sit behind. What it proves is narrow: see MixViewDigest. */
    bool ViewAgreed(const uint256& hashAnnouncement) const;

    bool OpenOutputWindow(int64_t nNow, std::string* pstrError = NULL);

    /** Register an output against a token, NOT against a session key. Naming the
     *  session here would hand the coordinator the input-to-output mapping the blind
     *  signature exists to withhold, so this call cannot see one. The token must open as
     *  MixOutputCredentialHash(outputKey), so it authorises this key and no other; the
     *  round it belongs to is settled by which modulus verifies it, not by the message. */
    bool RegisterOutput(const std::vector<unsigned char>& vchCredential,
                        const std::vector<unsigned char>& vchBlindSignature,
                        const uint256& outputKey,
                        const PrivacyVNextDigest& commitment,
                        const PrivacyVNextDigest& mask,
                        int64_t nNow,
                        std::string* pstrError = NULL);

    /** Every output's opening in registration (output) order, for PrivacyVNextMixBalanceCombine.
     *  Only the sum enters the proof, so each opening is checked against its commitment before
     *  the token is spent. */
    const std::vector<PrivacyVNextDigest>& OutputMasks() const { return vOutputMasks; }
    const std::vector<PrivacyVNextDigest>& OutputCommitments() const
    {
        return vOutputCommitments;
    }

    /** Whether the assembled transaction may be handed out: only once the window has
     *  closed and every seat has an output. Publishing earlier orders the two lists
     *  by arrival. */
    bool CanPublish(int64_t nNow) const;

    // -- The joint balance signature. No one holds the total excess mask: each seat publishes a
    // nonce point and responds under the aggregate challenge. A round signs once; a second
    // attempt (which could extract a reused nonce's mask) ends it.

    /** Move to signing. Only once the window has closed with every seat's output in,
     *  because the signable hash covers the outputs. */
    bool OpenSigning(int64_t nNow, std::string* pstrError = NULL);

    bool SubmitNonce(const CPubKey& pubkeySession,
                     const std::vector<unsigned char>& vchNonce,
                     std::string* pstrError = NULL);

    /** Fix the aggregate. After this no nonce may be added or replaced: moving one
     *  would move the challenge every seat already responded under. */
    bool FreezeNonces(std::string* pstrError = NULL);
    bool NoncesAreFrozen() const { return fNoncesFrozen; }

    bool SubmitResponse(const CPubKey& pubkeySession,
                        const std::vector<unsigned char>& vchResponse,
                        std::string* pstrError = NULL);

    bool SigningComplete() const;

    /** Nonce points in input-index order, which is what the combine reads. Empty
     *  until every seat has submitted. */
    std::vector<std::vector<unsigned char> > NoncesInInputOrder() const;
    std::vector<std::vector<unsigned char> > ResponsesInInputOrder() const;

    /** A participant that goes away. Before the input set is frozen this is an
     *  ordinary withdrawal; after it the index no longer matches, so the round ends
     *  rather than producing a payload nobody can spend. */
    void Drop(const CPubKey& pubkeySession);

    void Abort(const std::string& strReason);

    MixRoundPhase Phase() const { return nPhase; }
    /** The round this object is. Every frame is judged against THIS, never against an id
     *  a caller passes in: a driver holding several rounds with one stale id variable would
     *  otherwise let one round's frames verify in another. */
    const uint256& RoundId() const { return hashRound; }
    const std::string& AbortReason() const { return strAbortReason; }
    size_t Seats() const { return vParticipants.size(); }
    size_t Outputs() const { return vOutputs.size(); }
    /** The frozen input set, sorted, which the self-pay index binds. Empty until
     *  CloseJoin. */
    const std::vector<uint256>& FinalKeyImages() const { return vFinalKeyImages; }
    bool IsExpired(int64_t nNow) const;

private:
    bool Require(MixRoundPhase nExpected, std::string* pstrError);

    MixRoundPhase nPhase;
    uint256 hashRound;
    int nTargetParticipants;
    std::vector<unsigned char> vchRSA_N;
    std::vector<unsigned char> vchRSA_E;
    bool fStreamIsolated;
    bool fNoncesFrozen;
    bool fHasSigned;
    int64_t nOpened;
    int64_t nWindowCloses;
    std::string strAbortReason;
    std::vector<CMixParticipant> vParticipants;
    std::vector<CMixRosterEntry> vRoster;
    std::vector<uint256> vFinalKeyImages;
    std::vector<uint256> vOutputs;
    std::vector<PrivacyVNextDigest> vOutputCommitments;
    std::vector<PrivacyVNextDigest> vOutputMasks;
    std::vector<uint256> vSpentCredentials;
    uint64_t nDenomination;
};

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------
//
// Which frames carry a session key is the design. JOIN, NONCE and RESPONSE are
// authenticated: they act on a named seat, so the coordinator has to know which.
// OUTPUT is not, and there is nowhere in its body to put a key -- an authenticated
// output registration would hand over the input-to-output mapping the blind
// signature exists to withhold.
//
// This is NOT the whole frame set, and an earlier version of this comment claimed it
// was. Four of the nine declared types have no handler on either side, and the round
// cannot be driven without them: no frame issues a token (IssueToken has only test
// callers and BLIND_REQUEST falls through to the refusal), the OUTPUT body carries no
// field for the output opening the combiner needs, nothing conveys the frozen key-image
// set a seat derives its index from, and Drop is written for a wire-driven leave that
// has no frame. doc/nullsend-v2008-wire.md specifies what is settled and what is not.
//
// Do not add frames before the announcement model is settled. A coordinator can still
// hand each seat its own announcement, and until a participant can establish that its
// co-seats hold the same one, every frame written against the current model is written
// against a model that has to change.

/** Body of an authenticated frame, with the session signature split off its tail.
 *  Returns false on any payload that is not exactly one body plus one signature. */
bool SplitAuthedMixFrame(const std::vector<unsigned char>& vchPayload,
                         std::vector<unsigned char>& vchBodyOut,
                         std::vector<unsigned char>& vchSigOut);

bool BuildAuthedMixFrame(const CKey& key, const uint256& hashRound, MixFrameType nType,
                         const std::vector<unsigned char>& vchBody,
                         std::vector<unsigned char>& vchPayloadOut);

/** A seat's join: its session public key and the key image of the note it spends. */
bool BuildMixJoinBody(const CPubKey& pubkeySession, const uint256& keyImage,
                      std::vector<unsigned char>& vchOut);
/** A 32-byte scalar or point under a session key: NONCE and RESPONSE share the shape. */
bool BuildMixScalarBody(const CPubKey& pubkeySession, const std::vector<unsigned char>& vch32,
                        std::vector<unsigned char>& vchOut);
/** A seat's view signature: its session key, the announcement it holds, and its
 *  signature over the resulting view digest. Authenticated, because it acts on a
 *  named seat -- the anonymity this protects is the OUTPUT side, not the input side. */
bool BuildMixViewSigBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                         const std::vector<unsigned char>& vchViewSig,
                         std::vector<unsigned char>& vchOut);

/** A seat's request for its token: its session key, the announcement it holds, and the
 *  blinded credential. Authenticated -- issuance is per-seat by design, so the
 *  coordinator has to know whose one token it is spending. If this is ever made
 *  unauthenticated, any connection can take tokens without holding a seat and each one
 *  registers an output, which is a free round-kill. */
bool BuildMixBlindRequestBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                              const std::vector<unsigned char>& vchBlinded,
                              std::vector<unsigned char>& vchOut);

/** The frozen key-image set, coordinator to seat. Must be in 32-byte-array order (as
 *  PrivacyVNextChangeIndexFor sorts), not uint256 order; the reader refuses unsorted sets. */
bool BuildMixKeySetBody(const std::vector<uint256>& vKeyImages,
                        std::vector<unsigned char>& vchOut);

/** Parses a key-set frame. Refuses a set that is not already sorted in byte order, or
 *  that repeats an image: a seat must reject a set it would have to reorder, because
 *  reordering is how the two derivations silently disagree. */
bool ReadMixKeySetBody(const std::vector<unsigned char>& vchIn,
                       std::vector<uint256>& vOut);

/** An output registration: a token, a one-time key, the output's commitment and its
 *  opening -- and no identity. The opening is here because the joint balance proof is
 *  combined from it and no authenticated frame can carry it without naming the seat's
 *  output. It is checked against the commitment before the token is spent. */
bool BuildMixOutputBody(const std::vector<unsigned char>& vchCredential,
                        const std::vector<unsigned char>& vchBlindSignature,
                        const uint256& outputKey,
                        const PrivacyVNextDigest& commitment,
                        const PrivacyVNextDigest& mask,
                        std::vector<unsigned char>& vchOut);

enum MixDispatch
{
    MIX_DISPATCH_OK = 0,
    MIX_DISPATCH_REFUSED,     // the frame was not acted on; the round is unharmed
    MIX_DISPATCH_ABORTED,     // the round ended as a result
};

/** Act on one frame from a participant. */
MixDispatch DispatchMixFrame(CMixRound& round,
                             MixFrameType nType,
                             const std::vector<unsigned char>& vchPayload,
                             int64_t nNow, std::string& strError);

#endif // INNOVA_NULLSEND_V2008_H
