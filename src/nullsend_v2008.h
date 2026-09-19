// The v2008 mix round announcement. Kept apart from the legacy structures in nullsend.h,
// which serialize on a live wire until Boundary A.

#ifndef INNOVA_NULLSEND_V2008_H
#define INNOVA_NULLSEND_V2008_H

#include <map>
#include <string>
#include <vector>

#include "key.h"
#include "main.h"
#include "nullsend.h"
#include "netbase.h"
#include "serialize.h"
#include "privacy_vnext_ffi.h"
#include "privacy_vnext_builder.h"
#include "privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "uint256.h"
#include "util.h"


/** How long a peer may take to accept one frame before the sender gives up on it. */
static const int MIX_SEND_TIMEOUT_MS = 30000;

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

/** Bounds on one window of a round's schedule. A window shorter than the work it covers
 *  kills every round on a slow seat, which selects for fast seats and is a deanonymising
 *  filter, not a usability problem; one longer than it needs holds the anchor open. */
static const int MIX_WINDOW_MIN_SECS = 15;
static const int MIX_WINDOW_MAX_SECS = 900;
/** The proving window covers one input's membership proof. A one-input prove measures
 *  ~2.5 s on a 48-core host and proving is single-threaded, so a slow wallet is minutes:
 *  this floor is a floor, not a target. */
static const int MIX_PROOF_WINDOW_MIN_SECS = 60;

/** JOIN is the only window a seat enters cold (chain read, announcement fetch, no circuit),
 *  so it has its own floor above the generic one. */
static const int MIX_JOIN_WINDOW_MIN_SECS = 60;

/** How far into its own slot a round must start. A seat cannot act on a slot until the
 *  finalized chain has passed the slot's opening, and median time past and finality both lag,
 *  so a round starting AT the opening is one honest seats reach late -- the same "only seats
 *  told in advance" outcome as a short join window, by a different route. Half a slot leaves
 *  the settle-and-fetch time on one side and the round's own start on the other. */
static const int64_t MIX_RENDEZVOUS_MIN_START_SLACK = 300;
/** How long the round may keep answering after it has published. Terminal is the only window
 *  after the broadcast, so it spends no anchor life. */
static const int MIX_SCHEDULE_MAX_TERMINAL_SECS = 900;

/** The round's anchor is frozen when the announcement is signed, so everything from signing
 *  to the transaction being connected spends that anchor's life:
 *
 *      (slot opening - signing)      <= 600   one slot of publication lead
 *    + start offset in the slot       300..599
 *    + the windows up to broadcast   <= 480   this bound
 *    + inclusion                      = 120   MIX_INCLUSION_ALLOWANCE_SECS
 *
 *  This cap is the static half, checked before anything else. The chain half is
 *  CheckMixAnchorBudget, which a seat runs before it reveals a key image: an anchor taken as the
 *  head at signing lasts 1500..1800 blocks with finality current, and a seat projecting at the
 *  margin rate refuses a long schedule under a late start or an early signature.
 *
 *  A schedule that does not fit produces a transaction ConnectBlock refuses AFTER every seat
 *  has revealed a key image and proved its input. The loss is what they disclosed and the
 *  work they did, not the value of the notes -- a refused transaction spends nothing -- but
 *  the disclosure is the part that cannot be taken back, so the round is refused up front.
 *
 *  The long-term fix is an announcement that commits to an anchor RULE rather than an anchor
 *  value, resolved once and frozen into the view certificate before any proving; that removes
 *  publication-lead ageing entirely. */
static const int MIX_SCHEDULE_MAX_TO_BROADCAST_SECS = 480;

/** How long a finished transaction is given to be mined after the last response. */
static const int64_t MIX_INCLUSION_ALLOWANCE_SECS = 120;

/** The rate at which a seat turns seconds into blocks when it projects its anchor forward:
 *  three blocks every two seconds. The target is one a second; the margin covers a hash-rate
 *  surge the retarget has not caught, which consensus does not bound below six a second. */
static const int64_t MIX_ANCHOR_BLOCKS_PER_SEC_NUM = 3;
static const int64_t MIX_ANCHOR_BLOCKS_PER_SEC_DEN = 2;

/** The last height at which consensus is certain to accept an anchor from nAnchorEpoch that
 *  it accepts now, however finality moves (EPOCHSTATE_VNEXT_MIN_HEAD_LAG_EPOCHS). */
int MixAnchorSafeThroughHeight(int nAnchorEpoch);

class CMixRoundAnnouncement
{
public:
    static const int CURRENT_VERSION = 2;

    int nVersion;
    uint256 hashRound;
    uint256 hashRoundKey;
    std::string strEndpoint;
    int nPort;
    int nParticipants;
    int64_t nTime;
    CPubKey pubkeyCoordinator;

    // The transcript. Every seat must hold the same anchor, denomination and fee; signed and
    // covered by the derived identifier, so an edited copy is a different round.
    uint8_t nNetwork;
    PrivacyVNextDigest genesis;
    PrivacyVNextDigest parameterDigest;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nFinalizedTreeSize;
    uint64_t nDenomination;
    uint64_t nFee;

    // The schedule, in seconds after nTime. Deadlines live in the announcement, not in coordinator
    // replies, so every seat derives the same instants and the coordinator cannot time seats apart.
    uint16_t nJoinSecs;
    uint16_t nViewSecs;
    uint16_t nTokenSecs;
    uint16_t nOutputSecs;
    uint16_t nApproveSecs;
    uint16_t nNonceSecs;
    uint16_t nResponseSecs;
    uint16_t nTerminalSecs;

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
        nNetwork = 0;
        genesis.fill(0);
        parameterDigest.fill(0);
        finalizedRoot.fill(0);
        nFinalizedTreeSize = 0;
        nDenomination = 0;
        nFee = 0;
        nJoinSecs = 0;
        nViewSecs = 0;
        nTokenSecs = 0;
        nOutputSecs = 0;
        nApproveSecs = 0;
        nNonceSecs = 0;
        nResponseSecs = 0;
        nTerminalSecs = 0;
        vchSig.clear();
    }

    // The instants every seat derives, rather than is told.
    int64_t JoinCloses() const { return nTime + (int64_t)nJoinSecs; }
    int64_t ViewCloses() const { return JoinCloses() + (int64_t)nViewSecs; }
    int64_t TokenCloses() const { return ViewCloses() + (int64_t)nTokenSecs; }
    int64_t OutputCloses() const { return TokenCloses() + (int64_t)nOutputSecs; }
    int64_t ApproveCloses() const { return OutputCloses() + (int64_t)nApproveSecs; }
    int64_t NonceCloses() const { return ApproveCloses() + (int64_t)nNonceSecs; }
    int64_t ResponseCloses() const { return NonceCloses() + (int64_t)nResponseSecs; }
    /** When the round stops answering at all. */
    int64_t Ends() const { return ResponseCloses() + (int64_t)nTerminalSecs; }

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
        READWRITE(FLATDATA(nNetwork));
        READWRITE(FLATDATA(genesis));
        READWRITE(FLATDATA(parameterDigest));
        READWRITE(FLATDATA(finalizedRoot));
        READWRITE(nFinalizedTreeSize);
        READWRITE(nDenomination);
        READWRITE(nFee);
        READWRITE(nJoinSecs);
        READWRITE(nViewSecs);
        READWRITE(nTokenSecs);
        READWRITE(nOutputSecs);
        READWRITE(nApproveSecs);
        READWRITE(nNonceSecs);
        READWRITE(nResponseSecs);
        READWRITE(nTerminalSecs);
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

    /** Joinable only inside its own join window, and dead once the schedule ends. */
    bool IsJoinable(int64_t nNow) const { return nNow >= nTime && nNow < JoinCloses(); }
    bool IsExpired(int64_t nNow) const { return nNow > Ends(); }

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
    MIX_FRAME_INPUT_CONSTRUCTION = 11,  // a seat's pseudo-output for its joined key image
    MIX_FRAME_TRANSACTION_PREFIX = 12,  // the complete prefix every seat must approve
    MIX_FRAME_PREFIX_SIG      = 13,  // a seat's signature over the prefix it approved
    MIX_FRAME_MEMBERSHIP_PROOF = 14, // a seat's membership proof for its input
    MIX_FRAME_STATE           = 15,  // anyone -> coordinator: how far has the round got
    MIX_FRAME_STATE_AUTH      = 16,  // a seat -> coordinator: the same, in full
    MIX_FRAME_SNAPSHOT        = 17,  // the reply to either
    MIX_FRAME_ACK             = 18,  // the reply to anything that changes the round
    MIX_FRAME_RESULT          = 19,  // anyone -> coordinator: the finished transaction
    MIX_FRAME_TYPE_MAX        = 19,
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

    /** nTimeoutMs bounds the whole frame, as Receive's does. Without one a peer that
     *  stops reading holds the sender in send() forever, and a service loop with one
     *  thread per connection is then stalled by any seat that wants it to be. */
    bool Send(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
              std::string* pstrError = NULL, int nTimeoutMs = MIX_SEND_TIMEOUT_MS);

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

/** The coordinator's listening socket, forwarded to by its hidden service; one stream per
 *  connection. Binds to loopback only, so the coordinator's address is never published. */
class CMixListener
{
public:
    CMixListener();
    ~CMixListener();

    /** Binds 127.0.0.1:nPort and listens. Port 0 takes any free port, readable from
     *  Port() afterwards, which is what a test uses. */
    bool Listen(int nPort, std::string* pstrError = NULL);
    void Close();
    bool IsOpen() const { return hListen != INVALID_SOCKET; }
    int Port() const { return nBoundPort; }

    /** Waits up to nTimeoutMs for one connection. Returns false with no error set when
     *  the wait simply expired, so a service loop can tell "nobody called" from "the
     *  listener is broken". */
    bool Accept(CMixStream& streamOut, int nTimeoutMs, std::string* pstrError = NULL);

private:
    CMixListener(const CMixListener&);
    CMixListener& operator=(const CMixListener&);

    SOCKET hListen;
    int nBoundPort;
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

/** Everything one mix output puts on the chain, as its participant generated it. No position:
 *  the coordinator orders outputs, and a seat-chosen position would name the seat. */
struct CMixOutputRecord
{
    PrivacyVNextDigest owner;
    PrivacyVNextDigest commitment;
    PrivacyVNextDigest noteEphemeral;
    PrivacyVNextDigest tweakEphemeral;
    std::vector<unsigned char> vchRecipientCiphertext;
    std::vector<unsigned char> vchOutgoingCiphertext;
    PrivacyVNextDigest mask;

    CMixOutputRecord()
    {
        owner.fill(0);
        commitment.fill(0);
        noteEphemeral.fill(0);
        tweakEphemeral.fill(0);
        mask.fill(0);
    }
    uint256 OwnerKey() const;
};

static const size_t MIX_OUTPUT_RECORD_BYTES =
    5 * 32 + INNOVA_PRIVACY_VNEXT_RECIPIENT_CIPHERTEXT_SIZE +
    INNOVA_PRIVACY_VNEXT_OUTGOING_CIPHERTEXT_SIZE;

/** The one canonical byte form: fixed-width fields in the order above. Refuses a record
 *  whose ciphertexts are not exactly the sizes a payload carries. */
bool EncodeMixOutputRecord(const CMixOutputRecord& record, std::vector<unsigned char>& vchOut);
bool DecodeMixOutputRecord(const std::vector<unsigned char>& vchIn, CMixOutputRecord& recordOut);

/** A seat's bundle: one complete record per transaction position, in position order.
 *  Output encryption binds the position and an anonymous seat cannot know its position in
 *  advance, so it registers every position; the round keeps the assigned one. */
bool EncodeMixOutputBundle(const std::vector<CMixOutputRecord>& vBundle,
                           std::vector<unsigned char>& vchOut);
bool DecodeMixOutputBundle(const std::vector<unsigned char>& vchIn,
                           std::vector<CMixOutputRecord>& vBundleOut);

/** One bundle of variants for one recipient: the same amount, opening and commitment at
 *  every position, with the position-dependent parts generated for that position and fresh
 *  ephemeral secrets per variant. The caller supplies the secrets, one pair per position. */
bool BuildMixOutputBundle(uint8_t nNetwork, const PrivacyVNextDigest& genesis,
                          const PrivacyVNextDigest& recipientSpend,
                          const PrivacyVNextDigest& recipientView,
                          const PrivacyVNextDigest& outgoingSecret,
                          const PrivacyVNextDigest& inputContext, uint64_t nAmount,
                          const PrivacyVNextDigest& y, const PrivacyVNextDigest& mask,
                          const std::vector<std::pair<PrivacyVNextDigest, PrivacyVNextDigest> >& vEphemerals,
                          std::vector<CMixOutputRecord>& vBundleOut, std::string& strError);

/** Token message: the canonical encoding of the whole bundle, length included; zero for a
 *  malformed bundle. Must not include the round, session key or seat index (per-seat tags);
 *  rounds are separated by the key, so a driver uses a fresh key per round. */
uint256 MixOutputBundleCredentialHash(const std::vector<CMixOutputRecord>& vBundle);

/** A mix prefix, parsed. Strict: only the NullSend layout at the NullSend disclosure mask,
 *  with nothing after the empty finality body. */
struct CMixPrefixView
{
    uint8_t nOperation;
    uint8_t nDisclosureMask;
    uint8_t nNetwork;
    PrivacyVNextDigest genesis;
    PrivacyVNextDigest parameterDigest;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nFinalizedTreeSize;
    int64_t nTransparentValueBalance;
    uint64_t nFee;
    PrivacyVNextDigest transparentBinding;
    std::vector<PrivacyVNextDigest> vPseudoOuts;
    std::vector<uint256> vKeyImages;
    std::vector<CMixOutputRecord> vOutputs;  // the disclosed mask folded into each record
    std::vector<uint64_t> vAmounts;

    CMixPrefixView()
        : nOperation(0), nDisclosureMask(0), nNetwork(0), nFinalizedTreeSize(0),
          nTransparentValueBalance(0), nFee(0) {}
};

bool ParseMixPrefix(const std::vector<unsigned char>& vchPrefix, CMixPrefixView& viewOut,
                    std::string& strError);

/** What a seat knows independently of the coordinator, and holds a prefix to. */
struct CMixSeatExpectation
{
    uint8_t nNetwork;
    PrivacyVNextDigest genesis;
    PrivacyVNextDigest parameterDigest;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nFinalizedTreeSize;
    uint64_t nFee;
    uint64_t nDenomination;
    PrivacyVNextDigest transparentBinding;
    std::vector<uint256> vRosterKeyImages;   // the roster the seat signed the view over
    uint256 myKeyImage;
    PrivacyVNextDigest myPseudoOut;
    /** The seat's own output records, each with the position it is valid at, or -1 where
     *  any position will do. Exactly one of them must appear, at that position. */
    std::vector<std::pair<int, CMixOutputRecord> > vMyOutputs;

    CMixSeatExpectation() : nNetwork(0), nFinalizedTreeSize(0), nFee(0), nDenomination(0) {}
};

/** A seat's check of the whole prefix before it proves or signs: fixed fields, inputs against
 *  the roster, its own construction, output count, amounts and openings, no duplicates, and
 *  exactly one copy of its own output. */
bool CheckMixPrefixForSeat(const std::vector<unsigned char>& vchPrefix,
                           const CMixSeatExpectation& expect, std::string& strError);

/** The transparent binding of a mix transaction: no inputs, no outputs, lock time zero. */
PrivacyVNextDigest MixTransparentBinding();

/** The transaction that carries a mix payload: the v2008 version, no transparent side, lock
 *  time zero, stamped with the caller's time. Refused unless the payload is a mix whose
 *  declared binding is this transaction's. */
bool BuildMixTransaction(const std::vector<unsigned char>& vchPayload, uint32_t nTime,
                         CTransaction& txOut, std::string& strError);

/** What a seat signs to approve a prefix: the view it agreed and the prefix's signing hash,
 *  so a certificate over one prefix cannot be presented for another or under another view. */
uint256 MixPrefixDigest(const uint256& hashView, const PrivacyVNextDigest& signingHash);

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
    /** This seat's signature approving the frozen prefix; empty until it signs, once. */
    std::vector<unsigned char> vchPrefixSig;
    /** This seat's one-input membership proof under the approved prefix; empty until it
     *  arrives and verifies, and taken once. */
    std::vector<unsigned char> vchMembershipProof;
    /** The pseudo-output this seat's input will carry in the prefix, submitted on its
     *  authenticated channel once the view is agreed. It is input-side data the
     *  transaction publishes against this key image anyway, so it names nothing new. */
    PrivacyVNextDigest pseudoOut;
    bool fHavePseudoOut;

    CMixParticipant() : fTokenIssued(false), nInputIndex(-1), fHavePseudoOut(false)
    {
        pseudoOut.fill(0);
    }
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

    /** A seat's pseudo-output for the key image it joined with. Accepted only after every seat
     *  signed the same view, once per seat, and never a pseudo-output already submitted. */
    bool SubmitInputConstruction(const CPubKey& pubkeySession,
                                 const uint256& hashAnnouncement,
                                 const uint256& keyImage,
                                 const PrivacyVNextDigest& pseudoOut,
                                 std::string* pstrError = NULL);
    bool InputConstructionsComplete() const;
    /** Pseudo-outputs in input order, the order the prefix writes them. Empty until every
     *  seat has submitted one. */
    std::vector<PrivacyVNextDigest> PseudoOutsInInputOrder() const;

    /** The prefix every seat approves before any proof or nonce, built by the payload builder's
     *  assembler. Refuses anything but a NullSend operation at the NullSend mask with no
     *  transparent crossing, and refuses until every construction and output is in. */
    bool AssemblePrefix(const PrivacyVNextPrefixHeader& header,
                        std::vector<unsigned char>& vchPrefixOut,
                        std::string* pstrError = NULL) const;

    /** Fix the prefix the seats will approve: it must be exactly what AssemblePrefix writes
     *  from the round's state under this header, and the announcement must be the view the
     *  seats agreed. Once only; the prefix cannot change underneath a certificate. */
    bool FreezePrefix(const PrivacyVNextPrefixHeader& header, const uint256& hashAnnouncement,
                      std::string* pstrError = NULL);
    const std::vector<unsigned char>& FrozenPrefix() const { return vchFrozenPrefix; }
    /** The announcement the frozen prefix was fixed under; zero until it is. */
    const uint256& PrefixAnnouncement() const { return hashPrefixAnnouncement; }
    /** The digest every seat signs; zero until the prefix is frozen. */
    uint256 PrefixDigest() const;
    bool SubmitPrefixSignature(const CPubKey& pubkeySession, const std::vector<unsigned char>& vchSig,
                               std::string* pstrError = NULL);
    /** Whether every seat has signed the frozen prefix. Nonces wait for this. */
    bool PrefixAgreed() const;

    /** The two certificates, in input order, and only once complete. A seat that sees one
     *  knows the round may go on; a partial list would name the seat that has not moved. */
    std::vector<std::vector<unsigned char> > ViewCertificate(const uint256& hashAnnouncement) const;
    std::vector<std::vector<unsigned char> > PrefixCertificate() const;

    /** A seat's membership proof for its own input, verified on arrival against the approved
     *  prefix's root and signing hash and the seat's own construction, exactly as the
     *  payload's membership section is checked. A proof that fails names its seat. */
    bool SubmitMembershipProof(const CPubKey& pubkeySession, const std::vector<unsigned char>& vchProof,
                               std::string* pstrError = NULL);
    bool MembershipProofsComplete() const;
    /** Every seat's proof concatenated in input order; empty until all are in. */
    std::vector<unsigned char> MembershipSection() const;

    /** The complete mix payload, validated in full (proofs included) before it is returned, so
     *  wrong shares yield no payload rather than one the network refuses. */
    bool AssemblePayload(std::vector<unsigned char>& vchPayloadOut,
                         std::string* pstrError = NULL) const;

    /** The round is over and its transaction is out. Refused before the signature is complete. */
    bool MarkComplete(std::string* pstrError = NULL);

    /** Opens the anonymous window. The close instant is passed in from the announcement's
     *  schedule so it matches the one the seats derived. */
    bool OpenOutputWindow(int64_t nNow, int64_t nClosesAt, std::string* pstrError = NULL);

    /** Register an output against a token, never a session key (that would reveal the
     *  input-to-output mapping). The token must open as MixOutputBundleCredentialHash(vBundle);
     *  the modulus that verifies it settles the round. */
    bool RegisterOutput(const std::vector<unsigned char>& vchCredential,
                        const std::vector<unsigned char>& vchBlindSignature,
                        const std::vector<CMixOutputRecord>& vBundle,
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
    /** The complete registered outputs, in registration order. */
    const std::vector<CMixOutputRecord>& OutputRecords() const { return vOutputRecords; }

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
    const std::vector<CMixParticipant>& Participants() const { return vParticipants; }
    const std::string& AbortReason() const { return strAbortReason; }
    size_t Seats() const { return vParticipants.size(); }
    int TargetParticipants() const { return nTargetParticipants; }
    uint64_t Denomination() const { return nDenomination; }
    int64_t Opened() const { return nOpened; }
    /** When the output window closes, which is when signing may open. Zero until it opens. */
    int64_t WindowCloses() const { return nWindowCloses; }
    bool StreamIsolated() const { return fStreamIsolated; }
    const std::vector<unsigned char>& RsaModulus() const { return vchRSA_N; }
    const std::vector<unsigned char>& RsaExponent() const { return vchRSA_E; }
    /** The seat a session key holds, or -1. Input-side only: nothing that touches an output
     *  may call it, or the coordinator learns which seat registered which output. */
    int SeatFor(const CPubKey& pubkeySession) const;
    size_t Outputs() const { return vOutputs.size(); }
    /** The frozen input set, sorted, which the self-pay index binds. Empty until
     *  CloseJoin. */
    const std::vector<uint256>& FinalKeyImages() const { return vFinalKeyImages; }
    /** Past the end of the schedule it was opened under. The round holds no announcement,
     *  so the caller supplies the instant its schedule ends. */
    bool IsExpired(int64_t nNow, int64_t nEnds) const;

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
    std::vector<CMixOutputRecord> vOutputRecords;
    std::vector<unsigned char> vchFrozenPrefix;
    PrivacyVNextDigest prefixSigningHash;
    PrivacyVNextDigest prefixFinalizedRoot;
    uint256 hashPrefixAnnouncement;
    std::vector<uint256> vSpentCredentials;
    uint64_t nDenomination;
};

// Dispatch. Every input-side frame is authenticated with the session key; OUTPUT is not, as
// that would reveal the input-to-output mapping. See doc/nullsend-v2008-wire.md.

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

/** A seat's input construction: the announcement, its key image and its pseudo-output.
 *  Authenticated like every input-side frame. */
bool BuildMixInputConstructionBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                                   const uint256& keyImage, const PrivacyVNextDigest& pseudoOut,
                                   std::vector<unsigned char>& vchOut);

/** The coordinator's prefix frame: the complete prefix bytes, length-prefixed. */
bool BuildMixPrefixBody(const std::vector<unsigned char>& vchPrefix, std::vector<unsigned char>& vchOut);
bool ReadMixPrefixBody(const std::vector<unsigned char>& vchIn, std::vector<unsigned char>& vchPrefixOut);
/** A seat's approval of the frozen prefix: its signature over MixPrefixDigest. */
bool BuildMixPrefixSigBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                           const std::vector<unsigned char>& vchSig, std::vector<unsigned char>& vchOut);
bool BuildMixMembershipProofBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                                 const std::vector<unsigned char>& vchProof,
                                 std::vector<unsigned char>& vchOut);

bool BuildMixBlindRequestBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                              const std::vector<unsigned char>& vchBlinded,
                              std::vector<unsigned char>& vchOut);

/** The frozen roster, coordinator to seat: (key image, session key) pairs in freeze order,
 *  which MixViewDigest covers. Neither side sorts; both refuse any other order. */
bool BuildMixRosterBody(const std::vector<CMixRosterEntry>& vRoster,
                        std::vector<unsigned char>& vchOut);
bool ReadMixRosterBody(const std::vector<unsigned char>& vchIn,
                       std::vector<CMixRosterEntry>& vOut);

/** The frozen key-image set, coordinator to seat. Must be in 32-byte-array order (as
 *  PrivacyVNextChangeIndexFor sorts), not uint256 order; the reader refuses unsorted sets. */
bool BuildMixKeySetBody(const std::vector<uint256>& vKeyImages,
                        std::vector<unsigned char>& vchOut);

/** Parses a key-set frame. Refuses a set that is not already sorted in byte order, or
 *  that repeats an image: a seat must reject a set it would have to reorder, because
 *  reordering is how the two derivations silently disagree. */
bool ReadMixKeySetBody(const std::vector<unsigned char>& vchIn,
                       std::vector<uint256>& vOut);

/** The anonymous output frame: a token and the bundle it authorises, with no identity. Each
 *  opening is checked against its commitment before the token is spent. */
bool BuildMixOutputBundleBody(const std::vector<unsigned char>& vchCredential,
                              const std::vector<unsigned char>& vchBlindSignature,
                              const std::vector<CMixOutputRecord>& vBundle,
                              std::vector<unsigned char>& vchOut);

enum MixDispatch
{
    MIX_DISPATCH_OK = 0,
    MIX_DISPATCH_REFUSED,     // the frame was not acted on; the round is unharmed
    MIX_DISPATCH_ABORTED,     // the round ended as a result
};

/** Who a snapshot is for. The public form carries only the phase; the frozen prefix holds
 *  disclosed openings, so it goes only to seats. Every seat gets the same bytes. */
enum MixSnapshotAudience
{
    MIX_SNAPSHOT_PUBLIC = 0,
    MIX_SNAPSHOT_SEAT = 1,
};

/** The round's state as a caller may read it. Same bytes for every caller of one audience,
 *  so a coordinator that answered per seat would have to do it by writing different bytes,
 *  not by the protocol offering it a per-seat field. */
struct CMixSnapshot
{
    uint8_t nVersion;
    uint8_t nAudience;
    uint8_t nPhase;
    uint8_t nSeats;                 // how many have joined; the target is in the announcement
    uint256 hashRound;
    // Seat audience only, and only once each exists.
    std::vector<CMixRosterEntry> vRoster;
    std::vector<unsigned char> vchRsaN;
    std::vector<unsigned char> vchRsaE;
    std::vector<unsigned char> vchPrefix;
    std::vector<PrivacyVNextDigest> vNonces;   // in input order, once the aggregate is fixed
    // Both certificates are published only once complete: a partial list would reveal which
    // roster position has not contributed yet.
    std::vector<std::vector<unsigned char> > vViewSigs;
    std::vector<std::vector<unsigned char> > vPrefixSigs;

    CMixSnapshot() : nVersion(1), nAudience(MIX_SNAPSHOT_PUBLIC), nPhase(0), nSeats(0),
                     hashRound(0) {}
};

/** Read the round into a snapshot for one audience. Nothing here names a seat: no progress
 *  bitmap, no list of missing contributions, no abort reason. */
bool BuildMixSnapshot(const CMixRound& round, MixSnapshotAudience nAudience,
                      CMixSnapshot& snapshotOut);
bool BuildMixSnapshotBody(const CMixSnapshot& snapshot, std::vector<unsigned char>& vchOut);
bool ReadMixSnapshotBody(const std::vector<unsigned char>& vchIn, CMixSnapshot& snapshotOut);

/** The reply to anything that changes the round: accepted, or not. No reason code and no
 *  detail, because the anonymous registration gets this reply too and a distinguishable
 *  refusal is a probe a coordinator can aim at one output. */
bool BuildMixAckBody(bool fAccepted, std::vector<unsigned char>& vchOut);
bool ReadMixAckBody(const std::vector<unsigned char>& vchIn, bool& fAcceptedOut);

/** A seat's authenticated read: its session key and the announcement it holds. */
bool BuildMixStateAuthBody(const CPubKey& pubkeySession, const uint256& hashAnnouncement,
                           std::vector<unsigned char>& vchOut);

/** What a dispatched frame leaves for its driver, e.g. the blinded message the round cannot
 *  sign itself. Input-side only: nothing from an OUTPUT frame appears here. */
struct CMixDispatchEffect
{
    MixFrameType nFrame;
    CPubKey pubkeySession;                  // the seat the frame authenticated as
    std::vector<unsigned char> vchBlinded;  // BLIND_REQUEST: what the driver must sign

    CMixDispatchEffect() : nFrame(MIX_FRAME_NONE) {}
    void Clear() { nFrame = MIX_FRAME_NONE; pubkeySession = CPubKey(); vchBlinded.clear(); }
};

/** Act on one frame from a participant. */
MixDispatch DispatchMixFrame(CMixRound& round,
                             MixFrameType nType,
                             const std::vector<unsigned char>& vchPayload,
                             int64_t nNow, std::string& strError,
                             CMixDispatchEffect* pEffect = NULL);

// The coordinator service: one request, one reply, one connection; the coordinator never
// pushes. Every instant derives from the announcement's schedule.

/** Where a round is in its schedule. Derived from the clock, never from what has
 *  arrived: a stage that advanced on completion would let the coordinator choose when a
 *  seat's window closes. */
enum MixServiceStage
{
    MIX_STAGE_JOIN = 0,
    MIX_STAGE_VIEW,        // view signatures and input constructions
    MIX_STAGE_TOKEN,       // blind-signature requests
    MIX_STAGE_OUTPUT,      // anonymous registrations
    MIX_STAGE_APPROVE,     // prefix approvals and membership proofs
    MIX_STAGE_NONCE,
    MIX_STAGE_RESPONSE,
    MIX_STAGE_TERMINAL,    // published or aborted; reads only
};

/** Whether a frame carries a session key and a signature over it. */
bool IsAuthenticatedMixFrame(MixFrameType nType);

/** What one seat may spend on one kind of frame in one round. A membership proof is verified
 *  on arrival and stored only when it verifies, so a seated key can otherwise pay for an
 *  unbounded number of ~50 ms verifications with one join. */
static const int MIX_SEAT_REQUEST_BUDGET = 8;
/** What the unauthenticated surface may spend per second across all callers. A read costs a
 *  snapshot build; nothing identifies the caller, so the bound is on the round rather than on
 *  whoever is asking. */
static const int MIX_PUBLIC_READS_PER_SECOND = 32;

class CMixCoordinator
{
public:
    CMixCoordinator();

    /** Open the round under a blind-signature key the announcement's commitment opens. The key
     *  must be new: a reused modulus verifies tokens minted in an earlier round. */
    bool Open(const CMixRoundAnnouncement& announce, const CNullSendSession& roundKey,
              int64_t nNow, std::string* pstrError = NULL);

    /** Advance the schedule to nNow: close the join set, open and close the anonymous
     *  window, freeze the prefix, fix the aggregate, and assemble when the signature is
     *  complete. A stage whose work did not arrive in time ends the round. */
    void Tick(int64_t nNow);

    /** Answer one request, and say what frame to send back. Everything that changes the
     *  round answers ACK; a read answers SNAPSHOT; a token request answers with its blind
     *  signature; a result request answers with the transaction or with ABORT. */
    bool Serve(MixFrameType nType, const std::vector<unsigned char>& vchPayload, int64_t nNow,
               MixFrameType& nReplyTypeOut, std::vector<unsigned char>& vchReplyOut);

    MixServiceStage Stage(int64_t nNow) const;
    const CMixRound& Round() const { return round; }
    const CMixRoundAnnouncement& Announcement() const { return announcement; }
    const CTransaction& Transaction() const { return txPublished; }
    bool HasTransaction() const { return fPublished; }
    bool IsOpen() const { return fOpen; }

private:
    CMixCoordinator(const CMixCoordinator&);
    CMixCoordinator& operator=(const CMixCoordinator&);

    bool ServeTokenRequest(const std::vector<unsigned char>& vchPayload, int64_t nNow,
                           MixFrameType& nReplyTypeOut, std::vector<unsigned char>& vchReplyOut);
    bool ServeSeatRead(const std::vector<unsigned char>& vchPayload,
                       MixFrameType& nReplyTypeOut, std::vector<unsigned char>& vchReplyOut);
    bool StageAccepts(MixServiceStage nStage, MixFrameType nType) const;
    void Assemble(int64_t nNow);
    /** Whether this frame is within its seat's budget, and spend one if so. Counted per
     *  frame type, so a seat that floods one kind does not spend another's allowance. */
    bool SpendSeatBudget(const CPubKey& pubkeySession, MixFrameType nType);
    /** Whether the unauthenticated surface has anything left this second. */
    bool SpendPublicBudget(int64_t nNow);

    CMixRoundAnnouncement announcement;
    CMixRound round;
    CNullSendSession key;
    bool fOpen;
    bool fPublished;
    MixServiceStage nLastStage;
    CTransaction txPublished;
    // Per seat, what was blinded and what was signed. A reply lost on its own circuit is
    // routine, so an identical request is re-served rather than refused; a different one
    // under the same seat is not a retry and gets nothing.
    std::vector<std::vector<unsigned char> > vBlinded;
    std::vector<std::vector<unsigned char> > vBlindSignatures;
    // Per seat, per frame type. A seat is named on every frame that has a budget, so this
    // costs the anonymous side nothing.
    std::map<std::pair<uint256, int>, int> mapSeatRequests;
    int64_t nPublicSecond;
    int nPublicReads;
};

/** Whether this blind-signature modulus has run a round on this node before. Round keys
 *  are single-use (a reused modulus lets a first-round token open in the second); kept on
 *  disk so the check survives restarts. */
bool MixRoundKeyWasUsed(const std::vector<unsigned char>& vchRSA_N);
bool RecordMixRoundKeyUse(const std::vector<unsigned char>& vchRSA_N, const uint256& hashRound);

// The seat: signs one view and one prefix per attempt, uses fresh entropy for every proof and
// nonce, rebuilds the challenge from what it approved, and checks its token and the prefix.

// Rendezvous: an on-chain commitment per coordinator identity per slot tells seats which
// announcement to hold, checked before a key image is revealed. It does not stop a
// coordinator running many identities or not publishing.

/** How long one rendezvous slot lasts. Slots are numbered from the epoch so every client
 *  computes the same one without asking anybody. */
static const int64_t MIX_RENDEZVOUS_SLOT_SECONDS = 600;

int64_t MixRendezvousSlot(int64_t nTime);

/** The commitment a coordinator publishes for a slot: the announcement's derived identifier,
 *  which already binds every announcement field. */
uint256 MixRendezvousCommitment(const CPubKey& pubkeyCoordinator, int64_t nSlot,
                                const uint256& hashRound);

/** Rendezvous record: tag "INRV", the identity-and-slot key, the commitment, and a coordinator
 *  signature over both. The key is hashed for cheap filtering, not secrecy. */
static const unsigned char MIX_RENDEZVOUS_TAG[4] = { 0x49, 0x4E, 0x52, 0x56 }; // "INRV"
static const size_t MIX_RENDEZVOUS_SIG_SIZE = 65;
static const size_t MIX_RENDEZVOUS_PAYLOAD_SIZE = 4 + 32 + 32 + MIX_RENDEZVOUS_SIG_SIZE;

struct CMixRendezvousRecord
{
    uint256 idSlot;
    uint256 hashCommitment;
    std::vector<unsigned char> vchSig;

    CMixRendezvousRecord() : idSlot(0), hashCommitment(0) {}
};

/** The key a reader computes from the identity and slot it is looking for. */
uint256 MixRendezvousIdentitySlot(const CPubKey& pubkeyCoordinator, int64_t nSlot);

/** What the coordinator signs. */
uint256 MixRendezvousAuthHash(const uint256& idSlot, const uint256& hashCommitment);

/** The whole record for one round, ready to publish. */
bool SignMixRendezvous(const CKey& keyCoordinator, int64_t nSlot, const uint256& hashRound,
                       CMixRendezvousRecord& recordOut, std::string* pstrError = NULL);

/** Whether this record is this coordinator's, for this slot. Cheap checks first. */
bool CheckMixRendezvousRecord(const CMixRendezvousRecord& record,
                              const CPubKey& pubkeyCoordinator, int64_t nSlot);

CScript BuildMixRendezvousScript(const CMixRendezvousRecord& record);

/** Strict: minimal push, whole script consumed, exact length. An OP_RETURN without the tag
 *  is not a rendezvous record rather than a malformed one, so records of other features in
 *  the same transaction are invisible here. */
bool DecodeMixRendezvousScript(const CScript& script, CMixRendezvousRecord& recordOut);

/** What a seat holds after reading the chain: the commitment it found for this coordinator
 *  and slot, and nothing else. Empty means the slot has none, which is a slot to skip
 *  rather than a reason to take whatever a server offers. */
struct CMixRendezvous
{
    CPubKey pubkeyCoordinator;
    int64_t nSlot;
    uint256 hashCommitment;

    CMixRendezvous() : nSlot(0), hashCommitment(0) {}
    bool IsNull() const { return hashCommitment == 0; }
};

/** How far back a record may be published for a slot; a record outside the window is not
 *  for this slot. One slot, because publication lead spends the frozen anchor's life. */
static const int MIX_RENDEZVOUS_PUBLISH_SLOTS = 1;

/** The window, in median-time-past, which only moves forward, so once the finalized chain
 *  passes a slot's opening the blocks in its window are fixed. */
inline bool MixRendezvousInWindow(int64_t nMedianTimePast, int64_t nSlot)
{
    if (nSlot <= 0)
        return false;
    const int64_t nOpens = nSlot * MIX_RENDEZVOUS_SLOT_SECONDS;
    return nMedianTimePast < nOpens &&
           nMedianTimePast >= nOpens - (int64_t)MIX_RENDEZVOUS_PUBLISH_SLOTS *
                                       MIX_RENDEZVOUS_SLOT_SECONDS;
}

/** Never scan more than this many blocks, or hold more than this many records. Reaching
 *  either is an INCOMPLETE VIEW and refuses the slot: a cap that silently shortened the
 *  window would let a flood of records decide which publication a seat sees first. */
static const int MIX_RENDEZVOUS_MAX_BLOCKS = 8192;
static const size_t MIX_RENDEZVOUS_MAX_RECORDS = 8192;

/** Every record in one block, in transaction order then output order. */
void CollectMixRendezvousRecords(const CBlock& block,
                                 std::vector<CMixRendezvousRecord>& vRecordsOut);

/** The settled point a slot is read from: a height and the block attested at it. The height
 *  must come from CDagManager::TryGetDeterministicFinalizedAnchor, not the node-local
 *  CFinalityTracker::GetFinalizedHeight; the hash only ties it to the caller's best chain. */
struct CMixSettledPoint
{
    int nHeight;
    uint256 hashBlock;

    CMixSettledPoint() : nHeight(0), hashBlock(0) {}
    CMixSettledPoint(int nHeightIn, const uint256& hashIn)
        : nHeight(nHeightIn), hashBlock(hashIn) {}
    bool IsNull() const { return hashBlock == 0; }
};

/** Which blocks a slot's records may come from, newest first, from a settled view. Split out
 *  from the read so the window and settlement rules can be checked without a chain on disk. */
bool SelectMixRendezvousBlocks(const CBlockIndex* pindexTip, const CMixSettledPoint& settled,
                               int64_t nSlot, std::vector<const CBlockIndex*>& vScanOut,
                               std::string* pstrError = NULL);

/** The records a slot may select from, oldest first, from the finalized chain only. A slot
 *  whose window is not yet finalized is refused. */
bool ReadMixRendezvousRecords(const CBlockIndex* pindexTip, const CMixSettledPoint& settled,
                              int64_t nSlot, std::vector<CMixRendezvousRecord>& vRecordsOut,
                              std::string* pstrError = NULL);

/** What the chain says about this coordinator and slot. */
bool LookupMixRendezvous(const CBlockIndex* pindexTip, const CMixSettledPoint& settled,
                         const CPubKey& pubkeyCoordinator, int64_t nSlot,
                         CMixRendezvous& rendezvousOut, std::string* pstrError = NULL);

/** The first authorised record for this identity and slot, in the given (oldest first) order.
 *  Other coordinators' records take no part; a later authorised one is ignored, not voiding. */
bool SelectMixRendezvous(const std::vector<CMixRendezvousRecord>& vRecords,
                         const CPubKey& pubkeyCoordinator, int64_t nSlot,
                         CMixRendezvous& rendezvousOut);

/** Whether the rendezvous authorises this announcement: same coordinator, slot matching its
 *  start time, and the commitment over its derived identifier. A seat joins only on yes. */
bool MixAnnouncementMatchesRendezvous(const CMixRoundAnnouncement& announce,
                                      const CMixRendezvous& rendezvous,
                                      std::string* pstrError = NULL);

/** What this node's chain says about a round's anchor, read at one tip.
 *
 *  The schedule cap in the announcement is the static half of the anchor budget. This is the
 *  half only the chain can answer: whether consensus accepts the anchor at all, and from which
 *  epoch, which fixes how long it stays accepted. A seat checks it before it reveals a key
 *  image and again before it approves a prefix and before it signs its final response. */
struct CMixAnchorView
{
    PrivacyVNextDigest finalizedRoot;
    uint64_t nFinalizedTreeSize;
    int nTipHeight;
    int64_t nReadTime;
    int nAnchorEpoch;        // the newest accepted epoch carrying the anchor, or -1
    int nSafeThroughHeight;  // MixAnchorSafeThroughHeight(nAnchorEpoch), or -1

    CMixAnchorView()
        : nFinalizedTreeSize(0), nTipHeight(-1), nReadTime(0), nAnchorEpoch(-1),
          nSafeThroughHeight(-1)
    {
        finalizedRoot.fill(0);
    }
};

/** Read the view of this announcement's anchor for the block after nTipHeight, judged by the
 *  code a connecting transaction is. A refused anchor is a view with no epoch; false only when
 *  this node cannot read its own state. Read nTipHeight and the view under one cs_main lock,
 *  or a commit between them tears the view. A node whose tip lags the network under-counts the
 *  blocks still to come by its lag. */
bool ReadMixAnchorView(CTxDB& txdb, int nTipHeight, int64_t nNow,
                       const CMixRoundAnnouncement& announce, CMixAnchorView& viewOut,
                       std::string* pstrError = NULL);

/** Whether the announcement's anchor, as the view saw it, is still accepted when a
 *  transaction finished by nConnectBy is mined: the tip projected forward from the view's
 *  read time at the margin rate must not pass the anchor's safe-through height. The seat's
 *  later checks refuse a view read before their own window, so each is a fresh read. */
bool CheckMixAnchorBudget(const CMixRoundAnnouncement& announce, const CMixAnchorView& view,
                          int64_t nConnectBy, std::string* pstrError = NULL);

/** The denominations a client mixes at, and the fixed per-seat fee share at each. A seat
 *  refuses a round whose fee or denomination differs from its own choice, so a coordinator
 *  cannot tag a seat by amount. */
struct CMixPolicy
{
    std::vector<uint64_t> vDenominations;
    uint64_t nFeeSharePerSeat;

    CMixPolicy() : nFeeSharePerSeat(0) {}

    /** The shipped ladder: one and ten INN, each seat paying one shielded transaction fee.
     *  That share is 0.1% of the base tier, which is the fraction the tier was chosen to
     *  hold: a tier small enough for the fee to matter is a tier nobody should mix at. */
    static CMixPolicy Standard();

    bool Allows(uint64_t nDenomination) const;
    /** Whether a round announcing this denomination, fee and seat count is one this client
     *  takes part in. */
    bool AllowsRound(uint64_t nDenomination, uint64_t nFee, int nSeats,
                     std::string* pstrError = NULL) const;
};

/** What a seat brings to one attempt. Every scalar here is drawn fresh for the attempt: a
 *  membership proof repeated under a second statement, or a balance nonce reused under a
 *  second challenge, hands over the secret each was protecting. */
struct CMixSeatMaterial
{
    PrivacyVNextSpendInput input;             // the note being spent, with its witness
    PrivacyVNextDigest recipientSpend;        // who the output pays
    PrivacyVNextDigest recipientView;
    PrivacyVNextDigest outgoingSecret;
    PrivacyVNextDigest noteMask;              // the mask the note being spent was committed under
    PrivacyVNextDigest outputY;               // the opening every variant of the bundle shares
    PrivacyVNextDigest outputMask;
    std::vector<std::pair<PrivacyVNextDigest, PrivacyVNextDigest> > vEphemerals;  // per position
    PrivacyVNextDigest membershipEntropy;
    PrivacyVNextDigest balanceEntropy;
};

class CMixSeat
{
public:
    CMixSeat();

    /** Take the announcement, check what can be checked without the coordinator, and do
     *  the proving pass that fixes this attempt's pseudo-output and key image. */
    bool Begin(const CMixRoundAnnouncement& announce, const CKey& keySession,
               const CMixSeatMaterial& material, const CMixPolicy& policy,
               const CMixRendezvous& rendezvous, const CMixAnchorView& anchor,
               std::string* pstrError = NULL);

    const uint256& KeyImage() const { return keyImage; }
    const PrivacyVNextDigest& PseudoOut() const { return pseudoOut; }
    const std::vector<CMixOutputRecord>& Bundle() const { return vBundle; }
    /** What this seat asked to have signed, so a driver can re-send the identical request
     *  after a lost reply rather than blinding a second message. */
    const std::vector<unsigned char>& Blinded() const { return vchBlinded; }

    bool BuildJoin(std::vector<unsigned char>& vchFrameOut, std::string* pstrError = NULL) const;

    /** Accept the frozen roster from a snapshot and sign its view. Refused if this seat's pair is
     *  missing, the roster is not the announced size, or a view was already signed. */
    bool AcceptRoster(const CMixSnapshot& snapshot, std::vector<unsigned char>& vchFrameOut,
                      std::string* pstrError = NULL);

    bool BuildConstruction(std::vector<unsigned char>& vchFrameOut,
                           std::string* pstrError = NULL) const;

    /** Check the round key against the announcement's commitment, then blind this attempt's
     *  bundle credential under it. A key the commitment does not open is refused before
     *  anything is blinded to it. */
    bool BuildTokenRequest(const CMixSnapshot& snapshot, std::vector<unsigned char>& vchFrameOut,
                           std::string* pstrError = NULL);
    /** Unblind, and verify the token locally before it is ever presented: a signature that
     *  does not verify is a round this seat cannot register in, and finding that out on the
     *  anonymous connection would be finding it out with a tag attached. */
    bool AcceptToken(const std::vector<unsigned char>& vchBlindSignature,
                     std::string* pstrError = NULL);

    /** The anonymous registration. Carries the token and the bundle and names no seat. */
    bool BuildRegistration(std::vector<unsigned char>& vchBodyOut,
                           std::string* pstrError = NULL) const;

    /** Check the whole prefix and approve it. One prefix per attempt: a second, however
     *  well formed, is refused, because approving two is how a seat proves one input under
     *  two statements. */
    bool AcceptPrefix(const CMixSnapshot& snapshot, const CMixAnchorView& anchor,
                      std::vector<unsigned char>& vchFrameOut, std::string* pstrError = NULL);

    /** Prove this seat's input under the approved prefix, with entropy drawn for this
     *  attempt. */
    bool BuildMembershipProof(std::vector<unsigned char>& vchFrameOut,
                              std::string* pstrError = NULL);

    /** The balance share. The nonce answers one aggregate and the response is computed
     *  against the aggregate this seat read back, not one it was told. */
    bool BuildNonce(std::vector<unsigned char>& vchFrameOut, std::string* pstrError = NULL);
    bool BuildResponse(const CMixSnapshot& snapshot, const CMixAnchorView& anchor,
                       std::vector<unsigned char>& vchFrameOut, std::string* pstrError = NULL);

private:
    CMixSeat(const CMixSeat&);
    CMixSeat& operator=(const CMixSeat&);

    bool BalanceFacts(PrivacyVNextMixBalanceFacts& factsOut, PrivacyVNextMixBalanceShare& shareOut,
                      std::string* pstrError) const;

    CMixRoundAnnouncement announcement;
    CKey keySession;
    CPubKey pubkeySession;
    CMixSeatMaterial material;
    CMixPolicy policy;
    bool fBegun;

    uint256 keyImage;
    PrivacyVNextDigest pseudoOut;
    PrivacyVNextDigest pseudoOutMaskDelta;
    std::vector<CMixOutputRecord> vBundle;

    std::vector<CMixRosterEntry> vRoster;     // the roster this seat signed, held fixed
    uint256 hashViewSigned;
    std::vector<unsigned char> vchToken;      // the unblinded credential
    std::vector<unsigned char> vchTokenSig;
    std::vector<unsigned char> vchBlinded;
    std::vector<unsigned char> vchRsaN;
    std::vector<unsigned char> vchRsaE;
    CNullSendClient blinder;
    std::vector<unsigned char> vchApprovedPrefix;
    PrivacyVNextDigest approvedSigningHash;
    int nMyPosition;
};

#endif // INNOVA_NULLSEND_V2008_H
