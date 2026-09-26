// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_NULLSEND_DRIVER_H
#define INN_NULLSEND_DRIVER_H

// NullSend v2008 round jobs: a coordinator that plans, publishes and serves a round, and a
// seat that finds, joins and completes one. Clock-stepped behind an environment interface.

#include <map>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>

#include "nullsend_v2008.h"

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------

class CMixCoordinatorEnv
{
public:
    virtual ~CMixCoordinatorEnv() {}
    /** PlanMixRound at this node's tip, under its own locks. */
    virtual bool PlanRound(int64_t nNow, CMixRoundPlan& planOut, std::string& strError) = 0;
    /** The network and genesis every announcement on this chain names. */
    virtual void ChainIdentity(uint8_t& nNetworkOut, PrivacyVNextDigest& genesisOut) = 0;
    /** Put the record on chain from this node's own funds. */
    virtual bool PublishRecord(const CScript& scriptRecord, uint256& txidOut,
                               std::string& strError) = 0;
    /** Whether the record's transaction is in a block on the best chain. */
    virtual bool RecordConfirmed(const uint256& txid) = 0;
    virtual bool Broadcast(const CTransaction& tx, std::string& strError) = 0;
};

struct CMixCoordinatorConfig
{
    CKey keyCoordinator;
    std::string strEndpoint;   // the onion name seats dial
    int nPort;                 // the port seats dial
    int nParticipants;
    uint64_t nDenomination;
    uint64_t nFeeSharePerSeat;
    std::vector<CMixDirectoryEndpoint> vDirectories;

    CMixCoordinatorConfig() : nPort(0), nParticipants(0), nDenomination(0), nFeeSharePerSeat(0) {}
};

enum MixCoordinatorJobState
{
    MIX_COORD_WAITING = 0,     // for the publishing window and a plan that fits
    MIX_COORD_PUBLISHED,       // record sent, waiting for it to be mined
    MIX_COORD_UPLOADED,        // a directory holds the announcement; round open
    MIX_COORD_DONE,            // past the round's end, transaction broadcast or not
    MIX_COORD_FAILED,
};

/** One round, from plan to broadcast. Step() advances it; Serve() answers the round's
 *  requests from any thread. */
class CMixCoordinatorJob
{
public:
    CMixCoordinatorJob(const CMixCoordinatorConfig& configIn, CMixCoordinatorEnv& envIn,
                       CMixDialer& dialerIn);

    void Step(int64_t nNow);
    bool Serve(MixFrameType nType, const std::vector<unsigned char>& vchPayload, int64_t nNow,
               MixFrameType& nReplyTypeOut, std::vector<unsigned char>& vchReplyOut);

    MixCoordinatorJobState State() const;
    std::string Status() const;
    CMixRoundAnnouncement Announcement() const;
    bool Broadcasted() const;

    /** How often a refused or unreachable upload is tried again. */
    static const int64_t UPLOAD_RETRY_SECS = 15;

private:
    CMixCoordinatorJob(const CMixCoordinatorJob&);
    CMixCoordinatorJob& operator=(const CMixCoordinatorJob&);

    void Fail(const std::string& strWhy);
    void StepLocked(int64_t nNow);
    bool OpenIfUploaded(int64_t nNow);

    CMixCoordinatorConfig config;
    CMixCoordinatorEnv& env;
    CMixDialer& dialer;
    mutable CCriticalSection cs;
    MixCoordinatorJobState nState;
    std::string strStatus;
    CMixRoundPlan plan;
    CNullSendSession roundKey;
    CMixRoundAnnouncement announce;
    uint256 txidRecord;
    std::vector<bool> vUploaded;
    int64_t nNextUpload;
    bool fRecordMined;
    CMixCoordinator coordinator;
    bool fBroadcast;
    int64_t nNextBroadcast;
};

// ---------------------------------------------------------------------------
// Seat
// ---------------------------------------------------------------------------

class CMixSeatEnv
{
public:
    virtual ~CMixSeatEnv() {}
    /** What the chain says for this identity and slot, read at the deterministic latch.
     *  fPendingOut when the slot is not settled yet, which is a reason to wait, not to fail. */
    virtual bool ReadRendezvous(const CPubKey& pubkeyCoordinator, int64_t nSlot,
                                CMixRendezvous& rendezvousOut, bool& fPendingOut,
                                std::string& strError) = 0;
    /** ReadMixAnchorView at this node's tip, under its own locks. */
    virtual bool ReadAnchor(const CMixRoundAnnouncement& announce, int64_t nNow,
                            CMixAnchorView& viewOut, std::string& strError) = 0;
    /** A note for this round witnessed at its anchor, held for the attempt. */
    virtual bool BuildMaterial(const CMixRoundAnnouncement& announce,
                               CMixSeatMaterial& materialOut, std::string& strError) = 0;
    /** Who this wallet's output pays, derived from the frozen roster. */
    virtual bool DeriveRecipient(const std::vector<uint256>& vRosterKeyImages,
                                 PrivacyVNextDigest& spendOut, PrivacyVNextDigest& viewOut,
                                 PrivacyVNextDigest& outgoingOut, std::string& strError) = 0;
    /** Give the note back. Called only while no final share has left. */
    virtual void ReleaseNote() = 0;
    /** The final share is about to leave: record the note as committed, across a restart,
     *  since a transaction spending it may be mined while its anchor stays accepted. False
     *  when it cannot be recorded, and then the share must not leave. */
    virtual bool NoteFinalShare(int64_t nRoundEnds) { (void)nRoundEnds; return true; }
    /** The finished transaction's payload validates and carries this seat's own output. */
    virtual bool VerifyResult(const CTransaction& tx, std::string& strError) = 0;
};

struct CMixSeatConfig
{
    CPubKey pubkeyCoordinator;
    int64_t nRecordSlot;       // the slot whose record authorises the round to join
    CMixPolicy policy;
    std::vector<CMixDirectoryEndpoint> vDirectories;

    CMixSeatConfig() : nRecordSlot(0) {}
};

enum MixSeatJobState
{
    MIX_SEAT_FINDING = 0,      // waiting for the record slot to settle, then fetching
    MIX_SEAT_READY,            // announcement in hand, not yet begun
    MIX_SEAT_BEGUN,            // proved, key image not yet sent
    MIX_SEAT_JOINED,
    MIX_SEAT_VIEWED,           // view signed; construction next
    MIX_SEAT_CONSTRUCTED,
    MIX_SEAT_TOKENED,
    MIX_SEAT_REGISTERED,
    MIX_SEAT_APPROVED,         // prefix approved; proof next
    MIX_SEAT_PROVED,
    MIX_SEAT_NONCED,
    MIX_SEAT_RESPONDED,        // final share sent
    MIX_SEAT_DONE,
    MIX_SEAT_FAILED,
};

/** One seat's attempt at one round. Every exchange is its own connection; a step is taken at
 *  an instant drawn inside its window rather than the moment the window opens, and a frame
 *  that must be sent again is sent byte for byte. */
class CMixSeatJob
{
public:
    CMixSeatJob(const CMixSeatConfig& configIn, CMixSeatEnv& envIn, CMixDialer& dialerIn);

    void Step(int64_t nNow);

    MixSeatJobState State() const;
    std::string Status() const;
    bool KeyImageRevealed() const;
    bool FinalShareSent() const;
    const CTransaction& Result() const { return txResult; }

    /** Stop the attempt at the user's request, from the stepping thread. Refused after the
     *  final share has left, and without fForce after the key image has gone out. */
    bool Cancel(bool fForce, std::string& strWhyNot);
    bool Cancelled() const { return fCancelled; }

    /** How often an exchange that failed or was refused is tried again inside its window. */
    static const int64_t RETRY_SECS = 8;

private:
    CMixSeatJob(const CMixSeatJob&);
    CMixSeatJob& operator=(const CMixSeatJob&);

    void Fail(const std::string& strWhy);
    bool Due(int64_t nNow) const { return nNow >= nNextAction; }
    void Schedule(int64_t nFrom, int64_t nUntil);
    bool Ask(MixFrameType nType, const std::vector<unsigned char>& vchPayload,
             MixFrameType& nReplyOut, std::vector<unsigned char>& vchReplyOut);
    /** What is left of the current window, as an exchange deadline. */
    void Window(int64_t nNow, int64_t nCloses);
    void Retry(int64_t nNow);
    void NewCircuit();
    bool AskAccepted(MixFrameType nType, const std::vector<unsigned char>& vchPayload);
    bool ReadSnapshot(CMixSnapshot& snapshotOut);
    bool FreshAnchor(int64_t nNow, CMixAnchorView& viewOut);

    CMixSeatConfig config;
    CMixSeatEnv& env;
    CMixDialer& dialer;
    MixSeatJobState nState;
    std::string strStatus;
    int64_t nNextAction;
    int nExchangeTimeoutMs;
    int64_t nWindowCloses;
    // The circuit this seat's authenticated frames share: random per job, and redrawn when an
    // exchange on it fails.
    std::string strCircuit;
    CMixRendezvous rendezvous;
    CMixRoundAnnouncement announce;
    CMixSeat seat;
    // Built once and resent unchanged.
    std::vector<unsigned char> vchJoin, vchViewSig, vchConstruction, vchTokenRequest,
        vchRegistration, vchPrefixSig, vchProof, vchNonce, vchResponse;
    bool fKeyImageRevealed;
    bool fFinalShareSent;
    bool fCancelled;
    CTransaction txResult;
};

/** The longest a seat waits before trying a step again: RETRY_SECS, or a third of what is left
 *  of its window when that is shorter, so a short window still holds a retry. The wait itself
 *  is drawn from the upper half of this. */
int64_t MixSeatRetryDelay(int64_t nNow, int64_t nWindowCloses);
int64_t MixSeatRetryWait(int64_t nNow, int64_t nWindowCloses);

// ---------------------------------------------------------------------------
// The node's mix service
// ---------------------------------------------------------------------------

class CWallet;

/** Connections a mix listener answers at once; past this a new one is dropped. */
static const int MIX_MAX_CONNECTIONS = 32;
/** How long a connection has to deliver its request. A caller that has dialed through Tor has
 *  its circuit already; a short deadline is what keeps idle connections from holding the cap. */
static const int MIX_CONNECTION_TIMEOUT_MS = 8000;

/** The onion service directory a mix role uses, apart from the node's own: a mix endpoint on
 *  the node's P2P onion would tie the coordinator or directory to that node. */
boost::filesystem::path GetMixOnionServiceDir(const std::string& strRole);

// Settings. -mixdir, -mixproxy, -mixonion, -mixcoordinatorport and -mixdirectoryport come
// from innova.conf or the command line; a key set in the mix settings file (written by the
// mixsetsetting RPC) takes precedence over them.

/** Names the settings file accepts, without the leading dash. */
const std::vector<std::string>& MixSettingNames();
/** Whether a setting takes effect without a restart: the directory list and the proxy apply
 *  to every seat started after the change. */
bool MixSettingIsLive(const std::string& strName);

bool ParseMixDirectories(const std::vector<std::string>& vIn,
                         std::vector<CMixDirectoryEndpoint>& vOut, std::string& strError);
bool ParseMixProxy(const std::string& str, CService& addrOut, std::string& strError);
/** Validate one value for a setting. An empty value is valid: it removes the override. */
bool CheckMixSettingValue(const std::string& strName, const std::string& strValue,
                          std::string& strError);
/** One key=value per line, keys from MixSettingNames(); mixdir may repeat. Blank lines and
 *  lines starting with # are skipped. */
bool ParseMixSettingsText(const std::string& strText,
                          std::map<std::string, std::vector<std::string> >& mapOut,
                          std::string& strError);
std::string FormatMixSettingsText(const std::map<std::string, std::vector<std::string> >& mapIn);

boost::filesystem::path GetMixSettingsPath();

struct CMixSettings
{
    std::vector<CMixDirectoryEndpoint> vDirectories;
    std::string strProxy;
    // "nativetor", "default", "config" or "settings file".
    std::string strProxySource;
    std::string strOnion;
    int nCoordinatorPort;
    int nDirectoryPort;
    // Keys the settings file sets.
    std::vector<std::string> vOverridden;
    CMixSettings() : nCoordinatorPort(0), nDirectoryPort(0) {}
};

/** What the next start will use. False, with the reason, for a value that cannot work. */
bool ResolveMixSettings(CMixSettings& out, std::string& strError);
/** What the running service uses now. */
void GetRunningMixSettings(CMixSettings& out, bool& fRunningOut);
/** Change one setting and persist it. A live setting also applies at once to seats started
 *  from now on; any other sets fRestartOut. An empty value removes the override. */
bool MixSetSetting(const std::string& strName, const std::string& strValue, bool& fRestartOut,
                   std::string& strError);

/** Read the settings, open the listeners the configured roles need and start the service
 *  threads. False only for a setting that cannot work. */
bool StartMixService(CWallet* pwallet, std::string& strError);
void StopMixService();

// Proxy readiness.

struct CMixProxyStatus
{
    std::string strProxy;
    std::string strSource;
    bool fReachable;
    bool fSocks5;
    // Takes per-exchange credentials, which every mix exchange offers and nothing else.
    bool fIsolation;
    int64_t nLatencyMs;
    std::string strError;
    CMixProxyStatus() : fReachable(false), fSocks5(false), fIsolation(false), nLatencyMs(-1) {}
    bool Ready() const { return fReachable && fSocks5 && fIsolation; }
};

/** Connect to the proxy, offer the SOCKS5 methods the dialer offers and read the choice, then
 *  close. No destination is named and nothing else is sent, so the probe dials nowhere. */
bool ProbeMixProxy(const CService& addrProxy, int nTimeoutMs, CMixProxyStatus& statusOut);
/** Probe the proxy seats started now would use. */
void GetMixProxyStatus(int nTimeoutMs, CMixProxyStatus& statusOut);

// Round discovery.

struct CMixListedRound
{
    CMixRoundAnnouncement announce;
    std::vector<std::string> vDirectories;   // host:port of every directory that listed it
};

/** Ask every configured directory, or only strOnly (host:port) when set, for the rounds open
 *  to join, each on a circuit of its own. Rounds for another chain are dropped. Listed rounds
 *  are remembered for MixCachedRound. False only when no directory could be asked. */
bool MixListRounds(const std::string& strOnly, std::vector<CMixListedRound>& vOut,
                   std::vector<std::pair<std::string, std::string> >& vFailuresOut,
                   std::string& strError);
/** A round the last listing returned. */
bool MixCachedRound(const uint256& hashRound, CMixRoundAnnouncement& announceOut);

/** The record this identity published for nSlot, read at the deterministic latch the seat
 *  uses. fPendingOut when the slot is not settled yet. */
bool ReadSettledMixRendezvous(const CPubKey& pubkeyCoordinator, int64_t nSlot,
                              CMixRendezvous& rendezvousOut, bool& fPendingOut,
                              std::string& strError);

// Note eligibility.

/** One note as the wallet holds it, for deciding whether it can take a seat. */
struct CMixNoteFacts
{
    uint256 txhash;
    uint32_t nOutputIndex;
    uint64_t nAmount;
    int nHeight;
    bool fLeafIndexKnown;
    uint64_t nLeafIndex;
    bool fPrepared;
    // Empty when nothing but the round's own terms stands in the way.
    std::string strUnusable;
    CMixNoteFacts()
        : txhash(0), nOutputIndex(0), nAmount(0), nHeight(0), fLeafIndexKnown(false),
          nLeafIndex(0), fPrepared(false) {}
};

/** The tip height from which a round's anchor can cover a note mined at nNoteHeight: the end
 *  of the note's epoch plus the depth an anchor needs at JOIN. -1 for no height. */
int MixNoteEligibleHeight(int nNoteHeight);
/** Why this note cannot take a seat in this round, or empty when it can. */
std::string MixNoteIneligibility(const CMixNoteFacts& note, const CMixRoundAnnouncement& announce);

/** One coordinator round at a time, under this key, from the next publishing window on. */
bool MixStartCoordinator(const CKey& keyCoordinator, uint64_t nDenomination, int nSeats,
                         std::string& strError);
/** One attempt at the round this coordinator's record for nRecordSlot authorises. nIdOut is
 *  the seat's id in mixstatus. */
bool MixStartSeat(const CPubKey& pubkeyCoordinator, int64_t nRecordSlot, std::string& strError,
                  int64_t* pnIdOut = NULL);

struct CMixJobStatus
{
    int64_t nId;
    std::string strRole;
    std::string strState;
    std::string strStatus;
    std::string strRound;
    int64_t nRecordSlot;
    int64_t nStarted;
    int64_t nUpdated;
    bool fFinished;
    bool fCancelled;
    bool fCancelPending;
    CMixJobStatus()
        : nId(0), nRecordSlot(0), nStarted(0), nUpdated(0), fFinished(false), fCancelled(false),
          fCancelPending(false) {}
};
void GetMixServiceStatus(std::vector<CMixJobStatus>& vJobsOut, size_t& nDirectoryEntriesOut,
                         size_t& nRecordsOut);

/** Ask the seats thread to cancel seat nId. It is applied between steps, so an exchange in
 *  flight finishes first; this waits up to nWaitMs for the outcome. fAppliedOut false with no
 *  error means it is still queued. */
bool MixCancelSeat(int64_t nId, bool fForce, int nWaitMs, bool& fAppliedOut,
                   std::string& strResult, std::string& strError);
/** Remove every seat that is done, failed or cancelled; the count removed. */
size_t MixClearFinishedSeats();

#endif // INN_NULLSEND_DRIVER_H
