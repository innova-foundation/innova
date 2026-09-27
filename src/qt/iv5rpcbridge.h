#ifndef IV5RPCBRIDGE_H
#define IV5RPCBRIDGE_H

#include <QList>
#include <QString>
#include <QStringList>

// GUI-side access to the v5 RPCs used by the privacy, seed and staking pages.
// Separate from WalletModel's legacy bridge; the whitelist is the set of reachable verbs.
namespace Iv5Rpc
{

// Only what the finality panel renders. Fields absent from the reply keep the
// value set by the constructor, so a partial reply renders as unknown instead of
// as a confident zero.
struct FinalitySnapshot
{
    FinalitySnapshot();

    int nHeight;
    int nEpoch;
    int nEpochInterval;
    int nFinalizedHeight;
    int nFinalizedEpoch;
    QString strFinalizedHash;
    QString strTier;
    int nConsecutiveHardEpochs;
    int nTransparentVotes;
    int nPrivateVotes;
    int nVoters;

    bool fBoundaryAActive;
    bool fBoundaryBActive;

    bool fCommitteeSeated;
    int nCommitteeSeats;
    int nCommitteeThresholdM;
    int nCommitteeTermEpoch;
    int nCommitteeTermEpochs;
    QString strCommitteeSetHash;
    QStringList vSeatKeys;

    bool fHaveNextDraw;
    int nNextTermEpoch;
    int nNextAnchorHeight;
    int nNextRegistryRows;
    int nNextRowsRequired;
    bool fNextSeated;

    int nCertificates;
    int nPrivateCertificates;
    bool fPrivateCertificatePresent;
    bool fPendingPrivateCertificatePresent;
    int nCertificateVersion;
    QString strCertificateSource;
    QString strPrivatePromotionStatus;
    QString strEpochStateHealth;

    // Derived, not a reply field: which lane produced what is on chain now.
    QString LaneDescription() const;
};

// The wallet's own view of the pool, from z_getshieldedinfo.
struct PoolSnapshot
{
    PoolSnapshot();

    bool fHaveBalance;
    double dBalance;
    double dUnconfirmed;
    int nNoteCount;
    bool fSeedUnlocked;
    int nScanGapHeight;
    bool fHavePoolValue;
    double dPoolValue;
    bool fBoundaryBActive;
    // Together these two are exactly what z_iv5transfer and z_shieldall require, so
    // the page can say why an operation will be refused instead of guessing.
    bool fTransactionsAccepted;
    // Unshield is retired in consensus at the IV5 fee-note height, and the height is
    // not set on every network, so the state is read rather than assumed.
    bool fUnshieldRetired;
    int nUnshieldRetirementHeight;
    // Seed and recovery-phrase coverage.
    bool fSeedPresent;
    QString strKeyState;
    bool fTransparentHd;
    int nTransparentKeysNotCovered;

    bool UnshieldRetirementScheduled() const;
};

// One job from mixstatus.
struct MixJob
{
    MixJob() : nId(0), nRecordSlot(0), nStarted(0), nUpdated(0), fFinished(false),
               fCancelled(false), fCancelPending(false) {}

    qint64 nId;
    QString strRole;
    QString strState;
    QString strStatus;
    QString strRound;
    qint64 nRecordSlot;
    qint64 nStarted;
    qint64 nUpdated;
    bool fFinished;
    bool fCancelled;
    bool fCancelPending;

    bool Terminal() const;
    QString StateName() const;
};

struct MixSnapshot
{
    MixSnapshot() : nDirectoryEntries(0), nRecords(0), fRunning(false), nDirectories(0) {}

    QList<MixJob> vJobs;
    int nDirectoryEntries;
    int nRecords;
    bool fRunning;
    int nDirectories;
    QString strProxy;
    QString strProxySource;
};

// mixsettings: what runs now and what the next start uses.
struct MixSettingsView
{
    MixSettingsView() : fRunning(false), fRestartRequired(false) {}

    bool fRunning;
    QStringList vDirectories;
    QString strProxy;
    QString strProxySource;
    QStringList vNextDirectories;
    QString strNextProxy;
    QString strSettingsFile;
    bool fRestartRequired;
};

// mixproxystatus.
struct MixProxyView
{
    MixProxyView() : fReachable(false), fSocks5(false), fIsolation(false), fReady(false),
                     nLatencyMs(-1) {}

    QString strProxy;
    QString strSource;
    bool fReachable;
    bool fSocks5;
    bool fIsolation;
    bool fReady;
    qint64 nLatencyMs;
    QString strError;
};

// One row of mixlistrounds.
struct MixRoundRow
{
    MixRoundRow() : nRecordSlot(0), dDenomination(0), dNoteAmount(0), nSeats(0), nStarts(0),
                    nJoinCloses(0), nEnds(0), fJoinable(false), nEligibleNotes(0) {}

    QString strRound;
    QString strCoordinator;
    qint64 nRecordSlot;
    double dDenomination;
    double dNoteAmount;
    int nSeats;
    qint64 nStarts;
    qint64 nJoinCloses;
    qint64 nEnds;
    QString strRecord;
    bool fJoinable;
    int nEligibleNotes;
    QStringList vDirectories;
};

// One row of mixnotes.
struct MixNoteRow
{
    MixNoteRow() : dAmount(0), nHeight(0), fPrepared(false), fInTree(false), fUsable(false),
                   nEligibleHeight(-1), nEligibleInBlocks(-1), nEligibleTime(0),
                   fHaveRound(false), fEligible(false) {}

    QString strNote;
    double dAmount;
    int nHeight;
    bool fPrepared;
    bool fInTree;
    bool fUsable;
    QString strReason;
    int nEligibleHeight;
    int nEligibleInBlocks;
    qint64 nEligibleTime;
    bool fHaveRound;
    bool fEligible;
    QString strRoundReason;
};

// One row of z_listiv5holds.
struct HeldNote
{
    HeldNote() : fHaveAmount(false), dAmount(0), fSpent(false) {}

    QString strNote;
    bool fHaveAmount;
    double dAmount;
    bool fSpent;
};

// getcoldstakinginfo.
struct ColdStakingInfo
{
    ColdStakingInfo() : fEnabled(false), nForkHeight(0), nHeight(0), dBalance(0),
                        nStakerUtxos(0), nOwnerUtxos(0) {}

    bool fEnabled;
    int nForkHeight;
    int nHeight;
    double dBalance;
    int nStakerUtxos;
    int nOwnerUtxos;
};

// One row of listcoldutxos.
struct ColdUtxo
{
    ColdUtxo() : nVout(0), dAmount(0), fIsStaker(false), fIsOwner(false), nConfirmations(0) {}

    QString strTxid;
    int nVout;
    double dAmount;
    QString strStaker;
    QString strOwner;
    bool fIsStaker;
    bool fIsOwner;
    int nConfirmations;
};

// The client's mix ladder: the tier and the note a seat at it spends.
struct MixTier
{
    qint64 nDenomination;
    qint64 nNoteAmount;
};

QList<MixTier> MixTiers();
QString FormatInn(qint64 nAmount);
// Directories the running mix service fetches from; a seat has nothing to fetch from without one.
int MixDirectoriesConfigured();

bool FetchFinality(FinalitySnapshot& out, QString& errorOut);
bool FetchMix(MixSnapshot& out, QString& errorOut);
bool FetchMixSettings(MixSettingsView& out, QString& errorOut);
bool FetchMixProxy(MixProxyView& out, QString& errorOut);
bool FetchMixRounds(QList<MixRoundRow>& out, QStringList& failuresOut, QString& errorOut);
// strRound empty: no round; otherwise a round id from the last FetchMixRounds.
bool FetchMixNotes(const QString& strRound, QList<MixNoteRow>& out, QString& errorOut);
bool FetchHolds(QList<HeldNote>& out, QString& errorOut);
bool FetchPool(PoolSnapshot& out, QString& errorOut);
bool FetchColdStaking(ColdStakingInfo& out, QString& errorOut);
bool FetchColdUtxos(QList<ColdUtxo>& out, QString& errorOut);

// Whitelisted call. On success resultOut holds the pretty-printed reply.
bool Call(const QString& method, const QStringList& params,
          QString& resultOut, QString& errorOut);

// Reads one string field out of a reply object; false if it is not there.
bool ReadField(const QString& jsonObject, const QString& key, QString& valueOut);

// Plain-language rendering of a three-bit disclosure mask. A set bit hides.
QString MaskTitle(int nMask);
QString MaskDetail(int nMask);
bool MaskDisclosesSender(int nMask);
bool MaskDisclosesReceiver(int nMask);
bool MaskDisclosesAmount(int nMask);

} // namespace Iv5Rpc

#endif // IV5RPCBRIDGE_H
