#ifndef IV5RPCBRIDGE_H
#define IV5RPCBRIDGE_H

#include <QString>
#include <QStringList>

// GUI-side access to the v5 RPCs the privacy surfaces drive.
//
// Kept apart from WalletModel's legacy bridge: the calls here are the v2008 ones,
// and their whitelist is the list of verbs this page is allowed to reach.
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

    bool UnshieldRetirementScheduled() const;
};

bool FetchFinality(FinalitySnapshot& out, QString& errorOut);
bool FetchPool(PoolSnapshot& out, QString& errorOut);

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
