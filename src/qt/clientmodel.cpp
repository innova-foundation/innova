#include "clientmodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "peertablemodel.h"
#include "bantablemodel.h"
#include "addresstablemodel.h"
#include "transactiontablemodel.h"
#include "alert.h"
#include "dag.h"
#include "finality.h"
#include "main.h"
#include "ui_interface.h"
#include "util.h"
#include <QDateTime>
#include <QTimer>

#if BOOST_VERSION >= 107300
#include <boost/bind/bind.hpp>
using boost::placeholders::_1;
using boost::placeholders::_2;
#else
#include <boost/bind.hpp>
#endif

static const int64_t nClientStartupTime = GetTime();

ClientModel::DAGStatus::DAGStatus() :
    valid(false),
    lockBusy(false),
    active(false),
    dagKnightActive(false),
    height(0),
    dagForkHeight(0),
    dagKnightForkHeight(0),
    tipCount(0),
    entryCount(0),
    ghostdagK(0),
    inferredK(-1),
    inferredKError(false),
    adaptiveBlockLimit(0),
    adaptiveBlockFloor(0),
    adaptiveBlockCeiling(0),
    epoch(0),
    epochInterval(0),
    finalizedHeight(0),
    currentEpochVotes(0),
    currentEpochVoters(0),
    latestBlockSize(0),
    latestBlockTxCount(0),
    latestBlockUtilizationPct(0.0),
    latestBlockParentCount(-1)
{
}

ClientModel::ClientModel(OptionsModel *optionsModel, QObject *parent) :
    QObject(parent), optionsModel(optionsModel),
    cachedNumBlocks(0), cachedNumBlocksOfPeers(0), pollTimer(0)
{
    peerTableModel = new PeerTableModel(this);
    banTableModel = new BanTableModel(this);

    numBlocksAtStartup = -1;

    pollTimer = new QTimer(this);
	connect(pollTimer, SIGNAL(timeout()), this, SLOT(updateTimer()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

ClientModel::~ClientModel()
{
    unsubscribeFromCoreSignals();
}

int ClientModel::getNumConnections() const
{
    TRY_LOCK(cs_vNodes, lockNodes);
    if (!lockNodes)
        return 0;
    return vNodes.size();
}

int ClientModel::getNumBlocks() const
{
    // nBestHeight is an atomic int — safe to read without lock.
    // Using LOCK(cs_main) here was blocking the UI thread when the
    // consensus thread held cs_main during block processing.
    return nBestHeight;
}

int ClientModel::getNumBlocksAtStartup()
{
    if (numBlocksAtStartup == -1) numBlocksAtStartup = getNumBlocks();
    return numBlocksAtStartup;
}

quint64 ClientModel::getTotalBytesRecv() const
{
    return CNode::GetTotalBytesRecv();
}

quint64 ClientModel::getTotalBytesSent() const
{
    return CNode::GetTotalBytesSent();
}

QDateTime ClientModel::getLastBlockDate() const
{
    if (pindexBest)
    {
        TRY_LOCK(cs_main, lockMain);
        if (lockMain && pindexBest)
            return QDateTime::fromTime_t(pindexBest->GetBlockTime());
    }
    if (!isTestNet())
        return QDateTime::fromTime_t(1576002227); // I n n o v a - MAINNET Genesis Block Coinbase Time
    else
        return QDateTime::fromTime_t(1778976000); // I n n o v a TESTNET V3 Genesis Block Coinbase Time
}

void ClientModel::updateTimer()
{
    // Get required lock upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    TRY_LOCK(cs_main, lockMain);
    if(!lockMain)
        return;

    // Some quantities (such as number of blocks) change so fast that we don't want to be notified for each change.
    // Periodically check and update with a timer.
    int newNumBlocks = getNumBlocks();
    int newNumBlocksOfPeers = getNumBlocksOfPeers();

    if (cachedNumBlocks != newNumBlocks || cachedNumBlocksOfPeers != newNumBlocksOfPeers)
    {
        cachedNumBlocks = newNumBlocks;
        cachedNumBlocksOfPeers = newNumBlocksOfPeers;

        emit numBlocksChanged(newNumBlocks, newNumBlocksOfPeers);
    }

    emit bytesChanged(getTotalBytesRecv(), getTotalBytesSent());
}

void ClientModel::updateNumBlocks(int newNumBlocks, int newNumBlocksOfPeers)
{
    // Get required lock upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
  //  TRY_LOCK(cs_main, lockMain);
  //  if(!lockMain)
  //      return;

    emit numBlocksChanged(newNumBlocks, newNumBlocksOfPeers);
    emit bytesChanged(getTotalBytesRecv(), getTotalBytesSent());
}

void ClientModel::updateNumConnections(int numConnections)
{
    emit numConnectionsChanged(numConnections);
}

void ClientModel::updateAlert(const QString &hash, int status)
{
    // Show error message notification for new alert
    if(status == CT_NEW)
    {
        uint256 hash_256;
        hash_256.SetHex(hash.toStdString());
        CAlert alert = CAlert::getAlertByHash(hash_256);
        if(!alert.IsNull())
        {
            emit error(tr("Network Alert"), QString::fromStdString(alert.strStatusBar), false);
        }
    }

    // Emit a numBlocksChanged when the status message changes,
    // so that the view recomputes and updates the status bar.
    emit numBlocksChanged(getNumBlocks(), getNumBlocksOfPeers());
}

bool ClientModel::isTestNet() const
{
    return fTestNet;
}

bool ClientModel::isNativeTor() const
{
    return fNativeTor;
}

bool ClientModel::isCNLock() const
{
    return fCNLock;
}

bool ClientModel::inInitialBlockDownload() const
{
    return IsInitialBlockDownload();
}

int ClientModel::getNumBlocksOfPeers() const
{
    return GetNumBlocksOfPeers();
}

QString ClientModel::getStatusBarWarnings() const
{
    return QString::fromStdString(GetWarnings("statusbar"));
}

static QString FinalityTierToString(FinalityTier tier)
{
    switch (tier)
    {
    case FINALITY_HARD:
        return QString("hard");
    case FINALITY_SOFT:
        return QString("soft");
    case FINALITY_TENTATIVE:
        return QString("tentative");
    case FINALITY_NONE:
    default:
        return QString("none");
    }
}

ClientModel::DAGStatus ClientModel::getDAGStatus(int recentBlockCount) const
{
    DAGStatus status;

    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
    {
        status.lockBusy = true;
        return status;
    }

    status.valid = true;
    status.dagForkHeight = FORK_HEIGHT_DAG;
    status.dagKnightForkHeight = FORK_HEIGHT_DAGKNIGHT;
    status.adaptiveBlockFloor = ADAPTIVE_BLOCK_FLOOR;
    status.adaptiveBlockCeiling = ADAPTIVE_BLOCK_CEILING;
    status.ghostdagK = GHOSTDAG_K;

    CBlockIndex* pBest = pindexBest;
    status.height = pBest ? pBest->nHeight : 0;
    status.active = status.height >= FORK_HEIGHT_DAG;
    status.dagKnightActive = status.height >= FORK_HEIGHT_DAGKNIGHT;
    status.orderingAlgorithm = status.active
        ? (status.dagKnightActive ? QString("DAGKNIGHT") : QString("GHOSTDAG"))
        : QString("inactive");
    status.epoch = GetEpochForHeight(status.height);
    status.epochInterval = GetEpochInterval(status.height);
    status.adaptiveBlockLimit = pBest ? GetAdaptiveBlockSizeLimit(pBest) : MAX_BLOCK_SIZE_LEGACY;

    std::vector<uint256> vTips = g_dagManager.GetDAGTips();
    status.tipCount = (int)vTips.size();
    status.entryCount = g_dagManager.GetDAGEntryCount();

    CBlockIndex* pBestDAGTip = status.active ? g_dagManager.SelectBestDAGTip() : NULL;
    if (pBestDAGTip && pBestDAGTip->phashBlock)
    {
        uint256 hashBestDAGTip = pBestDAGTip->GetBlockHash();
        status.bestDAGTip = QString::fromStdString(hashBestDAGTip.GetHex());

        CBlockDAGData tipData;
        if (g_dagManager.GetDAGData(hashBestDAGTip, tipData))
        {
            status.bestDAGScore = QString::fromStdString(tipData.nDAGScore.GetHex());
            if (status.dagKnightActive)
            {
                status.inferredK = tipData.nInferredK;
                status.inferredKError = tipData.nInferredK < 0;
            }
        }
        else if (status.dagKnightActive)
        {
            status.inferredKError = true;
        }
    }
    else if (status.dagKnightActive)
    {
        status.inferredKError = true;
    }

    status.finalizedHeight = g_finalityTracker.GetFinalizedHeight();
    status.finalizedHash = QString::fromStdString(g_finalityTracker.GetFinalizedHash().GetHex());
    status.finalityTier = FinalityTierToString(g_finalityTracker.GetFinalityTier());
    status.currentEpochVotes = g_finalityTracker.GetEpochVoteCount(status.epoch);
    status.currentEpochVoters = g_finalityTracker.GetEpochVoterCount(status.epoch);
    status.currentEpochWeight = QString::fromStdString(FormatMoney(g_finalityTracker.GetEpochVoteWeight(status.epoch)));

    if (pBest && pBest->phashBlock)
    {
        uint256 hashBest = pBest->GetBlockHash();
        status.latestBlockHash = QString::fromStdString(hashBest.GetHex());
        status.latestBlockSize = pBest->nSize;
        status.latestBlockTxCount = pBest->nTx;
        if (status.adaptiveBlockLimit > 0)
            status.latestBlockUtilizationPct = 100.0 * (double)status.latestBlockSize / (double)status.adaptiveBlockLimit;

        CBlockDAGData latestData;
        if (g_dagManager.GetDAGData(hashBest, latestData))
            status.latestBlockParentCount = (int)latestData.vDAGParents.size();
    }

    if (recentBlockCount > 0 && pBest)
    {
        int nRows = recentBlockCount > 64 ? 64 : recentBlockCount;
        const CBlockIndex* pWalk = pBest;
        for (int i = 0; i < nRows && pWalk; i++, pWalk = pWalk->pprev)
        {
            DAGBlockActivity row;
            row.height = pWalk->nHeight;
            row.hash = pWalk->phashBlock ? QString::fromStdString(pWalk->GetBlockHash().GetHex()) : QString();
            row.blockType = pWalk->IsProofOfStake() ? QString("PoS") : QString("PoW");
            row.sizeBytes = pWalk->nSize;
            row.txCount = pWalk->nTx;
            row.intervalSeconds = pWalk->pprev ? (int)(pWalk->GetBlockTime() - pWalk->pprev->GetBlockTime()) : 0;
            row.utilizationPct = status.adaptiveBlockLimit > 0
                ? 100.0 * (double)row.sizeBytes / (double)status.adaptiveBlockLimit
                : 0.0;
            row.parentCount = -1;

            if (pWalk->phashBlock)
            {
                CBlockDAGData dagData;
                if (g_dagManager.GetDAGData(pWalk->GetBlockHash(), dagData))
                    row.parentCount = (int)dagData.vDAGParents.size();
            }

            status.recentBlocks.append(row);
        }
    }

    return status;
}

OptionsModel *ClientModel::getOptionsModel()
{
    return optionsModel;
}

PeerTableModel *ClientModel::getPeerTableModel()
{
    return peerTableModel;
}

BanTableModel *ClientModel::getBanTableModel()
{
    return banTableModel;
}

QString ClientModel::formatFullVersion() const
{
    return QString::fromStdString(FormatFullVersion());
}

QString ClientModel::formatBuildDate() const
{
    return QString::fromStdString(CLIENT_DATE);
}

QString ClientModel::clientName() const
{
    return QString::fromStdString(CLIENT_NAME);
}

QString ClientModel::formatClientStartupTime() const
{
    return QDateTime::fromTime_t(nClientStartupTime).toString();
}

// Handlers for core signals
static void NotifyBlocksChanged(ClientModel *clientmodel, int nHeight, int newNumBlocksOfPeers)
{
    // This notification is too frequent. Don't trigger a signal.
    // Don't remove it, though, as it might be useful later.
    QMetaObject::invokeMethod(clientmodel, "updateNumBlocks", Qt::QueuedConnection, Q_ARG(int, nHeight), Q_ARG(int, newNumBlocksOfPeers));

}

static void NotifyNumConnectionsChanged(ClientModel *clientmodel, int newNumConnections)
{
    // Too noisy: OutputDebugStringF("NotifyNumConnectionsChanged %i\n", newNumConnections);
    QMetaObject::invokeMethod(clientmodel, "updateNumConnections", Qt::QueuedConnection,
                              Q_ARG(int, newNumConnections));
}

static void NotifyAlertChanged(ClientModel *clientmodel, const uint256 &hash, ChangeType status)
{
    OutputDebugStringF("NotifyAlertChanged %s status=%i\n", hash.GetHex().c_str(), status);
    QMetaObject::invokeMethod(clientmodel, "updateAlert", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(hash.GetHex())),
                              Q_ARG(int, status));
}

void ClientModel::updateBanlist()
{
    banTableModel->refresh();
    emit banListChanged();
}

static void BannedListChanged(ClientModel *clientmodel)
{
    // qDebug() << "BannedListChanged";
    QMetaObject::invokeMethod(clientmodel, "updateBanlist", Qt::QueuedConnection);
}

void ClientModel::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.NotifyBlocksChanged.connect(boost::bind(NotifyBlocksChanged, this, _1, _2));
    uiInterface.NotifyNumConnectionsChanged.connect(boost::bind(NotifyNumConnectionsChanged, this, _1));
    uiInterface.NotifyAlertChanged.connect(boost::bind(NotifyAlertChanged, this, _1, _2));
    uiInterface.BannedListChanged.connect(boost::bind(BannedListChanged, this));
}

void ClientModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.NotifyBlocksChanged.disconnect(boost::bind(NotifyBlocksChanged, this, _1, _2));
    uiInterface.NotifyNumConnectionsChanged.disconnect(boost::bind(NotifyNumConnectionsChanged, this, _1));
    uiInterface.NotifyAlertChanged.disconnect(boost::bind(NotifyAlertChanged, this, _1, _2));
    uiInterface.BannedListChanged.disconnect(boost::bind(BannedListChanged, this));
}
