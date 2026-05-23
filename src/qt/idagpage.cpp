#include "idagpage.h"

#include "clientmodel.h"

#include <QAbstractItemView>
#include <QFont>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QList>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

IDAGPage::IDAGPage(QWidget *parent) :
    QWidget(parent),
    clientModel(0),
    refreshTimer(new QTimer(this))
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(18, 18, 18, 18);
    mainLayout->setSpacing(12);

    QLabel *title = new QLabel(tr("IDAG"));
    QFont titleFont = title->font();
    titleFont.setPointSize(titleFont.pointSize() + 6);
    titleFont.setBold(true);
    title->setFont(titleFont);
    mainLayout->addWidget(title);

    QGroupBox *summaryGroup = new QGroupBox(tr("Summary"));
    QGridLayout *summaryLayout = new QGridLayout(summaryGroup);
    summaryLayout->setHorizontalSpacing(24);
    summaryLayout->setVerticalSpacing(8);

    statusValue = addMetric(summaryLayout, 0, 0, tr("Status"));
    heightValue = addMetric(summaryLayout, 1, 0, tr("Height"));
    tipsValue = addMetric(summaryLayout, 2, 0, tr("Tips"));
    entriesValue = addMetric(summaryLayout, 3, 0, tr("Entries"));

    algorithmValue = addMetric(summaryLayout, 0, 1, tr("Algorithm"));
    inferredKValue = addMetric(summaryLayout, 1, 1, tr("Inferred k"));
    adaptiveLimitValue = addMetric(summaryLayout, 2, 1, tr("Adaptive limit"));
    utilizationValue = addMetric(summaryLayout, 3, 1, tr("Current utilization"));

    bestTipValue = addMetric(summaryLayout, 0, 2, tr("Best tip"));
    bestScoreValue = addMetric(summaryLayout, 1, 2, tr("Best score"));
    finalityValue = addMetric(summaryLayout, 2, 2, tr("Finality"));
    epochValue = addMetric(summaryLayout, 3, 2, tr("Epoch"));

    mainLayout->addWidget(summaryGroup);

    QGroupBox *recentGroup = new QGroupBox(tr("Recent Activity"));
    QVBoxLayout *recentLayout = new QVBoxLayout(recentGroup);
    recentBlocksTable = new QTableWidget(0, 8, this);
    recentBlocksTable->setHorizontalHeaderLabels(QStringList()
        << tr("Height")
        << tr("Hash")
        << tr("Type")
        << tr("Size")
        << tr("Tx")
        << tr("Interval")
        << tr("Utilization")
        << tr("Parents"));
    recentBlocksTable->verticalHeader()->hide();
    recentBlocksTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    recentBlocksTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    recentBlocksTable->setAlternatingRowColors(true);
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    recentBlocksTable->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
    recentBlocksTable->horizontalHeader()->setResizeMode(1, QHeaderView::Stretch);
#else
    recentBlocksTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    recentBlocksTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
#endif
    recentLayout->addWidget(recentBlocksTable);
    mainLayout->addWidget(recentGroup, 1);

    connect(refreshTimer, SIGNAL(timeout()), this, SLOT(refresh()));
    refreshTimer->start(2000);

    refresh();
}

QLabel* IDAGPage::addMetric(QGridLayout *layout, int row, int column, const QString &title)
{
    QLabel *name = new QLabel(title);
    QFont nameFont = name->font();
    nameFont.setBold(true);
    name->setFont(nameFont);

    QLabel *value = new QLabel(tr("N/A"));
    value->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    value->setMinimumWidth(150);

    int baseColumn = column * 2;
    layout->addWidget(name, row, baseColumn);
    layout->addWidget(value, row, baseColumn + 1);
    return value;
}

void IDAGPage::setModel(ClientModel *model)
{
    if (clientModel)
        disconnect(clientModel, 0, this, 0);

    clientModel = model;

    if (clientModel)
        connect(clientModel, SIGNAL(numBlocksChanged(int,int)), this, SLOT(refresh()));

    refresh();
}

QString IDAGPage::shortHash(const QString &hash) const
{
    if (hash.isEmpty())
        return tr("N/A");
    if (hash.size() <= 16)
        return hash;
    return hash.left(16);
}

QString IDAGPage::formatBytes(unsigned int bytes) const
{
    if (bytes >= 1000000)
        return tr("%1 MB").arg((double)bytes / 1000000.0, 0, 'f', 2);
    if (bytes >= 1000)
        return tr("%1 KB").arg((double)bytes / 1000.0, 0, 'f', 1);
    return tr("%1 B").arg(bytes);
}

QString IDAGPage::formatPercent(double value) const
{
    return tr("%1%").arg(value, 0, 'f', 3);
}

void IDAGPage::setValue(QLabel *label, const QString &value, const QString &toolTip)
{
    label->setText(value);
    label->setToolTip(toolTip.isEmpty() ? value : toolTip);
}

void IDAGPage::refresh()
{
    if (!clientModel)
    {
        setValue(statusValue, tr("No client model"));
        recentBlocksTable->setRowCount(0);
        return;
    }

    ClientModel::DAGStatus status = clientModel->getDAGStatus(24);
    if (status.lockBusy)
    {
        setValue(statusValue, tr("Updating..."));
        return;
    }

    if (!status.valid)
    {
        setValue(statusValue, tr("Unavailable"));
        recentBlocksTable->setRowCount(0);
        return;
    }

    QString statusText;
    if (!status.active)
        statusText = tr("IDAG not active");
    else if (status.dagKnightActive)
        statusText = tr("DAGKNIGHT active");
    else
        statusText = tr("GHOSTDAG active");

    setValue(statusValue, statusText);
    setValue(heightValue, tr("%1 (DAG fork %2)").arg(status.height).arg(status.dagForkHeight));
    setValue(tipsValue, QString::number(status.tipCount));
    setValue(entriesValue, QString::number(status.entryCount));
    setValue(algorithmValue, status.orderingAlgorithm);

    QString inferredK = tr("N/A");
    if (status.dagKnightActive)
        inferredK = status.inferredKError ? tr("Unavailable") : QString::number(status.inferredK);
    setValue(inferredKValue, inferredK);

    setValue(
        adaptiveLimitValue,
        tr("%1 (%2 floor / %3 ceiling)")
            .arg(formatBytes(status.adaptiveBlockLimit))
            .arg(formatBytes(status.adaptiveBlockFloor))
            .arg(formatBytes(status.adaptiveBlockCeiling)));

    setValue(
        utilizationValue,
        tr("%1 (%2, %3 tx)")
            .arg(formatPercent(status.latestBlockUtilizationPct))
            .arg(formatBytes(status.latestBlockSize))
            .arg(status.latestBlockTxCount));

    setValue(bestTipValue, shortHash(status.bestDAGTip), status.bestDAGTip);
    setValue(bestScoreValue, shortHash(status.bestDAGScore), status.bestDAGScore);

    QString finality = tr("%1, finalized height %2, votes %3/%4")
        .arg(status.finalityTier)
        .arg(status.finalizedHeight)
        .arg(status.currentEpochVotes)
        .arg(status.currentEpochVoters);
    if (status.finalityTier == "none" && status.currentEpochVotes == 0)
        finality = tr("none, no votes, finalized height %1").arg(status.finalizedHeight);
    setValue(finalityValue, finality);

    setValue(epochValue, tr("%1 (%2-block interval)").arg(status.epoch).arg(status.epochInterval));

    recentBlocksTable->setRowCount(status.recentBlocks.size());
    for (int row = 0; row < status.recentBlocks.size(); row++)
    {
        const ClientModel::DAGBlockActivity &activity = status.recentBlocks.at(row);
        QString parents = activity.parentCount >= 0 ? QString::number(activity.parentCount) : tr("N/A");
        QString interval = row == status.recentBlocks.size() - 1 && activity.intervalSeconds == 0
            ? tr("N/A")
            : tr("%1 s").arg(activity.intervalSeconds);

        QList<QTableWidgetItem*> items;
        items << new QTableWidgetItem(QString::number(activity.height));
        items << new QTableWidgetItem(shortHash(activity.hash));
        items << new QTableWidgetItem(activity.blockType);
        items << new QTableWidgetItem(formatBytes(activity.sizeBytes));
        items << new QTableWidgetItem(QString::number(activity.txCount));
        items << new QTableWidgetItem(interval);
        items << new QTableWidgetItem(formatPercent(activity.utilizationPct));
        items << new QTableWidgetItem(parents);

        for (int column = 0; column < items.size(); column++)
        {
            if (column != 1 && column != 2)
                items[column]->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            if (column == 1)
                items[column]->setToolTip(activity.hash);
            recentBlocksTable->setItem(row, column, items[column]);
        }
    }
}
