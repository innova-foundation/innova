#ifndef OVERVIEWPAGE_H
#define OVERVIEWPAGE_H

#include <QWidget>
#include <QTimer>
#include <QFutureWatcher>

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

namespace Ui {
    class OverviewPage;
}
class WalletModel;
class TxViewDelegate;
class TransactionFilterProxy;

struct PriceData {
    double usd;
    double btc;
    double eur;
    double gbp;
    double rub;
    double jpy;
    QString newsfeed;
    bool success;
    PriceData() : usd(0), btc(0), eur(0), gbp(0), rub(0), jpy(0), success(false) {}
};

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(QWidget *parent = 0);
    ~OverviewPage();

    void setModel(WalletModel *model);
    void showOutOfSyncWarning(bool fShow);

public slots:
    void setBalance(qint64 balance, qint64 lockedbalance, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance, qint64 watchOnlyBalance, qint64 watchUnconfBalance, qint64 watchImmatureBalance);
    void PriceRequest();

signals:
    void transactionClicked(const QModelIndex &index);

private:
    QTimer *timer;
    QTimer *refreshbtnTimer;
    QTimer *updateDisplayTimer;
    Ui::OverviewPage *ui;
    WalletModel *model;
    qint64 currentBalance;
    qint64 currentLockedBalance;
    qint64 currentStake;
    qint64 currentUnconfirmedBalance;
    qint64 currentImmatureBalance;
    qint64 currentWatchOnlyBalance;
    qint64 currentWatchUnconfBalance;
    qint64 currentWatchImmatureBalance;
    qint64 totalBalance;
    qint64 lastNewBlock;

    int cachedNumBlocks;
    TxViewDelegate *txdelegate;
    TransactionFilterProxy *filter;
    QFutureWatcher<PriceData> *priceWatcher;
    bool priceFetchInProgress;

    static PriceData fetchPricesWorker();

private slots:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void onPricesFetched();
};

#endif // OVERVIEWPAGE_H
