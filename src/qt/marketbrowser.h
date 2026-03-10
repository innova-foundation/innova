#ifndef MARKETBROWSER_H
#define MARKETBROWSER_H

#include "clientmodel.h"
#include "main.h"
#include "wallet.h"
#include "base58.h"

#include <QWidget>
#include <QObject>
#include <QFutureWatcher>

extern QString bitcoing;
extern QString dollarg;
extern QString eurog;
extern QString poundg;
extern QString rubleg;
extern QString yeng;
extern QString innmarket;
extern QString innnewsfeed;

namespace Ui {
class MarketBrowser;
}
class ClientModel;

struct MarketData {
    double innUsd;
    double btcUsd;
    double innMcap;
    double innBtc;
    bool success;
    MarketData() : innUsd(0), btcUsd(0), innMcap(0), innBtc(0), success(false) {}
};

class MarketBrowser : public QWidget
{
    Q_OBJECT

public:
    explicit MarketBrowser(QWidget *parent = 0);
    ~MarketBrowser();

    void setModel(ClientModel *model);

signals:

public slots:
    void requests();
    void update();

private:
    Ui::MarketBrowser *ui;
    ClientModel *model;
    QFutureWatcher<MarketData> *marketWatcher;
    bool fetchInProgress;

    QString innovap;
    QString bitcoinp;
    QString innmcp;
    QString innbtcp;

    static MarketData fetchMarketWorker();

private slots:
    void onMarketFetched();
};

#endif // MARKETBROWSER_H
