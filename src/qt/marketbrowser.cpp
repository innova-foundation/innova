#include "marketbrowser.h"
#include "ui_marketbrowser.h"
#include "main.h"
#include "wallet.h"
#include "base58.h"
#include "clientmodel.h"
#include "innovarpc.h"
#include <QDesktopServices>
#include <curl/curl.h>
#include <QtConcurrent/QtConcurrent>

#include <sstream>
#include <string>

using namespace json_spirit;

const QString kBaseUrl = "https://innova-foundation.com/innusd.php";
const QString kBaseUrl1 = "https://innova-foundation.com/ibitcoin.php";
const QString kBaseUrl2 = "https://innova-foundation.com/innmc.php";
const QString kBaseUrl3 = "https://innova-foundation.com/innbitcoin.php";

double bitcoin2;
double innova2;
double innmc2;
double innbtc2;
QString bitcoing;
QString innnewsfeed;
QString innmarket;
QString dollarg;
QString eurog;
QString poundg;
QString rubleg;
QString yeng;
int mode=1;
int o = 0;


MarketBrowser::MarketBrowser(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MarketBrowser),
    fetchInProgress(false)
{
    ui->setupUi(this);
    setFixedSize(400, 420);

    marketWatcher = new QFutureWatcher<MarketData>(this);
    connect(marketWatcher, SIGNAL(finished()), this, SLOT(onMarketFetched()));

    requests();
    connect(ui->startButton, SIGNAL(pressed()), this, SLOT(requests()));
    connect(ui->egal, SIGNAL(pressed()), this, SLOT(update()));
}

void MarketBrowser::update()
{
    QString temps = ui->egals->text();
    double totald = dollarg.toDouble() * temps.toDouble();
    double totaldq = bitcoing.toDouble() * temps.toDouble();
    ui->egald->setText("$ "+QString::number(totald)+" USD or "+QString::number(totaldq)+" BTC");
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Helper: fetch a single URL, return body as string
static std::string fetchUrl(const std::string &url)
{
    std::string readBuffer;
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return readBuffer;
}

// Static worker — runs on thread pool, NO Qt UI access
MarketData MarketBrowser::fetchMarketWorker()
{
    MarketData result;

    std::string buf1 = fetchUrl(kBaseUrl.toStdString());
    std::string buf2 = fetchUrl(kBaseUrl1.toStdString());
    std::string buf3 = fetchUrl(kBaseUrl2.toStdString());
    std::string buf4 = fetchUrl(kBaseUrl3.toStdString());

    if (!buf1.empty()) result.innUsd = QString::fromStdString(buf1).toDouble();
    if (!buf2.empty()) result.btcUsd = QString::fromStdString(buf2).toDouble();
    if (!buf3.empty()) result.innMcap = QString::fromStdString(buf3).toDouble();
    if (!buf4.empty()) result.innBtc = QString::fromStdString(buf4).toDouble();

    result.success = true;
    return result;
}

// Called on UI thread — dispatches work to thread pool
void MarketBrowser::requests()
{
    if (fetchInProgress)
        return;

    fetchInProgress = true;
    QFuture<MarketData> future = QtConcurrent::run(fetchMarketWorker);
    marketWatcher->setFuture(future);
}

// Called on UI thread when fetch completes — safe to update UI
void MarketBrowser::onMarketFetched()
{
    fetchInProgress = false;

    MarketData data = marketWatcher->result();
    if (!data.success)
        return;

    // INN/USD
    if (data.innUsd > 0) {
        QString innova = QString::number(data.innUsd, 'f', 2);
        if (innova > innovap)
            ui->innova->setText("<font color=\"yellow\">$" + innova + "</font>");
        else if (innova < innovap)
            ui->innova->setText("<font color=\"red\">$" + innova + "</font>");
        else
            ui->innova->setText("$" + innova + " USD");
        innovap = innova;
        dollarg = innova;
    }

    // BTC/USD
    if (data.btcUsd > 0) {
        QString bitcoin = QString::number(data.btcUsd, 'f', 2);
        if (bitcoin > bitcoinp)
            ui->bitcoin->setText("<font color=\"yellow\">$" + bitcoin + " USD</font>");
        else if (bitcoin < bitcoinp)
            ui->bitcoin->setText("<font color=\"red\">$" + bitcoin + " USD</font>");
        else
            ui->bitcoin->setText("$" + bitcoin + " USD");
        bitcoinp = bitcoin;
    }

    // INN Market Cap
    if (data.innMcap > 0) {
        QString innmc = QString::number(data.innMcap, 'f', 2);
        if (innmc > innmcp)
            ui->innmc->setText("<font color=\"yellow\">$" + innmc + "</font>");
        else if (innmc < innmcp)
            ui->innmc->setText("<font color=\"red\">$" + innmc + "</font>");
        else
            ui->innmc->setText("$" + innmc + " USD");
        innmcp = innmc;
        innmarket = innmc;
    }

    // INN/BTC
    if (data.innBtc > 0) {
        QString innbtc = QString::number(data.innBtc, 'f', 8);
        if (innbtc > innbtcp)
            ui->innbtc->setText("<font color=\"yellow\">" + innbtc + " BTC</font>");
        else if (innbtc < innbtcp)
            ui->innbtc->setText("<font color=\"red\">" + innbtc + " BTC</font>");
        else
            ui->innbtc->setText(innbtc + " BTC");
        innbtcp = innbtc;
        bitcoing = innbtc;
    }
}

void MarketBrowser::setModel(ClientModel *model)
{
    this->model = model;
}

MarketBrowser::~MarketBrowser()
{
    delete ui;
}
