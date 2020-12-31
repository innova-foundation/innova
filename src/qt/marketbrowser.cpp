#include "marketbrowser.h"
#include "ui_marketbrowser.h"
#include "main.h"
#include "wallet.h"
#include "base58.h"
#include "clientmodel.h"
#include "innovarpc.h"
#include <QDesktopServices>

#include <sstream>
#include <string>

using namespace json_spirit;

const QString kBaseUrl = "https://innova-foundation.com/innusd.php";
const QString kBaseUrl1 = "https://innova-foundation.com/ibitcoin.php";
const QString kBaseUrl2 = "https://innova-foundation.com/innmc.php";
const QString kBaseUrl3 = "https://innova-foundation.com/innbitcoin.php";

QString bitcoinp = "";
QString innovap = "";
QString innmcp = "";
QString innbtcp = "";
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
QString yeng;
int mode=1;
int o = 0;


MarketBrowser::MarketBrowser(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MarketBrowser)
{
    ui->setupUi(this);
    setFixedSize(400, 420);


requests();
QObject::connect(&m_nam, SIGNAL(finished(QNetworkReply*)), this, SLOT(parseNetworkResponse(QNetworkReply*)));
connect(ui->startButton, SIGNAL(pressed()), this, SLOT( requests()));
connect(ui->egal, SIGNAL(pressed()), this, SLOT( update()));

}

void MarketBrowser::update()
{
    QString temps = ui->egals->text();
    double totald = dollarg.toDouble() * temps.toDouble();
    double totaldq = bitcoing.toDouble() * temps.toDouble();
    ui->egald->setText("$ "+QString::number(totald)+" USD or "+QString::number(totaldq)+" BTC");

}

void MarketBrowser::requests()
{
	getRequest(kBaseUrl);
  getRequest(kBaseUrl1);
	getRequest(kBaseUrl2);
	getRequest(kBaseUrl3);
}

void MarketBrowser::getRequest( const QString &urlString )
{
    QUrl url ( urlString );
    QNetworkRequest req ( url );
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json; charset=utf-8");
    m_nam.get(req);
}

void MarketBrowser::parseNetworkResponse(QNetworkReply *finished )
{

    QUrl what = finished->url();

    if ( finished->error() != QNetworkReply::NoError )
    {
        // A communication error has occurred
        emit networkError( finished->error() );
        return;
    }

if (what == kBaseUrl) // Innova Price
{

    // QNetworkReply is a QIODevice. So we read from it just like it was a file
    QString innova = finished->readAll();
    innova2 = (innova.toDouble());
    innova = QString::number(innova2, 'f', 2);

    if(innova > innovap)
    {
        ui->innova->setText("<font color=\"yellow\">$" + innova + "</font>");
    } else if (innova < innovap) {
        ui->innova->setText("<font color=\"red\">$" + innova + "</font>");
        } else {
    ui->innova->setText("$"+innova+" USD");
    }

    innovap = innova;
	  dollarg = innova;
}

if (what == kBaseUrl1) // Bitcoin Price
{

    // QNetworkReply is a QIODevice. So we read from it just like it was a file
    QString bitcoin = finished->readAll();
    bitcoin2 = (bitcoin.toDouble());
    bitcoin = QString::number(bitcoin2, 'f', 2);
    if(bitcoin > bitcoinp)
    {
        ui->bitcoin->setText("<font color=\"yellow\">$" + bitcoin + " USD</font>");
    } else if (bitcoin < bitcoinp) {
        ui->bitcoin->setText("<font color=\"red\">$" + bitcoin + " USD</font>");
        } else {
    ui->bitcoin->setText("$"+bitcoin+" USD");
    }

    bitcoinp = bitcoin;
}

if (what == kBaseUrl2) // Innova Market Cap
{

    // QNetworkReply is a QIODevice. So we read from it just like it was a file
    QString innmc = finished->readAll();
    innmc2 = (innmc.toDouble());
    innmc = QString::number(innmc2, 'f', 2);

    if(innmc > innmcp)
    {
        ui->innmc->setText("<font color=\"yellow\">$" + innmc + "</font>");
    } else if (innmc < innmcp) {
        ui->innmc->setText("<font color=\"red\">$" + innmc + "</font>");
        } else {
    ui->innmc->setText("$"+innmc+" USD");
    }

    innmcp = innmc;
	innmarket = innmc;
}

if (what == kBaseUrl3) // Innova BTC Price
{

    // QNetworkReply is a QIODevice. So we read from it just like it was a file
    QString innbtc = finished->readAll();
    innbtc2 = (innbtc.toDouble());
    innbtc = QString::number(innbtc2, 'f', 8);

    if(innbtc > innbtcp)
    {
        ui->innbtc->setText("<font color=\"yellow\">" + innbtc + " BTC</font>");
    } else if (innbtc < innbtcp) {
        ui->innbtc->setText("<font color=\"red\">" + innbtc + " BTC</font>");
        } else {
    ui->innbtc->setText(innbtc+" BTC");
    }

    innbtcp = innbtc;
	bitcoing = innbtc;
}

finished->deleteLater();
}


void MarketBrowser::setModel(ClientModel *model)
{
    this->model = model;
}

MarketBrowser::~MarketBrowser()
{
    delete ui;
}
