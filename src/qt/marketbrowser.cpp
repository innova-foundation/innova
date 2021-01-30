#include "marketbrowser.h"
#include "ui_marketbrowser.h"
#include "main.h"
#include "wallet.h"
#include "base58.h"
#include "clientmodel.h"
#include "innovarpc.h"
#include <QDesktopServices>
#include <curl/curl.h>

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


requests(); //Segfaults 20.04/18.04
//QObject::connect(&m_nam, SIGNAL(finished(QNetworkReply*)), this, SLOT(parseNetworkResponse(QNetworkReply*)));
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
	getRequest1(kBaseUrl);
  getRequest2(kBaseUrl1);
	getRequest3(kBaseUrl2);
	getRequest4(kBaseUrl3);
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  ((std::string*)userp)->append((char*)contents, size * nmemb);
  return size * nmemb;
}

void MarketBrowser::getRequest1( const QString &urlString )
{
  CURL *curl;
      CURLcode res;
      std::string readBuffer;

      curl = curl_easy_init();
      if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, urlString.toStdString().c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        res = curl_easy_perform(curl);
        if(res != CURLE_OK){
              qWarning("curl_easy_perform() failed: \n");
        }
        curl_easy_cleanup(curl);

      //   std::cout << readBuffer << std::endl;

        //qDebug(readBuffer);
      //   qDebug("D cURL Request: %s", readBuffer.c_str());

          QString innova = QString::fromStdString(readBuffer);
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
}

void MarketBrowser::getRequest2( const QString &urlString )
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if(curl) {
      curl_easy_setopt(curl, CURLOPT_URL, urlString.toStdString().c_str());
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
      res = curl_easy_perform(curl);
      if(res != CURLE_OK){
            qWarning("curl_easy_perform() failed: \n");
      }
      curl_easy_cleanup(curl);

    //   std::cout << readBuffer << std::endl;

      //qDebug(readBuffer);
    //   qDebug("BTC cURL Request: %s", readBuffer.c_str());

        QString bitcoin = QString::fromStdString(readBuffer);
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
}

void MarketBrowser::getRequest3( const QString &urlString )
{

  CURL *curl;
  CURLcode res;
  std::string readBuffer;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, urlString.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    res = curl_easy_perform(curl);
    if(res != CURLE_OK){
          qWarning("curl_easy_perform() failed: \n");
    }
    curl_easy_cleanup(curl);

  //   std::cout << readBuffer << std::endl;

    //qDebug(readBuffer);
      // qDebug("INN MCap cURL Request: %s", readBuffer.c_str());

      QString innmc = QString::fromStdString(readBuffer);
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
}

void MarketBrowser::getRequest4( const QString &urlString )
{

  CURL *curl;
  CURLcode res;
  std::string readBuffer;

  curl = curl_easy_init();
  if(curl) {
      curl_easy_setopt(curl, CURLOPT_URL, urlString.toStdString().c_str());
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
      res = curl_easy_perform(curl);
      if(res != CURLE_OK){
          qWarning("curl_easy_perform() failed: \n");
      }
      curl_easy_cleanup(curl);

      // std::cout << readBuffer << std::endl;

      //qDebug(readBuffer);
      // qDebug("D/BTC cURL Request: %s", readBuffer.c_str());


      QString innbtc = QString::fromStdString(readBuffer);
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
}

void MarketBrowser::setModel(ClientModel *model)
{
    this->model = model;
}

MarketBrowser::~MarketBrowser()
{
    delete ui;
}
