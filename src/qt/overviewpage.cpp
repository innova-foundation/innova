#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "walletmodel.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "transactiontablemodel.h"
#include "transactionfilterproxy.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "marketbrowser.h"
#include <curl/curl.h>

#include <QAbstractItemDelegate>
#include <QPainter>
#include <QTimer>
#include <QDebug>
#include <QScrollArea>
//#include <QScroller>

#define DECORATION_SIZE 36
#define NUM_ITEMS 7

const QString BaseURL = "https://innova-foundation.com/innusd.php";
const QString BaseURL2 = "https://innova-foundation.com/innbitcoin.php";
const QString BaseURL3 = "https://innova-foundation.com/newsfeed.php";
const QString BaseURL4 = "https://innova-foundation.com/inneur.php";
const QString BaseURL5 = "https://innova-foundation.com/inngbp.php";
const QString BaseURL6 = "https://innova-foundation.com/innrub.php";
const QString BaseURL7 = "https://innova-foundation.com/innjpy.php";
double innovax;
double inneurx;
double inngbpx;
double innrubx;
double innjpyx;
double innbtcx;

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate(): QAbstractItemDelegate(), unit(BitcoinUnits::BTC), unitUSD(BitcoinUnits::USD)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(qVariantCanConvert<QColor>(value))
        {
            foreground = qvariant_cast<QColor>(value);
        }

        painter->setPen(foreground);
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address);

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
	int unitUSD;

};
#include "overviewpage.moc"

OverviewPage::OverviewPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    currentBalance(-1),
    currentStake(0),
    currentUnconfirmedBalance(-1),
    currentImmatureBalance(-1),
    txdelegate(new TxViewDelegate()),
    filter(0)
{
    ui->setupUi(this);



  PriceRequest(); //Segfault 20.04/18.04
	QObject::connect(&m_nam, SIGNAL(finished(QNetworkReply*)), this, SLOT(parseNetworkResponse(QNetworkReply*)));
	connect(ui->refreshButton, SIGNAL(pressed()), this, SLOT( PriceRequest()));

	//Refresh the Est. Balances and News automatically
	  refreshbtnTimer = new QTimer(this);
    connect(refreshbtnTimer, SIGNAL(timeout()), this, SLOT( PriceRequest()));
    refreshbtnTimer->start(120000); // 120 second timer

    //Handle refreshing updateDisplayUnit() more often instead of every tx change
    updateDisplayTimer = new QTimer(this);
    connect(updateDisplayTimer, SIGNAL(timeout()), this, SLOT( updateDisplayUnit()));
    updateDisplayTimer->start(120000); // Multithreaded, when a thread is available refresh all overview displays

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText("(" + tr("Out of Sync!") + ")");
    ui->labelTransactionsStatus->setText("(" + tr("Out of Sync!") + ")");

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
}

void OverviewPage::PriceRequest()
{
	getRequest1(BaseURL);
	getRequest2(BaseURL2);
	getRequest3(BaseURL3);
  getRequest4(BaseURL4);
  getRequest5(BaseURL5);
  getRequest6(BaseURL6);
  getRequest7(BaseURL7);
    //updateDisplayUnit(); //Segfault Fix
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void OverviewPage::getRequest1( const QString &urlString )
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

      //std::cout << readBuffer << std::endl;

      //qDebug(readBuffer);
      //qDebug("cURL Request: %s", readBuffer.c_str());

        QString denarius = QString::fromStdString(readBuffer);
        denariusx = (denarius.toDouble());
        denarius = QString::number(denariusx, 'f', 2);

        dollarg = denarius;
    }
}

void OverviewPage::getRequest2( const QString &urlString )
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

        QString innbtc = QString::fromStdString(readBuffer);
        innbtcx = (innbtc.toDouble());
        innbtc = QString::number(innbtcx, 'f', 8);

        bitcoing = innbtc;
    }
}

void OverviewPage::getRequest3( const QString &urlString )
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


        QString dnewsfeed = QString::fromStdString(readBuffer);
        innnewsfeed = dnewsfeed;
    }
}

void OverviewPage::getRequest4( const QString &urlString )
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

      //std::cout << readBuffer << std::endl;

      //qDebug(readBuffer);
      //qDebug("cURL Request: %s", readBuffer.c_str());

        QString inneur = QString::fromStdString(readBuffer);
        inneurx = (inneur.toDouble());
        inneur = QString::number(inneurx, 'f', 4);

        eurog = inneur;
    }
}

void OverviewPage::getRequest5( const QString &urlString )
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

      //std::cout << readBuffer << std::endl;

      //qDebug(readBuffer);
      //qDebug("cURL Request: %s", readBuffer.c_str());

        QString inngbp = QString::fromStdString(readBuffer);
        inngbpx = (inngbp.toDouble());
        inngbp = QString::number(inngbpx, 'f', 6);

        poundg = inngbp;
    }
}

void OverviewPage::getRequest6( const QString &urlString )
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

      //std::cout << readBuffer << std::endl;

      //qDebug(readBuffer);
      //qDebug("cURL Request: %s", readBuffer.c_str());

        QString innrub = QString::fromStdString(readBuffer);
        innrubx = (innrub.toDouble());
        innrub = QString::number(innrubx, 'f', 10);

        rubleg = innrub;
    }
}

void OverviewPage::getRequest7( const QString &urlString )
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

      //std::cout << readBuffer << std::endl;

      //qDebug(readBuffer);
      //qDebug("cURL Request: %s", readBuffer.c_str());

        QString innjpy = QString::fromStdString(readBuffer);
        innjpyx = (innjpy.toDouble());
        innjpy = QString::number(innjpyx, 'f', 12);

        yeng = innjpy;
    }
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        emit transactionClicked(filter->mapToSource(index));
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setBalance(qint64 balance, qint64 lockedbalance, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance, qint64 watchOnlyBalance, qint64 watchUnconfBalance, qint64 watchImmatureBalance)
{
    int unit = model->getOptionsModel()->getDisplayUnit();
    int unitdBTC = BitcoinUnits::dBTC;
    currentBalance = balance;
    currentLockedBalance = lockedbalance;
    currentStake = stake;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentImmatureBalance = immatureBalance;

    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;
    totalBalance = balance + lockedbalance + unconfirmedBalance + immatureBalance;

    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance));
    ui->labelLocked->setText(BitcoinUnits::formatWithUnit(unit, lockedbalance));

    ui->labelStake->setText(BitcoinUnits::formatWithUnit(unit, stake));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance));
    ui->labelTotal->setText(BitcoinUnits::formatWithUnit(unit, totalBalance));

    //Watch Only Balances
    ui->labelWatchAvailable->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance));
    ui->labelWatchPending->setText(BitcoinUnits::formatWithUnit(unit, watchUnconfBalance));
    ui->labelWatchImmature->setText(BitcoinUnits::formatWithUnit(unit, watchImmatureBalance));
    ui->labelWatchTotal->setText(BitcoinUnits::formatWithUnit(unit, watchOnlyBalance + watchUnconfBalance + watchImmatureBalance));


  	QString total;
    double dollarg1 = (dollarg.toDouble() * totalBalance / 100000000);
  	total = QString::number(dollarg1, 'f', 2);
  	ui->labelUSDTotal->setText("$" + total + " USD");

	  QString eurtotal;
	  double eurog1 = (eurog.toDouble() * totalBalance / 100000000);
  	eurtotal = QString::number(eurog1, 'f', 4);
  	ui->labelEURTotal->setText("€" + eurtotal + " EUR");

    QString gbptotal;
    double poundg1 = (poundg.toDouble() * totalBalance / 100000000);
    gbptotal = QString::number(poundg1, 'f', 6);
    ui->labelGBPTotal->setText("£" + gbptotal + " GBP");

    QString rubtotal;
    double rubleg1 = (rubleg.toDouble() * totalBalance / 100000000);
    rubtotal = QString::number(rubleg1, 'f', 10);
    ui->labelRUBTotal->setText("₽" + rubtotal + " RUB");

    QString jpytotal;
    double yeng1 = (yeng.toDouble() * totalBalance / 100000000);
    jpytotal = QString::number(yeng1, 'f', 12);
    ui->labelJPYTotal->setText("¥" + jpytotal + " JPY");

    ui->labelBTCTotal->setText("Ƀ" + BitcoinUnits::formatWithUnit(unitdBTC, bitcoing.toDouble() * totalBalance));
    ui->labelTradeLink->setTextFormat(Qt::RichText);
    ui->labelTradeLink->setTextInteractionFlags(Qt::TextBrowserInteraction);
    ui->labelTradeLink->setOpenExternalLinks(true);

	QString news;
	news = innnewsfeed;
  ui->labelNewsFeed->setText(news);

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = immatureBalance != 0;
    bool showLocked = lockedbalance != 0;
    bool showWatchImmature = watchImmatureBalance != 0;
    bool showStakeBalance = GetBoolArg("-staking", true);

    ui->labelImmature->setVisible(showImmature);
    ui->labelImmatureText->setVisible(showImmature);
    ui->labelWatchImmature->setVisible(showWatchImmature);
    ui->labelWatchImmatureText->setVisible(showWatchImmature);
    ui->labelLocked->setVisible(showLocked);
    ui->labelLockedText->setVisible(showLocked);
    ui->labelStake->setVisible(showStakeBalance);
    ui->labelStakeText->setVisible(showStakeBalance);

}

void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    //ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    //ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

	ui->watch1->setVisible(showWatchOnly);
	ui->watch2->setVisible(showWatchOnly);
    ui->labelWatchImmatureText->setVisible(showWatchOnly);
	ui->watch4->setVisible(showWatchOnly);

    if (!showWatchOnly)
        ui->labelWatchImmature->hide();
 }

void OverviewPage::setModel(WalletModel *model)
{
    this->model = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter = new TransactionFilterProxy();
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Status, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter);
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        setBalance(model->getUnlockedBalance(), model->getLockedBalance(), model->getStakeAmount(), model->getUnconfirmedBalance(), model->getImmatureBalance(), model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance());
        connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64)), this, SLOT(setBalance(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64)));

        // Watch Only
        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        if(currentBalance != -1)
            setBalance(currentBalance, currentLockedBalance, model->getStakeAmount(), currentUnconfirmedBalance, currentImmatureBalance, currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = model->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}
