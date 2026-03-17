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
#include "main.h"
#include <curl/curl.h>

#include <QAbstractItemDelegate>
#include <QPainter>
#include <QTimer>
#include <QDebug>
#include <QScrollArea>
#include <QtConcurrent/QtConcurrent>

#define DECORATION_SIZE 36
#define NUM_ITEMS 7

// CoinGecko API for prices (replaces dead innova-foundation.com PHP endpoints)
const QString PriceAPIURL = "https://api.coingecko.com/api/v3/simple/price?ids=innova&vs_currencies=usd,btc,eur,gbp,rub,jpy";
// Innova Foundation news feed (fallback: shows link to website)
const QString NewsURL = "https://innova-foundation.com/community/forum.html";
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
    filter(0),
    priceFetchInProgress(false)
{
    ui->setupUi(this);

    // Set up async price fetcher
    priceWatcher = new QFutureWatcher<PriceData>(this);
    connect(priceWatcher, SIGNAL(finished()), this, SLOT(onPricesFetched()));

    PriceRequest();
    connect(ui->refreshButton, SIGNAL(pressed()), this, SLOT(PriceRequest()));

    // Refresh the Est. Balances and News automatically
    refreshbtnTimer = new QTimer(this);
    connect(refreshbtnTimer, SIGNAL(timeout()), this, SLOT(PriceRequest()));
    refreshbtnTimer->start(120000); // 120 second timer

    // Handle refreshing updateDisplayUnit() more often instead of every tx change
    updateDisplayTimer = new QTimer(this);
    connect(updateDisplayTimer, SIGNAL(timeout()), this, SLOT(updateDisplayUnit()));
    updateDisplayTimer->start(120000);

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

static size_t PriceWriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

PriceData OverviewPage::fetchPricesWorker()
{
    PriceData result;

    // Single CoinGecko API call returns all prices as JSON
    std::string url = PriceAPIURL.toStdString();
    std::string buffer;

    CURL *curl = curl_easy_init();
    if (!curl)
        return result;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, PriceWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Innova-Wallet/5.0");

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || buffer.empty())
        return result;

    // Parse JSON: {"innova":{"usd":0.0006,"btc":6e-09,"eur":0.0005,"gbp":0.0004,"rub":0.05,"jpy":0.09}}
    QString json = QString::fromStdString(buffer);

    // Simple JSON extraction (no dependency on json_spirit in Qt code)
    auto extractDouble = [&](const QString& key) -> double {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return 0;
        idx = json.indexOf(":", idx);
        if (idx < 0) return 0;
        // Find the end of the number (next comma or closing brace)
        int start = idx + 1;
        int end = start;
        while (end < json.size() && json[end] != ',' && json[end] != '}')
            end++;
        if (end <= start) return 0;
        return json.mid(start, end - start).trimmed().toDouble();
    };

    result.usd = extractDouble("usd");
    result.btc = extractDouble("btc");
    result.eur = extractDouble("eur");
    result.gbp = extractDouble("gbp");
    result.rub = extractDouble("rub");
    result.jpy = extractDouble("jpy");

    // Fetch latest GitHub release for news
    std::string ghBuffer;
    CURL *ghCurl = curl_easy_init();
    if (ghCurl)
    {
        curl_easy_setopt(ghCurl, CURLOPT_URL, "https://api.github.com/repos/innova-foundation/innova/releases/latest");
        curl_easy_setopt(ghCurl, CURLOPT_WRITEFUNCTION, PriceWriteCallback);
        curl_easy_setopt(ghCurl, CURLOPT_WRITEDATA, &ghBuffer);
        curl_easy_setopt(ghCurl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(ghCurl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(ghCurl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(ghCurl, CURLOPT_USERAGENT, "Innova-Wallet/5.0");

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/vnd.github.v3+json");
        curl_easy_setopt(ghCurl, CURLOPT_HTTPHEADER, headers);

        CURLcode ghRes = curl_easy_perform(ghCurl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(ghCurl);

        if (ghRes == CURLE_OK && !ghBuffer.empty())
        {
            QString ghJson = QString::fromStdString(ghBuffer);

            // Extract release name and URL
            auto extractString = [&](const QString& json, const QString& key) -> QString {
                int idx = json.indexOf("\"" + key + "\"");
                if (idx < 0) return "";
                idx = json.indexOf(":", idx);
                if (idx < 0) return "";
                int qStart = json.indexOf("\"", idx + 1);
                if (qStart < 0) return "";
                int qEnd = json.indexOf("\"", qStart + 1);
                if (qEnd < 0) return "";
                return json.mid(qStart + 1, qEnd - qStart - 1);
            };

            QString releaseName = extractString(ghJson, "name");
            QString releaseUrl = extractString(ghJson, "html_url");
            QString publishedAt = extractString(ghJson, "published_at");

            if (!releaseName.isEmpty())
            {
                // Format date
                QString dateStr = publishedAt.left(10); // "2026-03-15"
                result.newsfeed = QString("<b>Latest Release:</b> <a href='%1' style='color: #4CAF50;'>%2</a> (%3)<br>"
                                         "<a href='https://innova-foundation.com/community/forum.html' style='color: #888;'>Community Forum</a> | "
                                         "<a href='https://github.com/innova-foundation/innova' style='color: #888;'>GitHub</a>")
                                         .arg(releaseUrl, releaseName, dateStr);
            }
            else
            {
                result.newsfeed = QString("<a href='https://innova-foundation.com/community/forum.html' style='color: #4CAF50;'>Innova Community Forum</a> | "
                                         "<a href='https://github.com/innova-foundation/innova' style='color: #888;'>GitHub</a>");
            }
        }
        else
        {
            result.newsfeed = QString("<a href='https://innova-foundation.com/community/forum.html' style='color: #4CAF50;'>Innova Community Forum</a>");
        }
    }

    result.success = (result.usd > 0 || result.btc > 0);
    return result;
}

void OverviewPage::PriceRequest()
{
    if (priceFetchInProgress)
        return; // Don't stack requests

    priceFetchInProgress = true;
    QFuture<PriceData> future = QtConcurrent::run(fetchPricesWorker);
    priceWatcher->setFuture(future);
}

void OverviewPage::onPricesFetched()
{
    priceFetchInProgress = false;

    PriceData data = priceWatcher->result();
    if (!data.success)
        return;

    if (data.usd > 0) {
        innovax = data.usd;
        dollarg = QString::number(innovax, 'f', 8); // full precision for small values
    }
    if (data.btc > 0) {
        innbtcx = data.btc;
        bitcoing = QString::number(innbtcx, 'f', 8);
    }
    if (!data.newsfeed.isEmpty()) {
        innnewsfeed = data.newsfeed;
    }
    if (data.eur > 0) {
        inneurx = data.eur;
        eurog = QString::number(inneurx, 'f', 4);
    }
    if (data.gbp > 0) {
        inngbpx = data.gbp;
        poundg = QString::number(inngbpx, 'f', 6);
    }
    if (data.rub > 0) {
        innrubx = data.rub;
        rubleg = QString::number(innrubx, 'f', 10);
    }
    if (data.jpy > 0) {
        innjpyx = data.jpy;
        yeng = QString::number(innjpyx, 'f', 12);
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

void OverviewPage::setBalance(qint64 balance, qint64 lockedbalance, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance, qint64 watchOnlyBalance, qint64 watchUnconfBalance, qint64 watchImmatureBalance, qint64 shieldedBalance)
{
    if (!model || !model->getOptionsModel())
        return;
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
    ui->labelStake->setToolTip(tr("Stake balance"));

    // Shielded (privacy) balance — always visible so users know it exists
    if (ui->labelShielded)
    {
        ui->labelShielded->setText(BitcoinUnits::formatWithUnit(unit, shieldedBalance));
        ui->labelShielded->setToolTip(tr("Shielded (private) balance — shield coins via the Send page to move funds here"));
    }

    // Include shielded in total
    totalBalance += shieldedBalance;

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
    // Trade link hidden - No exchanges for now
    // ui->labelTradeLink->setTextFormat(Qt::RichText);
    // ui->labelTradeLink->setTextInteractionFlags(Qt::TextBrowserInteraction);
    // ui->labelTradeLink->setOpenExternalLinks(true);

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
        setBalance(model->getUnlockedBalance(), model->getLockedBalance(), model->getStakeAmount(), model->getUnconfirmedBalance(), model->getImmatureBalance(), model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance(), model->getShieldedBalance());
        connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64)), this, SLOT(setBalance(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64)));

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
