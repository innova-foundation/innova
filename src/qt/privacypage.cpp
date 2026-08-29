#include "privacypage.h"

#include "bitcoinunits.h"
#include "disclosuremaskwidget.h"
#include "finalitystatuswidget.h"
#include "guiconstants.h"
#include "iv5rpcbridge.h"
#include "optionsmodel.h"
#include "privatecollateralwidget.h"
#include "walletmodel.h"

#include <QApplication>
#include <QClipboard>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>

PrivacyPage::PrivacyPage(QWidget *parent) :
    QWidget(parent),
    model(0)
{
    setupUI();
}

void PrivacyPage::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    QLabel *titleLabel = new QLabel(tr("Privacy"));
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;");
    mainLayout->addWidget(titleLabel);

    QLabel *descLabel = new QLabel(tr(
        "Value in this wallet lives in the pool as notes. A payment out of it has no "
        "transparent inputs and no transparent outputs whatever it discloses, so "
        "there is no shielded and transparent side to move value between. What a "
        "payment reveals is decided by its disclosure mask, and by nothing else."));
    descLabel->setWordWrap(true);
    descLabel->setStyleSheet("color: #888; margin-bottom: 15px;");
    mainLayout->addWidget(descLabel);

    availabilityLabel = new QLabel();
    availabilityLabel->setWordWrap(true);
    availabilityLabel->setStyleSheet("color: #d98c00; font-weight: bold; margin-bottom: 8px;");
    availabilityLabel->setVisible(false);
    mainLayout->addWidget(availabilityLabel);

    QGroupBox *balanceGroup = new QGroupBox(tr("Balances"));
    QFormLayout *balanceLayout = new QFormLayout(balanceGroup);
    labelPoolBalance = new QLabel(tr("unknown"));
    labelPoolBalance->setStyleSheet("font-weight: bold; color: #4CAF50;");
    labelPoolUnconfirmed = new QLabel(tr("unknown"));
    labelNoteCount = new QLabel(tr("unknown"));
    labelTransparentBalance = new QLabel(tr("unknown"));
    labelSeedState = new QLabel(tr("unknown"));
    labelScanGap = new QLabel(tr("unknown"));
    balanceLayout->addRow(tr("Pool (spendable):"), labelPoolBalance);
    balanceLayout->addRow(tr("Pool (unconfirmed):"), labelPoolUnconfirmed);
    balanceLayout->addRow(tr("Notes held:"), labelNoteCount);
    balanceLayout->addRow(tr("Transparent (not yet migrated):"), labelTransparentBalance);
    balanceLayout->addRow(tr("IV5 seed:"), labelSeedState);
    balanceLayout->addRow(tr("Scan gap:"), labelScanGap);
    QPushButton *refreshButton = new QPushButton(tr("Refresh"));
    balanceLayout->addRow(QString(), refreshButton);
    mainLayout->addWidget(balanceGroup);
    connect(refreshButton, SIGNAL(clicked()), this, SLOT(onRefreshClicked()));

    QTabWidget *tabs = new QTabWidget();
    tabs->addTab(buildSendTab(), tr("Send"));
    tabs->addTab(buildMigrateTab(), tr("Migrate"));
    tabs->addTab(buildAddressTab(), tr("Addresses"));

    collateralWidget = new PrivateCollateralWidget();
    tabs->addTab(collateralWidget, tr("Collateralnode"));

    finalityWidget = new FinalityStatusWidget();
    tabs->addTab(finalityWidget, tr("Finality"));

    mainLayout->addWidget(tabs, 1);

    statusLabel = new QLabel(tr("Ready"));
    statusLabel->setStyleSheet("color: #888; margin-top: 10px;");
    mainLayout->addWidget(statusLabel);
}

QWidget* PrivacyPage::buildSendTab()
{
    QWidget *tab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(tab);

    QGroupBox *group = new QGroupBox(tr("Send from the pool"));
    QFormLayout *form = new QFormLayout(group);
    sendToEdit = new QLineEdit();
    sendToEdit->setPlaceholderText(tr("Recipient IV5 address"));
    sendAmountEdit = new QLineEdit();
    sendAmountEdit->setPlaceholderText(tr("Amount in INN"));
    form->addRow(tr("To:"), sendToEdit);
    form->addRow(tr("Amount:"), sendAmountEdit);
    layout->addWidget(group);

    QGroupBox *maskGroup = new QGroupBox(tr("What this payment publishes"));
    QVBoxLayout *maskLayout = new QVBoxLayout(maskGroup);
    maskWidget = new DisclosureMaskWidget();
    maskLayout->addWidget(maskWidget);
    layout->addWidget(maskGroup);

    QHBoxLayout *buttons = new QHBoxLayout();
    sendButton = new QPushButton(tr("Send"));
    sendButton->setStyleSheet("QPushButton { background-color: #2196F3; color: white; "
                              "padding: 8px 16px; font-weight: bold; }");
    buttons->addWidget(sendButton);
    buttons->addStretch();
    layout->addLayout(buttons);
    layout->addStretch();

    connect(sendButton, SIGNAL(clicked()), this, SLOT(onSendClicked()));
    return tab;
}

QWidget* PrivacyPage::buildMigrateTab()
{
    QWidget *tab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(tab);

    QLabel *desc = new QLabel(tr(
        "Moves transparent coins into the pool. One transparent address per call, so "
        "a single transaction never publicly groups addresses the chain has not "
        "already grouped, and the whole selected value moves with no transparent "
        "change left behind."));
    desc->setWordWrap(true);
    desc->setStyleSheet("color: #888;");
    layout->addWidget(desc);

    // The way back out is a consensus height, not a build switch, so the state is
    // read from the node rather than asserted here.
    migrateNoticeLabel = new QLabel();
    migrateNoticeLabel->setWordWrap(true);
    migrateNoticeLabel->setStyleSheet("color: #d98c00; font-weight: bold;");
    layout->addWidget(migrateNoticeLabel);

    QGroupBox *group = new QGroupBox(tr("Migrate to the pool"));
    QFormLayout *form = new QFormLayout(group);
    migrateFromEdit = new QLineEdit();
    migrateFromEdit->setPlaceholderText(tr("Transparent address (blank sweeps the largest)"));
    migrateMaxInputsEdit = new QLineEdit();
    migrateMaxInputsEdit->setPlaceholderText(tr("Maximum inputs (blank for the default)"));
    form->addRow(tr("From:"), migrateFromEdit);
    form->addRow(tr("Max inputs:"), migrateMaxInputsEdit);
    migrateButton = new QPushButton(tr("Migrate"));
    migrateButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; "
                                 "padding: 8px 16px; font-weight: bold; }");
    form->addRow(QString(), migrateButton);
    layout->addWidget(group);
    layout->addStretch();

    connect(migrateButton, SIGNAL(clicked()), this, SLOT(onMigrateClicked()));
    return tab;
}

QWidget* PrivacyPage::buildAddressTab()
{
    QWidget *tab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(tab);

    QLabel *desc = new QLabel(tr(
        "IV5 addresses are derived from the wallet's encrypted seed. The wallet "
        "exposes no way to enumerate the addresses it has already issued, so this "
        "list holds only the ones created since the wallet was started; a restart "
        "empties it. The addresses themselves stay valid and are recovered from the "
        "seed, not from this list."));
    desc->setWordWrap(true);
    desc->setStyleSheet("color: #888;");
    layout->addWidget(desc);

    addressList = new QListWidget();
    addressList->setStyleSheet("QListWidget { font-family: monospace; font-size: 11px; }");
    layout->addWidget(addressList, 1);

    QHBoxLayout *buttons = new QHBoxLayout();
    newAddressButton = new QPushButton(tr("New IV5 address"));
    copyAddressButton = new QPushButton(tr("Copy selected"));
    buttons->addWidget(newAddressButton);
    buttons->addWidget(copyAddressButton);
    buttons->addStretch();
    layout->addLayout(buttons);

    connect(newAddressButton, SIGNAL(clicked()), this, SLOT(onNewAddressClicked()));
    connect(copyAddressButton, SIGNAL(clicked()), this, SLOT(onCopyAddressClicked()));
    return tab;
}

void PrivacyPage::setModel(WalletModel *modelIn)
{
    model = modelIn;
    collateralWidget->setModel(modelIn);
    refreshBalances();
}

void PrivacyPage::refreshBalances()
{
    Iv5Rpc::PoolSnapshot pool;
    QString error;
    const bool fHave = Iv5Rpc::FetchPool(pool, error);

    if (!fHave)
    {
        availabilityLabel->setText(tr("The node could not report the pool: %1").arg(error));
        availabilityLabel->setVisible(true);
    }
    else if (!pool.fBoundaryBActive)
    {
        availabilityLabel->setText(tr(
            "Boundary B has not activated at this height. Sending from the pool and "
            "migrating into it will be refused until it does."));
        availabilityLabel->setVisible(true);
    }
    else if (!pool.fTransactionsAccepted)
    {
        availabilityLabel->setText(tr(
            "Boundary B is active, but this node does not accept IV5 transactions "
            "yet. Sending and migrating will be refused."));
        availabilityLabel->setVisible(true);
    }
    else
    {
        availabilityLabel->setVisible(false);
    }

    if (fHave)
    {
        // Unshield is not disabled in the build; it is retired at a height, and on a
        // network with no such height scheduled it still works from the console.
        if (pool.fUnshieldRetired)
            migrateNoticeLabel->setText(tr(
                "There is no way back out. Moving value out of the pool to a "
                "transparent address was retired in consensus at height %1, which "
                "this chain has passed.").arg(pool.nUnshieldRetirementHeight));
        else if (pool.UnshieldRetirementScheduled())
            migrateNoticeLabel->setText(tr(
                "Moving value out of the pool to a transparent address is retired in "
                "consensus at height %1. This wallet offers no way out even before "
                "then, so treat migration as one-way.")
                .arg(pool.nUnshieldRetirementHeight));
        else
            migrateNoticeLabel->setText(tr(
                "No retirement height is set on this network, so consensus would "
                "still accept value leaving the pool. This wallet offers no way out "
                "regardless, so treat migration as one-way."));

        labelPoolBalance->setText(pool.fHaveBalance
                                      ? tr("%1 INN").arg(pool.dBalance, 0, 'f', 8)
                                      : tr("unknown"));
        labelPoolUnconfirmed->setText(tr("%1 INN").arg(pool.dUnconfirmed, 0, 'f', 8));
        labelNoteCount->setText(QString::number(pool.nNoteCount));
        labelSeedState->setText(pool.fSeedUnlocked
                                    ? tr("unlocked")
                                    : tr("locked, or this wallet has none"));
        // -1 is the only value that means nothing went unscanned; anything else is a
        // height whose payloads this wallet has not read, so notes may be missing.
        labelScanGap->setText(pool.nScanGapHeight < 0
                                  ? tr("none")
                                  : tr("from height %1: run z_rescaniv5, notes may be "
                                       "missing").arg(pool.nScanGapHeight));
    }

    if (model && model->getOptionsModel())
    {
        const int unit = model->getOptionsModel()->getDisplayUnit();
        labelTransparentBalance->setText(
            BitcoinUnits::formatWithUnit(unit, model->getBalance()));
    }
}

void PrivacyPage::onSendClicked()
{
    const QString to = sendToEdit->text().trimmed();
    const QString amount = sendAmountEdit->text().trimmed();
    if (to.isEmpty() || amount.isEmpty())
    {
        QMessageBox::warning(this, tr("Send"),
                             tr("Enter a recipient address and an amount."));
        return;
    }

    bool ok = false;
    const double value = amount.toDouble(&ok);
    if (!ok || value <= 0)
    {
        QMessageBox::warning(this, tr("Send"), tr("Enter a positive amount."));
        return;
    }

    const int nMask = maskWidget->mask();
    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Confirm payment"),
        tr("Send %1 INN to %2?\n\n%3")
            .arg(amount)
            .arg(to)
            .arg(maskWidget->confirmationText()),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    if (model == 0)
        return;
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    statusLabel->setText(tr("Building the payment..."));
    QApplication::processEvents();

    QStringList params;
    params << to << amount << QString::number(nMask);
    QString result;
    QString error;
    if (!Iv5Rpc::Call("z_iv5transfer", params, result, error))
    {
        statusLabel->setText(tr("Payment refused"));
        QMessageBox::warning(this, tr("Send"), error);
        return;
    }

    QString txid;
    if (!Iv5Rpc::ReadField(result, "txid", txid))
        txid = tr("(the node did not return a txid)");
    statusLabel->setText(tr("Sent: %1").arg(txid));
    sendAmountEdit->clear();
    refreshBalances();
    QMessageBox::information(this, tr("Send"), result);
}

void PrivacyPage::onMigrateClicked()
{
    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Migrate to the pool"),
        tr("This sweeps one transparent address into the pool. Treat it as one-way: "
           "this wallet offers no way to move value back out.\n\nContinue?"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    if (model == 0)
        return;
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    QStringList params;
    const QString from = migrateFromEdit->text().trimmed();
    const QString maxInputs = migrateMaxInputsEdit->text().trimmed();
    // z_shieldall takes maxinputs second, so a max with no address needs a
    // placeholder the RPC reads as "pick the largest address".
    if (!from.isEmpty() || !maxInputs.isEmpty())
        params << from;
    if (!maxInputs.isEmpty())
        params << maxInputs;

    statusLabel->setText(tr("Migrating..."));
    QApplication::processEvents();

    QString result;
    QString error;
    if (!Iv5Rpc::Call("z_shieldall", params, result, error))
    {
        statusLabel->setText(tr("Migration refused"));
        QMessageBox::warning(this, tr("Migrate to the pool"), error);
        return;
    }

    statusLabel->setText(tr("Migrated"));
    refreshBalances();
    QMessageBox::information(this, tr("Migrate to the pool"), result);
}

void PrivacyPage::onNewAddressClicked()
{
    if (model == 0)
        return;
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    QString result;
    QString error;
    if (!Iv5Rpc::Call("z_getnewiv5address", QStringList(), result, error))
    {
        QMessageBox::warning(this, tr("New IV5 address"), error);
        return;
    }

    QString address;
    if (!Iv5Rpc::ReadField(result, "address", address) || address.isEmpty())
    {
        QMessageBox::warning(this, tr("New IV5 address"),
                             tr("The node returned no address:\n\n%1").arg(result));
        return;
    }

    addressList->addItem(address);
    QApplication::clipboard()->setText(address);
    statusLabel->setText(tr("New IV5 address created and copied to the clipboard"));
}

void PrivacyPage::onCopyAddressClicked()
{
    QListWidgetItem *item = addressList->currentItem();
    if (item == 0)
        return;
    QApplication::clipboard()->setText(item->text());
    statusLabel->setText(tr("Address copied to the clipboard"));
}

void PrivacyPage::onRefreshClicked()
{
    refreshBalances();
    statusLabel->setText(tr("Refreshed"));
}
