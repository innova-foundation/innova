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
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollArea>
#include <QTabWidget>
#include <QVBoxLayout>

namespace {

// Each tab holds a tall form, and a QTabWidget will otherwise squeeze its page
// down with the window instead of letting it scroll -- the same treatment the
// staking tabs already get.
QWidget* ScrollableTab(QWidget* content)
{
    QScrollArea* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidget(content);
    return scroll;
}

} // namespace

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
    tabs->addTab(ScrollableTab(buildSendTab()), tr("Send"));
    tabs->addTab(ScrollableTab(buildMigrateTab()), tr("Migrate"));
    tabs->addTab(ScrollableTab(buildAddressTab()), tr("Addresses"));

    collateralWidget = new PrivateCollateralWidget();
    tabs->addTab(ScrollableTab(collateralWidget), tr("Collateralnode"));

    finalityWidget = new FinalityStatusWidget();
    tabs->addTab(ScrollableTab(finalityWidget), tr("Finality"));

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

    // Several payments, each as its own ordinary transfer. Batching them into one
    // transaction would give it more outputs than every other IV5 transaction and
    // so announce both that it is a transfer and how many people it paid.
    QGroupBox *manyGroup = new QGroupBox(tr("Pay several recipients"));
    QVBoxLayout *manyLayout = new QVBoxLayout(manyGroup);
    QLabel *manyHelp = new QLabel(tr(
        "One line per payment, as <address> <amount>. Each is sent as its own "
        "transaction with the mask chosen above, so none of them looks different "
        "from an ordinary payment.\n\n"
        "Each payment needs its own spendable note: a note is spendable once the "
        "epoch it arrived in has closed, so change from one payment cannot fund the "
        "next one in the same epoch."));
    manyHelp->setWordWrap(true);
    manyHelp->setStyleSheet("color: #888;");
    manyLayout->addWidget(manyHelp);
    sendManyEdit = new QPlainTextEdit();
    sendManyEdit->setPlaceholderText(tr("iv5addr...  12.5\niv5addr...  3.0"));
    sendManyEdit->setMaximumHeight(110);
    manyLayout->addWidget(sendManyEdit);
    sendManyButton = new QPushButton(tr("Send all"));
    manyLayout->addWidget(sendManyButton);
    layout->addWidget(manyGroup);
    layout->addStretch();

    connect(sendButton, SIGNAL(clicked()), this, SLOT(onSendClicked()));
    connect(sendManyButton, SIGNAL(clicked()), this, SLOT(onSendManyClicked()));
    return tab;
}

QWidget* PrivacyPage::buildMigrateTab()
{
    QWidget *tab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(tab);

    QLabel *desc = new QLabel(tr(
        "Migration is one-way and it is required. Transparent coins have to move into "
        "the pool to stay spendable; this wallet offers no way to move value back out, "
        "and there is no plan to add one.\n\n"
        "Each address is swept by its own transaction, so migrating never publicly "
        "groups addresses the chain has not already grouped, and the whole value of an "
        "address moves with no transparent change left behind."));
    desc->setWordWrap(true);
    desc->setStyleSheet("color: #888;");
    layout->addWidget(desc);

    QGroupBox *modeGroup = new QGroupBox(tr("Mode"));
    QVBoxLayout *modeLayout = new QVBoxLayout(modeGroup);
    migrateSimpleRadio = new QRadioButton(tr("Simple -- migrate everything"));
    migrateSimpleRadio->setToolTip(tr(
        "Sweeps every transparent address into the pool, one transaction each, until "
        "nothing transparent is left."));
    migrateAdvancedRadio = new QRadioButton(tr("Advanced -- choose an address"));
    migrateAdvancedRadio->setToolTip(tr(
        "Sweep one address at a time and cap how many outputs each transaction spends."));
    migrateSimpleRadio->setChecked(true);
    modeLayout->addWidget(migrateSimpleRadio);
    modeLayout->addWidget(migrateAdvancedRadio);
    layout->addWidget(modeGroup);
    connect(migrateSimpleRadio, SIGNAL(toggled(bool)), this, SLOT(onMigrateModeChanged()));

    // The way back out is a consensus height, not a build switch, so the state is
    // read from the node rather than asserted here.
    migrateNoticeLabel = new QLabel();
    migrateNoticeLabel->setWordWrap(true);
    migrateNoticeLabel->setStyleSheet("color: #d98c00; font-weight: bold;");
    layout->addWidget(migrateNoticeLabel);

    QGroupBox *simpleGroup = new QGroupBox(tr("Migrate everything"));
    QVBoxLayout *simpleLayout = new QVBoxLayout(simpleGroup);
    migrateAllSummary = new QLabel(tr("Reads the transparent balance when you start."));
    migrateAllSummary->setWordWrap(true);
    migrateAllSummary->setStyleSheet("color: #888;");
    simpleLayout->addWidget(migrateAllSummary);
    migrateAllButton = new QPushButton(tr("Migrate all transparent coins"));
    migrateAllButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; "
                                    "padding: 8px 16px; font-weight: bold; }");
    simpleLayout->addWidget(migrateAllButton);
    layout->addWidget(simpleGroup);
    connect(migrateAllButton, SIGNAL(clicked()), this, SLOT(onMigrateAllClicked()));

    migrateAdvancedBox = new QWidget();
    QVBoxLayout *advancedOuter = new QVBoxLayout(migrateAdvancedBox);
    advancedOuter->setContentsMargins(0, 0, 0, 0);
    QGroupBox *group = new QGroupBox(tr("Migrate one address"));
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
    advancedOuter->addWidget(group);
    layout->addWidget(migrateAdvancedBox);
    layout->addStretch();

    connect(migrateButton, SIGNAL(clicked()), this, SLOT(onMigrateClicked()));
    onMigrateModeChanged();
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

void PrivacyPage::onSendManyClicked()
{
    if (model == 0)
        return;

    // Parse first: nothing is sent until every line is understood, so a typo on
    // line 4 cannot leave three payments already broadcast.
    const QStringList lines = sendManyEdit->toPlainText().split(QChar('\n'),
                                                                Qt::SkipEmptyParts);
    QStringList vAddresses;
    QStringList vAmounts;
    for (int i = 0; i < lines.size(); ++i)
    {
        const QString line = lines.at(i).trimmed();
        if (line.isEmpty())
            continue;
        const QStringList parts = line.split(QRegExp("\\s+"), Qt::SkipEmptyParts);
        if (parts.size() != 2)
        {
            QMessageBox::warning(this, tr("Pay several recipients"),
                tr("Line %1 is not '<address> <amount>':\n%2").arg(i + 1).arg(line));
            return;
        }
        bool fOk = false;
        const double dAmount = parts.at(1).toDouble(&fOk);
        if (!fOk || dAmount <= 0.0)
        {
            QMessageBox::warning(this, tr("Pay several recipients"),
                tr("Line %1 has no usable amount: %2").arg(i + 1).arg(parts.at(1)));
            return;
        }
        vAddresses << parts.at(0);
        vAmounts << parts.at(1);
    }
    if (vAddresses.isEmpty())
    {
        QMessageBox::information(this, tr("Pay several recipients"),
                                 tr("Nothing to send."));
        return;
    }

    // Each payment needs its own already-anchored note, so say up front how many
    // are available rather than letting the run stop halfway.
    Iv5Rpc::PoolSnapshot pool;
    QString poolError;
    if (Iv5Rpc::FetchPool(pool, poolError) && pool.nNoteCount >= 0 &&
        pool.nNoteCount < vAddresses.size())
    {
        const QMessageBox::StandardButton go = QMessageBox::question(
            this, tr("Pay several recipients"),
            tr("You asked for %1 payments but hold %2 note(s). A payment needs its "
               "own spendable note, and change from one cannot fund the next until "
               "its epoch closes, so the run is likely to stop early.\n\n"
               "Send anyway?").arg(vAddresses.size()).arg(pool.nNoteCount),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (go != QMessageBox::Yes)
            return;
    }

    const int nMask = maskWidget ? maskWidget->mask() : -1;
    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Pay several recipients"),
        tr("Send %1 separate payments, each with the mask chosen above?\n\n"
           "They go out one at a time rather than together, because a burst of "
           "payments from one wallet is linkable by timing even though each "
           "transaction on its own is not.").arg(vAddresses.size()),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    sendManyButton->setEnabled(false);
    sendButton->setEnabled(false);

    int nSent = 0;
    QString error;
    QStringList vTxids;
    for (int i = 0; i < vAddresses.size(); ++i)
    {
        statusLabel->setText(tr("Sending payment %1 of %2...")
                                 .arg(i + 1).arg(vAddresses.size()));
        QApplication::processEvents();

        QStringList params;
        params << vAddresses.at(i) << vAmounts.at(i);
        if (nMask >= 0)
            params << QString::number(nMask);

        QString result;
        if (!Iv5Rpc::Call("z_iv5transfer", params, result, error))
        {
            error = tr("payment %1 to %2 was refused: %3")
                        .arg(i + 1).arg(vAddresses.at(i)).arg(error);
            break;
        }
        QString txid;
        if (Iv5Rpc::ReadField(result, "txid", txid))
            vTxids << txid.left(16);
        ++nSent;
    }

    sendManyButton->setEnabled(true);
    sendButton->setEnabled(true);
    refreshBalances();

    if (error.isEmpty())
    {
        statusLabel->setText(tr("Sent"));
        sendManyEdit->clear();
        QMessageBox::information(this, tr("Pay several recipients"),
            tr("Sent %1 payment(s).\n\n%2").arg(nSent).arg(vTxids.join("\n")));
    }
    else
    {
        statusLabel->setText(tr("Stopped after %1").arg(nSent));
        QMessageBox::warning(this, tr("Pay several recipients"),
            tr("Sent %1 of %2, then stopped.\n\n%3\n\n%4")
                .arg(nSent).arg(vAddresses.size()).arg(error).arg(vTxids.join("\n")));
    }
}

void PrivacyPage::onMigrateModeChanged()
{
    const bool fSimple = migrateSimpleRadio && migrateSimpleRadio->isChecked();
    if (migrateAdvancedBox)
        migrateAdvancedBox->setVisible(!fSimple);
}

void PrivacyPage::onMigrateAllClicked()
{
    if (model == 0)
        return;

    const qint64 nStart = model->getBalance();
    if (nStart <= 0)
    {
        QMessageBox::information(this, tr("Migrate everything"),
            tr("There is no transparent balance left to migrate."));
        return;
    }

    const int unit = model->getOptionsModel()
                         ? model->getOptionsModel()->getDisplayUnit()
                         : 0;
    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Migrate everything"),
        tr("This moves %1 into the pool, sweeping each transparent address with its own "
           "transaction so the chain is never told which addresses share an owner.\n\n"
           "Migration is one-way and required: this wallet offers no way to move value "
           "back out.\n\n"
           "It runs the sweeps back to back. That publishes this wallet's whole "
           "transparent address set inside a short window, so someone watching the "
           "network can still infer that the addresses belong together. Migrating a few "
           "addresses at a time, spread out, gives that away less.\n\nContinue?")
            .arg(BitcoinUnits::formatWithUnit(unit, nStart)),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    // z_migratetopool sweeps one address per transaction and skips addresses below the
    // fee; its bound is per call, so keep calling while it reports more work.
    migrateAllButton->setEnabled(false);
    migrateSimpleRadio->setEnabled(false);
    migrateAdvancedRadio->setEnabled(false);

    const int nMaxCalls = 100;
    double dShielded = 0.0;
    int nSent = 0;
    bool fComplete = false;
    QString error;

    for (int nCall = 0; nCall < nMaxCalls; ++nCall)
    {
        statusLabel->setText(tr("Migrating, %1 sent so far...").arg(nSent));
        QApplication::processEvents();

        QString result;
        if (!Iv5Rpc::Call("z_migratetopool", QStringList(), result, error))
            break;

        QString field;
        if (Iv5Rpc::ReadField(result, "shielded", field))
            dShielded += field.toDouble();
        if (Iv5Rpc::ReadField(result, "sent", field))
            nSent += field.toInt();
        if (Iv5Rpc::ReadField(result, "complete", field) && field == "true")
            fComplete = true;

        migrateAllSummary->setText(tr("Sent %1 transaction(s), %2 moved.")
                                       .arg(nSent).arg(dShielded, 0, 'f', 8));

        QString more;
        if (!Iv5Rpc::ReadField(result, "more", more) || more != "true")
            break;
    }

    migrateAllButton->setEnabled(true);
    migrateSimpleRadio->setEnabled(true);
    migrateAdvancedRadio->setEnabled(true);
    refreshBalances();

    const QString moved = tr("Moved %1 into the pool across %2 transaction(s).")
                              .arg(dShielded, 0, 'f', 8).arg(nSent);
    migrateAllSummary->setText(moved);

    if (!error.isEmpty())
    {
        statusLabel->setText(nSent > 0 ? tr("Migration stopped") : tr("Migration refused"));
        QMessageBox::warning(this, tr("Migrate everything"),
                             tr("%1\n\nThen it stopped: %2").arg(moved).arg(error));
        return;
    }

    statusLabel->setText(fComplete ? tr("Migrated") : tr("Migration incomplete"));
    if (fComplete)
    {
        QMessageBox::information(this, tr("Migrate everything"),
            tr("%1\n\nNothing transparent is left.").arg(moved));
    }
    else
    {
        QMessageBox::information(this, tr("Migrate everything"),
            tr("%1\n\nSome value could not be moved. An address whose value does not "
               "cover the shield fee cannot be swept at all; run 'z_migratetopool' in "
               "the debug console to see which addresses were skipped and why.")
                .arg(moved));
    }
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
