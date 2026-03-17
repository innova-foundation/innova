#include "sendcoinsdialog.h"
#include "ui_sendcoinsdialog.h"

#include "init.h"
#include "walletmodel.h"
#include "addresstablemodel.h"
#include "addressbookpage.h"

#include "bitcoinunits.h"
#include "addressbookpage.h"
#include "optionsmodel.h"
#include "sendcoinsentry.h"
#include "guiutil.h"
#include "askpassphrasedialog.h"

#include "coincontrol.h"
#include "coincontroldialog.h"

#include <QMessageBox>
#include <QLocale>
#include <QTextDocument>
#include <QScrollBar>
#include <QClipboard>
#include <QSettings>
#include <QVBoxLayout>
#include <QWidget>
#include <QFrame>
#include <QGridLayout>
#include <QToolButton>
#include <QApplication>
#include <QTabWidget>

SendCoinsDialog::SendCoinsDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SendCoinsDialog),
    model(0)
{
    ui->setupUi(this);

    // === Tab-based send modes ===
    sendTabs = new QTabWidget();
    sendTabs->setDocumentMode(true);

    // Shielded balance label (shown above tabs)
    labelShieldedBal = new QLabel(tr("Shielded: ..."));
    labelShieldedBal->setStyleSheet("color: #4CAF50; font-weight: bold; margin: 4px 0;");
    qobject_cast<QVBoxLayout*>(layout())->insertWidget(0, labelShieldedBal);

    // --- Tab 0: Transparent (uses existing UI from .ui file) ---
    // The existing scrollArea + coin control stays in place as the first tab content
    // We'll reparent it into the tab widget below

    // --- Tab 1: Shield ---
    {
        QWidget *tab = createPrivacyTab(
            tr("Move coins from transparent to shielded pool. Your coins become hidden from the public ledger."),
            false, true, true, false, false, // from=no, to=yes(z-addr), amount=yes, memo=no, dsp=no
            tr("Your z-address (leave empty to auto-select)"), tr("0.00000000"));
        sendTabs->addTab(tab, tr("Shield"));
    }

    // --- Tab 2: Private Send (FCMP++) ---
    {
        QWidget *tab = createPrivacyTab(
            tr("<b>FCMP++ Private Send with Dynamic Selective Privacy.</b> Choose which parts of the transaction to hide."),
            true, true, true, true, true, // from=yes, to=yes, amount=yes, memo=yes, dsp=yes
            tr("Recipient z-address or t-address"), tr("0.00000000"));
        sendTabs->addTab(tab, tr("Private"));
    }

    // --- Tab 3: Unshield ---
    {
        QWidget *tab = createPrivacyTab(
            tr("Move coins from shielded pool back to a transparent address."),
            true, true, true, false, false, // from=yes(z-addr), to=yes(t-addr), amount=yes, memo=no, dsp=no
            tr("Transparent address to receive"), tr("0.00000000"));
        sendTabs->addTab(tab, tr("Unshield"));
    }

    // --- Tab 4: Silent Payment ---
    {
        QWidget *tab = createPrivacyTab(
            tr("<b>BIP-352 Silent Payment.</b> Send to a static public key that generates a unique one-time address."),
            false, true, true, false, false, // from=no, to=yes(sp1...), amount=yes, memo=no, dsp=no
            tr("Silent Payment address (sp1...)"), tr("0.00000000"));
        sendTabs->addTab(tab, tr("Silent Pay"));
    }

    // Reparent the existing transparent send UI into tab 0
    // The .ui file's scrollArea contains the transparent entries
    QWidget *transparentTab = new QWidget();
    QVBoxLayout *tLayout = new QVBoxLayout(transparentTab);
    tLayout->setContentsMargins(0, 0, 0, 0);
    tLayout->addWidget(ui->frameCoinControl);
    tLayout->addWidget(ui->scrollArea);
    sendTabs->insertTab(0, transparentTab, tr("Send"));
    sendTabs->setCurrentIndex(0);

    qobject_cast<QVBoxLayout*>(layout())->insertWidget(1, sendTabs);

    connect(sendTabs, SIGNAL(currentChanged(int)), this, SLOT(onTabChanged(int)));

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->addButton->setIcon(QIcon());
    ui->clearButton->setIcon(QIcon());
    ui->sendButton->setIcon(QIcon());
#endif

#if QT_VERSION >= 0x040700
    /* Do not move this to the XML file, Qt before 4.7 will choke on it */
    ui->lineEditCoinControlChange->setPlaceholderText(tr("Enter a Innova address (e.g. igYcNv4Zp7g4ysSpdFUuzn6VaxvzAZAxsd)"));
#endif

    addEntry();

    connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));

    // UTXO Splitter
    connect(ui->splitBlockCheckBox, SIGNAL(stateChanged(int)), this, SLOT(splitBlockChecked(int)));
    connect(ui->splitBlockLineEdit, SIGNAL(textChanged(const QString &)), this, SLOT(splitBlockLineEditChanged(const QString &)));

    // Coin Control
    ui->lineEditCoinControlChange->setFont(GUIUtil::bitcoinAddressFont());
    connect(ui->pushButtonCoinControl, SIGNAL(clicked()), this, SLOT(coinControlButtonClicked()));
    connect(ui->checkBoxCoinControlChange, SIGNAL(stateChanged(int)), this, SLOT(coinControlChangeChecked(int)));
    connect(ui->lineEditCoinControlChange, SIGNAL(textEdited(const QString &)), this, SLOT(coinControlChangeEdited(const QString &)));

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardPriorityAction = new QAction(tr("Copy priority"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy low output"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardQuantity()));
    connect(clipboardAmountAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardAmount()));
    connect(clipboardFeeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardFee()));
    connect(clipboardAfterFeeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardAfterFee()));
    connect(clipboardBytesAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardBytes()));
    connect(clipboardPriorityAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardPriority()));
    connect(clipboardLowOutputAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardLowOutput()));
    connect(clipboardChangeAction, SIGNAL(triggered()), this, SLOT(coinControlClipboardChange()));
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlPriority->addAction(clipboardPriorityAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    fNewRecipientAllowed = true;
}

void SendCoinsDialog::setModel(WalletModel *model)
{
    this->model = model;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            entry->setModel(model);
        }
    }
    if(model && model->getOptionsModel())
    {
        setBalance(model->getUnlockedBalance(), model->getLockedBalance(), model->getStakeAmount(), model->getUnconfirmedBalance(), model->getImmatureBalance(), model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance());
        connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64)), this, SLOT(setBalance(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64)));
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        // Coin Control
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(coinControlUpdateLabels()));
        connect(model->getOptionsModel(), SIGNAL(coinControlFeaturesChanged(bool)), this, SLOT(coinControlFeatureChanged(bool)));
        connect(model->getOptionsModel(), SIGNAL(transactionFeeChanged(qint64)), this, SLOT(coinControlUpdateLabels()));
        ui->frameCoinControl->setVisible(model->getOptionsModel()->getCoinControlFeatures());
        coinControlUpdateLabels();
    }
}

SendCoinsDialog::~SendCoinsDialog()
{
    delete ui;
}

void SendCoinsDialog::on_sendButton_clicked()
{
    // If a privacy tab is selected, route to the privacy handler
    if (sendTabs->currentIndex() > 0)
    {
        onPrivacySendClicked();
        return;
    }

    QList<SendCoinsRecipient> recipients;
    bool valid = true;

    if(!model)
        return;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        //UTXO splitter - address should be our own
        CBitcoinAddress address = entry->getValue().address.toStdString();
        if(!model->isMine(address) && ui->splitBlockCheckBox->checkState() == Qt::Checked)
        {
            CoinControlDialog::coinControl->fSplitBlock = false;
            ui->splitBlockCheckBox->setCheckState(Qt::Unchecked);
            QMessageBox::warning(this, tr("Send Coins"),
                tr("The split UTXOs tool does not work when sending to outside addresses. Try again!"),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        if(entry)
        {
            if(entry->validate())
            {
                recipients.append(entry->getValue());
            }
            else
            {
                valid = false;
            }
        }
    }

    if(!valid || recipients.isEmpty())
    {
        return;
    }

    //set split block in model
    CoinControlDialog::coinControl->fSplitBlock = ui->splitBlockCheckBox->checkState() == Qt::Checked;

    if (ui->entries->count() > 1 && ui->splitBlockCheckBox->checkState() == Qt::Checked)
    {
        CoinControlDialog::coinControl->fSplitBlock = false;
        ui->splitBlockCheckBox->setCheckState(Qt::Unchecked);
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The split UTXOs tool does not work with multiple addresses. Try again!"),
            QMessageBox::Ok, QMessageBox::Ok);
        return;
    }

    if (CoinControlDialog::coinControl->fSplitBlock)
        CoinControlDialog::coinControl->nSplitBlock = int(ui->splitBlockLineEdit->text().toInt());

    // Format confirmation message
    QStringList formatted;
    QString recipientElement;
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
        formatted.append(tr("<b>%1</b> to %2 (%3)").arg(BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, rcp.amount), Qt::escape(rcp.label), rcp.address));
    }

    fNewRecipientAllowed = false;

    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm send coins"),
                          tr("Are you sure you want to send %1?").arg(formatted.join(tr(" and "))),
          QMessageBox::Yes|QMessageBox::Cancel,
          QMessageBox::Cancel);

    if(retval != QMessageBox::Yes)
    {
        fNewRecipientAllowed = true;
        return;
    }

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        fNewRecipientAllowed = true;
        return;
    }

    if(fSplitBlock)
    {
        recipientElement.append(tr(" split into %1 outputs using the UTXO splitter.").arg(CoinControlDialog::coinControl->nSplitBlock));
    }

    WalletModel::SendCoinsReturn sendstatus;

    if (!model->getOptionsModel() || !model->getOptionsModel()->getCoinControlFeatures())
        sendstatus = model->sendCoins(recipients);
    else
        sendstatus = model->sendCoins(recipients, CoinControlDialog::coinControl);

    switch(sendstatus.status)
    {
    case WalletModel::InvalidAddress:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The recipient address is not valid, please recheck."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::InvalidAmount:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The amount to pay must be larger than 0."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::AmountExceedsBalance:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The amount exceeds your balance."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("The total exceeds your balance when the %1 transaction fee is included.").
            arg(BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, sendstatus.fee)),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::DuplicateAddress:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("Duplicate address found, can only send to each address once per send operation."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::TransactionCreationFailed:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("Error: Transaction creation failed."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::TransactionCommitFailed:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("Error: The transaction was rejected. This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::NarrationTooLong:
        QMessageBox::warning(this, tr("Send Coins"),
            tr("Error: Narration is too long."),
            QMessageBox::Ok, QMessageBox::Ok);
        break;
    case WalletModel::Aborted: // User aborted, nothing to do
        break;
    case WalletModel::OK:
        accept();
        CoinControlDialog::coinControl->UnSelectAll();
        coinControlUpdateLabels();
        break;
    }
    fNewRecipientAllowed = true;
}

void SendCoinsDialog::clear()
{
    // Remove entries until only one left
    while(ui->entries->count())
    {
        delete ui->entries->takeAt(0)->widget();
    }
    addEntry();

    updateRemoveEnabled();

    ui->sendButton->setDefault(true);
}

void SendCoinsDialog::reject()
{
    clear();
}

void SendCoinsDialog::accept()
{
    clear();
}

// UTXO splitter
void SendCoinsDialog::splitBlockChecked(int state)
{
    if (model)
    {
        CoinControlDialog::coinControl->fSplitBlock = (state == Qt::Checked);
        fSplitBlock = (state == Qt::Checked);
        ui->splitBlockLineEdit->setEnabled((state == Qt::Checked));
        ui->labelBlockSizeText->setEnabled((state == Qt::Checked));
        ui->labelBlockSize->setEnabled((state == Qt::Checked));
        coinControlUpdateLabels();
    }
}

//UTXO splitter
void SendCoinsDialog::splitBlockLineEditChanged(const QString & text)
{
    //grab the amount in Coin Control AFter Fee field
    QString qAfterFee = ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" "))
            .replace("~", "").simplified().replace(" ", "");

    //convert to CAmount
    CAmount nAfterFee;
    ParseMoney(qAfterFee.toStdString().c_str(), nAfterFee);

    //if greater than 0 then divide after fee by the amount of blocks
    CAmount nSize = nAfterFee;
    int nBlocks = text.toInt();
    if (nAfterFee && nBlocks)
        nSize = nAfterFee / nBlocks;

    //assign to split block dummy, which is used to recalculate the fee amount more outputs
    CoinControlDialog::nSplitBlockDummy = nBlocks;

    //update labels
    ui->labelBlockSize->setText(QString::fromStdString(FormatMoney(nSize)));
    coinControlUpdateLabels();
}

SendCoinsEntry *SendCoinsDialog::addEntry()
{
    SendCoinsEntry *entry = new SendCoinsEntry(this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, SIGNAL(removeEntry(SendCoinsEntry*)), this, SLOT(removeEntry(SendCoinsEntry*)));
    connect(entry, SIGNAL(payAmountChanged()), this, SLOT(coinControlUpdateLabels()));

    updateRemoveEnabled();

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    QCoreApplication::instance()->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());
    return entry;
}

void SendCoinsDialog::updateRemoveEnabled()
{
    // Remove buttons are enabled as soon as there is more than one send-entry
    bool enabled = (ui->entries->count() > 1);
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            entry->setRemoveEnabled(enabled);
        }
    }
    setupTabChain(0);
    coinControlUpdateLabels();
}

void SendCoinsDialog::removeEntry(SendCoinsEntry* entry)
{
    delete entry;
    updateRemoveEnabled();
}

QWidget *SendCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->addButton);
    QWidget::setTabOrder(ui->addButton, ui->sendButton);
    return ui->sendButton;
}

void SendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    SendCoinsEntry *entry = 0;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
}

bool SendCoinsDialog::handleURI(const QString &uri)
{
    SendCoinsRecipient rv;
    // URI has to be valid
    if (GUIUtil::parseBitcoinURI(uri, &rv))
    {
        CBitcoinAddress address(rv.address.toStdString());
        if (!address.IsValid())
            return false;
        pasteEntry(rv);
        return true;
    }

    return false;
}

void SendCoinsDialog::setBalance(qint64 balance, qint64 lockedbalance, qint64 stake, qint64 unconfirmedBalance, qint64 immatureBalance, qint64 watchBalance, qint64 watchUnconfirmedBalance, qint64 watchImmatureBalance)
{
    Q_UNUSED(stake);
    Q_UNUSED(lockedbalance);
    Q_UNUSED(unconfirmedBalance);
    Q_UNUSED(immatureBalance);
    Q_UNUSED(watchBalance);
    Q_UNUSED(watchUnconfirmedBalance);
    Q_UNUSED(watchImmatureBalance);
    if(!model || !model->getOptionsModel())
        return;

    int unit = model->getOptionsModel()->getDisplayUnit();

    uint64_t bal = balance;

    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, bal));

    // Update shielded balance label
    if (labelShieldedBal)
    {
        qint64 shielded = model->getShieldedBalance();
        labelShieldedBal->setText(tr("Shielded: %1").arg(BitcoinUnits::formatWithUnit(unit, shielded)));
    }
}

void SendCoinsDialog::updateDisplayUnit()
{
    //setBalance(model->getBalance(), 0, 0, 0, 0, 0, 0);
    if(model && model->getOptionsModel())
    {
	uint64_t balance = model->getBalance();

        // Update labelBalance with the current balance and the current unit
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balance));
    }
    coinControlUpdateLabels();
}

// Coin Control: copy label "Quantity" to clipboard
void SendCoinsDialog::coinControlClipboardQuantity()
{
    QApplication::clipboard()->setText(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SendCoinsDialog::coinControlClipboardAmount()
{
    QApplication::clipboard()->setText(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SendCoinsDialog::coinControlClipboardFee()
{
    QApplication::clipboard()->setText(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")));
}

// Coin Control: copy label "After fee" to clipboard
void SendCoinsDialog::coinControlClipboardAfterFee()
{
    QApplication::clipboard()->setText(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")));
}

// Coin Control: copy label "Bytes" to clipboard
void SendCoinsDialog::coinControlClipboardBytes()
{
    QApplication::clipboard()->setText(ui->labelCoinControlBytes->text());
}

// Coin Control: copy label "Priority" to clipboard
void SendCoinsDialog::coinControlClipboardPriority()
{
    QApplication::clipboard()->setText(ui->labelCoinControlPriority->text());
}

// Coin Control: copy label "Low output" to clipboard
void SendCoinsDialog::coinControlClipboardLowOutput()
{
    QApplication::clipboard()->setText(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void SendCoinsDialog::coinControlClipboardChange()
{
    QApplication::clipboard()->setText(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void SendCoinsDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && model) // coin control features disabled
        CoinControlDialog::coinControl->SetNull();
}

// Coin Control: button inputs -> show actual coin control dialog
void SendCoinsDialog::coinControlButtonClicked()
{
    CoinControlDialog dlg;
    dlg.setModel(model);
    dlg.exec();
    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void SendCoinsDialog::coinControlChangeChecked(int state)
{
    if (model)
    {
        if (state == Qt::Checked)
            CoinControlDialog::coinControl->destChange = CBitcoinAddress(ui->lineEditCoinControlChange->text().toStdString()).Get();
        else
            CoinControlDialog::coinControl->destChange = CNoDestination();
    }

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
    ui->labelCoinControlChangeLabel->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void SendCoinsDialog::coinControlChangeEdited(const QString & text)
{
    if (model)
    {
        CoinControlDialog::coinControl->destChange = CBitcoinAddress(text.toStdString()).Get();

        // label for the change address
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");
        if (text.isEmpty())
            ui->labelCoinControlChangeLabel->setText("");
        else if (!CBitcoinAddress(text.toStdString()).IsValid())
        {
            ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");
            ui->labelCoinControlChangeLabel->setText(tr("WARNING: Invalid Innova address"));
        }
        else
        {
            QString associatedLabel = model->getAddressTableModel()->labelForAddress(text);
            if (!associatedLabel.isEmpty())
                ui->labelCoinControlChangeLabel->setText(associatedLabel);
            else
            {
                CPubKey pubkey;
                CKeyID keyid;
                CBitcoinAddress(text.toStdString()).GetKeyID(keyid);
                if (model->getPubKey(keyid, pubkey))
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));
                else
                {
                    ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");
                    ui->labelCoinControlChangeLabel->setText(tr("WARNING: unknown change address"));
                }
            }
        }
    }
}

// Coin Control: update labels
void SendCoinsDialog::coinControlUpdateLabels()
{
    if (!model || !model->getOptionsModel() || !model->getOptionsModel()->getCoinControlFeatures())
        return;

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
            CoinControlDialog::payAmounts.append(entry->getValue().amount);
    }

    if (CoinControlDialog::coinControl->HasSelected())
    {
        // actual coin control calculation
        CoinControlDialog::updateLabels(model, this);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

QWidget* SendCoinsDialog::createPrivacyTab(const QString& desc, bool showFrom, bool showTo,
    bool showAmount, bool showMemo, bool showDSP,
    const QString& toPlaceholder, const QString& amtPlaceholder)
{
    QWidget *tab = new QWidget();
    QVBoxLayout *tabLayout = new QVBoxLayout(tab);

    // Description
    QLabel *descLabel = new QLabel(desc);
    descLabel->setWordWrap(true);
    descLabel->setStyleSheet("color: #888; font-size: 11px; padding: 4px 0 8px 0;");
    descLabel->setTextFormat(Qt::RichText);
    tabLayout->addWidget(descLabel);

    // Form in a styled frame (matches transparent send)
    QFrame *formFrame = new QFrame();
    formFrame->setFrameShape(QFrame::StyledPanel);
    formFrame->setFrameShadow(QFrame::Sunken);
    QGridLayout *grid = new QGridLayout(formFrame);
    grid->setSpacing(12);
    int row = 0;

    QLineEdit *fromEdit = NULL;
    QLineEdit *toEdit = NULL;
    QLineEdit *amountEdit = NULL;
    QLineEdit *memoEdit = NULL;
    QComboBox *dspCombo = NULL;

    if (showFrom)
    {
        QLabel *lbl = new QLabel(tr("From:"));
        lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        fromEdit = new QLineEdit();
        fromEdit->setPlaceholderText(tr("Source address (z-address or * for all)"));
        fromEdit->setFont(GUIUtil::bitcoinAddressFont());
        QToolButton *pasteBtn = new QToolButton();
        pasteBtn->setIcon(QIcon(":/icons/editpaste"));
        pasteBtn->setToolTip(tr("Paste from clipboard"));
        connect(pasteBtn, &QToolButton::clicked, [fromEdit]() {
            fromEdit->setText(QApplication::clipboard()->text());
        });
        QHBoxLayout *r = new QHBoxLayout(); r->setSpacing(0);
        r->addWidget(fromEdit); r->addWidget(pasteBtn);
        grid->addWidget(lbl, row, 0);
        grid->addLayout(r, row, 1);
        row++;
    }

    if (showTo)
    {
        QLabel *lbl = new QLabel(tr("Pay &To:"));
        lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        toEdit = new QLineEdit();
        toEdit->setPlaceholderText(toPlaceholder);
        toEdit->setFont(GUIUtil::bitcoinAddressFont());
        QToolButton *bookBtn = new QToolButton();
        bookBtn->setIcon(QIcon(":/icons/address-book"));
        bookBtn->setToolTip(tr("Choose from address book"));
        QToolButton *pasteBtn = new QToolButton();
        pasteBtn->setIcon(QIcon(":/icons/editpaste"));
        pasteBtn->setToolTip(tr("Paste from clipboard"));
        connect(pasteBtn, &QToolButton::clicked, [toEdit]() {
            toEdit->setText(QApplication::clipboard()->text());
        });
        QHBoxLayout *r = new QHBoxLayout(); r->setSpacing(0);
        r->addWidget(toEdit); r->addWidget(bookBtn); r->addWidget(pasteBtn);
        grid->addWidget(lbl, row, 0);
        grid->addLayout(r, row, 1);
        row++;
    }

    if (showAmount)
    {
        QLabel *lbl = new QLabel(tr("A&mount:"));
        lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        amountEdit = new QLineEdit();
        amountEdit->setPlaceholderText(amtPlaceholder);
        amountEdit->setMaximumWidth(220);
        grid->addWidget(lbl, row, 0);
        grid->addWidget(amountEdit, row, 1);
        row++;
    }

    if (showMemo)
    {
        QLabel *lbl = new QLabel(tr("Memo:"));
        lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        memoEdit = new QLineEdit();
        memoEdit->setPlaceholderText(tr("Optional encrypted memo (max 512 chars)"));
        grid->addWidget(lbl, row, 0);
        grid->addWidget(memoEdit, row, 1);
        row++;
    }

    if (showDSP)
    {
        QLabel *lbl = new QLabel(tr("Privacy Level:"));
        lbl->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        dspCombo = new QComboBox();
        dspCombo->addItem(tr("7 — Full Privacy (hide sender + receiver + amount)"), 7);
        dspCombo->addItem(tr("6 — Hide amount + sender"), 6);
        dspCombo->addItem(tr("5 — Hide amount + receiver"), 5);
        dspCombo->addItem(tr("4 — Hide amount only"), 4);
        dspCombo->addItem(tr("3 — Hide sender + receiver"), 3);
        dspCombo->addItem(tr("2 — Hide sender only"), 2);
        dspCombo->addItem(tr("1 — Hide receiver only"), 1);
        dspCombo->addItem(tr("0 — Transparent (nothing hidden)"), 0);
        grid->addWidget(lbl, row, 0);
        grid->addWidget(dspCombo, row, 1);
        row++;
    }

    tabLayout->addWidget(formFrame);
    tabLayout->addStretch();

    // Store widget pointers for retrieval during send
    tab->setProperty("fromEdit", QVariant::fromValue((void*)fromEdit));
    tab->setProperty("toEdit", QVariant::fromValue((void*)toEdit));
    tab->setProperty("amountEdit", QVariant::fromValue((void*)amountEdit));
    tab->setProperty("memoEdit", QVariant::fromValue((void*)memoEdit));
    tab->setProperty("dspCombo", QVariant::fromValue((void*)dspCombo));

    return tab;
}

void SendCoinsDialog::onTabChanged(int index)
{
    // Update the send button text and style based on tab
    QString btnText;
    QString btnStyle = "";
    switch (index)
    {
    case 0: btnText = tr("&Send"); break;
    case 1: btnText = tr("Shield Coins"); btnStyle = "QPushButton { background-color: #4CAF50; color: white; }"; break;
    case 2: btnText = tr("Send Privately"); btnStyle = "QPushButton { background-color: #2196F3; color: white; }"; break;
    case 3: btnText = tr("Unshield Coins"); btnStyle = "QPushButton { background-color: #FF9800; color: white; }"; break;
    case 4: btnText = tr("Send Silent Payment"); btnStyle = "QPushButton { background-color: #00BCD4; color: white; }"; break;
    default: btnText = tr("&Send"); break;
    }
    ui->sendButton->setText(btnText);
    ui->sendButton->setStyleSheet(btnStyle);
}

void SendCoinsDialog::onPrivacySendClicked()
{
    if (!model)
        return;

    int tabIdx = sendTabs->currentIndex();
    QWidget *tab = sendTabs->currentWidget();

    // Extract field values from tab properties
    QLineEdit *fromEdit = (QLineEdit*)tab->property("fromEdit").value<void*>();
    QLineEdit *toEdit = (QLineEdit*)tab->property("toEdit").value<void*>();
    QLineEdit *amountEdit = (QLineEdit*)tab->property("amountEdit").value<void*>();
    QLineEdit *memoEdit = (QLineEdit*)tab->property("memoEdit").value<void*>();
    QComboBox *dspCombo = (QComboBox*)tab->property("dspCombo").value<void*>();

    QString from = fromEdit ? fromEdit->text().trimmed() : "";
    QString to = toEdit ? toEdit->text().trimmed() : "";
    QString amount = amountEdit ? amountEdit->text().trimmed() : "";
    QString memo = memoEdit ? memoEdit->text().trimmed() : "";
    int privLevel = dspCombo ? dspCombo->currentData().toInt() : 7;

    // Map tab index to mode: 0=transparent, 1=shield, 2=private, 3=unshield, 4=silent
    int mode = tabIdx; // 1=shield, 2=private, 3=unshield, 4=silent(mapped to 5)

    if (amount.isEmpty())
    {
        QMessageBox::warning(this, tr("Privacy Send"), tr("Please enter an amount."));
        return;
    }

    // Build the appropriate RPC command
    QString rpcCmd;
    QString confirmMsg;

    switch (mode)
    {
    case 1: // Shield — directly execute via WalletModel
    {
        confirmMsg = tr("Shield %1 INN to the shielded pool?\n\nA z-address will be created automatically if needed.").arg(amount);

        QMessageBox::StandardButton reply2 = QMessageBox::question(this, tr("Confirm Shield"), confirmMsg, QMessageBox::Yes | QMessageBox::No);
        if (reply2 != QMessageBox::Yes) { fNewRecipientAllowed = true; return; }

        WalletModel::UnlockContext ctx2(model->requestUnlock());
        if (!ctx2.isValid()) { fNewRecipientAllowed = true; return; }

        QString fromAddr = from.isEmpty() ? "*" : from;
        QString resultOut;
        WalletModel::StatusCode status = model->shieldCoins(fromAddr, amount, resultOut);
        if (status == WalletModel::OK)
            QMessageBox::information(this, tr("Shield Coins"), tr("Coins shielded successfully!\n\n%1").arg(resultOut));
        else
            QMessageBox::warning(this, tr("Shield Coins"), tr("Failed:\n\n%1").arg(resultOut));
        fNewRecipientAllowed = true;
        return;
    }
    case 2: // Private Send — directly execute via WalletModel
    {
        if (to.isEmpty()) { QMessageBox::warning(this, tr("Private Send"), tr("Enter a recipient address.")); return; }
        confirmMsg = tr("Send %1 INN privately to %2?\n\nPrivacy Level: %3").arg(amount, to.left(30) + "...").arg(privLevel);

        QMessageBox::StandardButton reply2 = QMessageBox::question(this, tr("Confirm Private Send"), confirmMsg, QMessageBox::Yes | QMessageBox::No);
        if (reply2 != QMessageBox::Yes) { fNewRecipientAllowed = true; return; }

        WalletModel::UnlockContext ctx2(model->requestUnlock());
        if (!ctx2.isValid()) { fNewRecipientAllowed = true; return; }

        QString resultOut;
        WalletModel::StatusCode status = model->sendShielded(from, to, amount, privLevel, resultOut);
        if (status == WalletModel::OK)
            QMessageBox::information(this, tr("Private Send"), tr("Sent successfully!\n\n%1").arg(resultOut));
        else
            QMessageBox::warning(this, tr("Private Send"), tr("Failed:\n\n%1").arg(resultOut));
        fNewRecipientAllowed = true;
        return;
    }
    case 3: // Unshield — directly execute via WalletModel
    {
        if (from.isEmpty() || to.isEmpty()) { QMessageBox::warning(this, tr("Unshield"), tr("Enter both source z-address and destination t-address.")); return; }
        confirmMsg = tr("Unshield %1 INN to %2?").arg(amount, to.left(30) + "...");

        QMessageBox::StandardButton reply2 = QMessageBox::question(this, tr("Confirm Unshield"), confirmMsg, QMessageBox::Yes | QMessageBox::No);
        if (reply2 != QMessageBox::Yes) { fNewRecipientAllowed = true; return; }

        WalletModel::UnlockContext ctx2(model->requestUnlock());
        if (!ctx2.isValid()) { fNewRecipientAllowed = true; return; }

        QString resultOut;
        WalletModel::StatusCode status = model->unshieldCoins(from, to, amount, resultOut);
        if (status == WalletModel::OK)
            QMessageBox::information(this, tr("Unshield"), tr("Unshielded successfully!\n\n%1").arg(resultOut));
        else
            QMessageBox::warning(this, tr("Unshield"), tr("Failed:\n\n%1").arg(resultOut));
        fNewRecipientAllowed = true;
        return;
    }
    case 4: // Silent Payment (tab index 4)
    case 5:
        if (to.isEmpty()) { QMessageBox::warning(this, tr("Silent Payment"), tr("Enter a Silent Payment address.")); return; }
        rpcCmd = QString("sp_send \"%1\" %2").arg(to, amount);
        confirmMsg = tr("Send %1 INN via Silent Payment to %2?").arg(amount, to.left(20) + "...");
        break;
    default:
        return;
    }

    // Confirm
    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Confirm Privacy Transaction"),
        confirmMsg, QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    // Unlock wallet
    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    // For now, show the RPC command to execute
    // TODO: Direct wallet integration when shielded transaction APIs are wired
    QMessageBox::information(this, tr("Privacy Transaction"),
        tr("Execute this command in the Debug Console (Help → Debug Window → Console):\n\n%1\n\n"
           "Direct wallet integration coming in a future update.").arg(rpcCmd));
}
