#include "privacypage.h"
#include "walletmodel.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "guiconstants.h"

#include <QMessageBox>
#include <QApplication>
#include <QClipboard>
#include <limits>

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

    // Title
    QLabel *titleLabel = new QLabel(tr("Privacy Dashboard"));
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;");
    mainLayout->addWidget(titleLabel);

    QLabel *descLabel = new QLabel(tr("Manage your shielded (private) funds. Shield coins to hide them from the public ledger, "
                                      "send privately between shielded addresses, or unshield to make them transparent again."));
    descLabel->setWordWrap(true);
    descLabel->setStyleSheet("color: #888; margin-bottom: 15px;");
    mainLayout->addWidget(descLabel);

    // Balance section
    QGroupBox *balanceGroup = new QGroupBox(tr("Privacy Balances"));
    QFormLayout *balanceLayout = new QFormLayout(balanceGroup);
    labelTransparentBalance = new QLabel("0.00 INN");
    labelTransparentBalance->setStyleSheet("font-weight: bold;");
    labelShieldedBalance = new QLabel("0.00 INN");
    labelShieldedBalance->setStyleSheet("font-weight: bold; color: #4CAF50;");
    labelTotalPrivateBalance = new QLabel("0.00 INN");
    labelTotalPrivateBalance->setStyleSheet("font-weight: bold;");
    balanceLayout->addRow(tr("Transparent (public):"), labelTransparentBalance);
    balanceLayout->addRow(tr("Shielded (private):"), labelShieldedBalance);
    balanceLayout->addRow(tr("Total:"), labelTotalPrivateBalance);
    mainLayout->addWidget(balanceGroup);

    // Tab widget for operations
    QTabWidget *tabs = new QTabWidget();

    // === Tab 1: Shield / Unshield ===
    QWidget *shieldTab = new QWidget();
    QVBoxLayout *shieldLayout = new QVBoxLayout(shieldTab);

    // Shield section
    QGroupBox *shieldGroup = new QGroupBox(tr("Shield Coins (Transparent -> Private)"));
    QFormLayout *shieldForm = new QFormLayout(shieldGroup);
    shieldAmountEdit = new QLineEdit();
    shieldAmountEdit->setPlaceholderText(tr("Amount to shield (or * for all)"));
    shieldTargetCombo = new QComboBox();
    shieldButton = new QPushButton(tr("Shield Coins"));
    shieldButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 8px 16px; font-weight: bold; }");
    shieldForm->addRow(tr("Amount:"), shieldAmountEdit);
    shieldForm->addRow(tr("To z-address:"), shieldTargetCombo);
    shieldForm->addRow("", shieldButton);
    shieldLayout->addWidget(shieldGroup);

    // Unshield section
    QGroupBox *unshieldGroup = new QGroupBox(tr("Unshield Coins (Private -> Transparent)"));
    QFormLayout *unshieldForm = new QFormLayout(unshieldGroup);
    unshieldAmountEdit = new QLineEdit();
    unshieldAmountEdit->setPlaceholderText(tr("Amount to unshield"));
    unshieldToEdit = new QLineEdit();
    unshieldToEdit->setPlaceholderText(tr("Transparent address to receive coins"));
    unshieldButton = new QPushButton(tr("Unshield Coins"));
    unshieldButton->setStyleSheet("QPushButton { background-color: #FF9800; color: white; padding: 8px 16px; font-weight: bold; }");
    unshieldForm->addRow(tr("Amount:"), unshieldAmountEdit);
    unshieldForm->addRow(tr("To address:"), unshieldToEdit);
    unshieldForm->addRow("", unshieldButton);
    shieldLayout->addWidget(unshieldGroup);
    shieldLayout->addStretch();

    tabs->addTab(shieldTab, tr("Shield / Unshield"));

    // === Tab 2: Send Shielded ===
    QWidget *sendTab = new QWidget();
    QVBoxLayout *sendLayout = new QVBoxLayout(sendTab);

    QGroupBox *sendGroup = new QGroupBox(tr("Send Privately (z-address -> z-address)"));
    QFormLayout *sendForm = new QFormLayout(sendGroup);
    sendFromEdit = new QLineEdit();
    sendFromEdit->setPlaceholderText(tr("Your z-address (leave empty for default)"));
    sendToEdit = new QLineEdit();
    sendToEdit->setPlaceholderText(tr("Recipient z-address or transparent address"));
    sendAmountEdit = new QLineEdit();
    sendAmountEdit->setPlaceholderText(tr("Amount to send"));
    sendMemoEdit = new QLineEdit();
    sendMemoEdit->setPlaceholderText(tr("Optional encrypted memo (max 512 chars)"));
    sendShieldedButton = new QPushButton(tr("Send Privately"));
    sendShieldedButton->setStyleSheet("QPushButton { background-color: #2196F3; color: white; padding: 8px 16px; font-weight: bold; }");
    sendForm->addRow(tr("From:"), sendFromEdit);
    sendForm->addRow(tr("To:"), sendToEdit);
    sendForm->addRow(tr("Amount:"), sendAmountEdit);
    sendForm->addRow(tr("Memo:"), sendMemoEdit);
    sendForm->addRow("", sendShieldedButton);
    sendLayout->addWidget(sendGroup);
    sendLayout->addStretch();

    tabs->addTab(sendTab, tr("Send Private"));

    // === Tab 3: Shielded Addresses ===
    QWidget *addrTab = new QWidget();
    QVBoxLayout *addrLayout = new QVBoxLayout(addrTab);

    QLabel *addrDesc = new QLabel(tr("Your shielded (z-) addresses. Share these to receive private payments."));
    addrDesc->setWordWrap(true);
    addrLayout->addWidget(addrDesc);

    zAddressList = new QListWidget();
    zAddressList->setStyleSheet("QListWidget { font-family: monospace; }");
    addrLayout->addWidget(zAddressList);

    QHBoxLayout *addrButtons = new QHBoxLayout();
    newZAddressButton = new QPushButton(tr("New z-Address"));
    newZAddressButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 6px 12px; }");
    copyAddressButton = new QPushButton(tr("Copy Selected"));
    refreshButton = new QPushButton(tr("Refresh"));
    addrButtons->addWidget(newZAddressButton);
    addrButtons->addWidget(copyAddressButton);
    addrButtons->addWidget(refreshButton);
    addrButtons->addStretch();
    addrLayout->addLayout(addrButtons);

    tabs->addTab(addrTab, tr("Shielded Addresses"));

    // === Tab 4: Silent Payment Addresses ===
    QWidget *spTab = new QWidget();
    QVBoxLayout *spLayout = new QVBoxLayout(spTab);

    QLabel *spDesc = new QLabel(tr("Silent Payment addresses provide stealth receiving. Each sender derives a unique "
                                    "one-time address from your SP address, so no two payments share an on-chain address. "
                                    "Share your SP address publicly — receivers cannot be linked on the blockchain."));
    spDesc->setWordWrap(true);
    spLayout->addWidget(spDesc);

    spAddressList = new QListWidget();
    spAddressList->setStyleSheet("QListWidget { font-family: monospace; font-size: 11px; }");
    spLayout->addWidget(spAddressList);

    QHBoxLayout *spButtons = new QHBoxLayout();
    newSPAddressButton = new QPushButton(tr("New SP Address"));
    newSPAddressButton->setStyleSheet("QPushButton { background-color: #9C27B0; color: white; padding: 6px 12px; font-weight: bold; }");
    copySPAddressButton = new QPushButton(tr("Copy Selected"));
    spButtons->addWidget(newSPAddressButton);
    spButtons->addWidget(copySPAddressButton);
    spButtons->addStretch();
    spLayout->addLayout(spButtons);

    tabs->addTab(spTab, tr("Silent Payment Addresses"));

    mainLayout->addWidget(tabs);

    // Status bar
    statusLabel = new QLabel(tr("Ready"));
    statusLabel->setStyleSheet("color: #888; margin-top: 10px;");
    mainLayout->addWidget(statusLabel);

    // Connect signals
    connect(shieldButton, SIGNAL(clicked()), this, SLOT(onShieldClicked()));
    connect(unshieldButton, SIGNAL(clicked()), this, SLOT(onUnshieldClicked()));
    connect(sendShieldedButton, SIGNAL(clicked()), this, SLOT(onSendShieldedClicked()));
    connect(newZAddressButton, SIGNAL(clicked()), this, SLOT(onNewZAddressClicked()));
    connect(copyAddressButton, SIGNAL(clicked()), this, SLOT(onCopyAddressClicked()));
    connect(refreshButton, SIGNAL(clicked()), this, SLOT(onRefreshClicked()));
    connect(newSPAddressButton, SIGNAL(clicked()), this, SLOT(onNewSPAddressClicked()));
    connect(copySPAddressButton, SIGNAL(clicked()), this, SLOT(onCopySPAddressClicked()));
}

void PrivacyPage::setModel(WalletModel *model)
{
    this->model = model;
    if (model)
    {
        refreshBalances();
        refreshAddresses();
        refreshSPAddresses();
    }
}

void PrivacyPage::refreshBalances()
{
    if (!model || !model->getOptionsModel())
        return;

    int unit = model->getOptionsModel()->getDisplayUnit();
    qint64 transparent = model->getBalance();
    qint64 shielded = model->getShieldedBalance();

    labelTransparentBalance->setText(BitcoinUnits::formatWithUnit(unit, transparent));
    labelShieldedBalance->setText(BitcoinUnits::formatWithUnit(unit, shielded));

    // Overflow-safe addition
    qint64 total = transparent;
    if (shielded > 0 && total > std::numeric_limits<qint64>::max() - shielded)
        total = std::numeric_limits<qint64>::max();
    else
        total += shielded;
    labelTotalPrivateBalance->setText(BitcoinUnits::formatWithUnit(unit, total));

    // Populate shield target combo with z-addresses
    QString currentTarget = shieldTargetCombo->currentText();
    shieldTargetCombo->clear();
    QStringList zAddrs = model->getShieldedAddresses();
    if (zAddrs.isEmpty())
    {
        shieldTargetCombo->addItem(tr("(Generate a z-address first)"));
    }
    else
    {
        for (const QString& addr : zAddrs)
            shieldTargetCombo->addItem(addr);
    }
    // Restore selection
    int idx = shieldTargetCombo->findText(currentTarget);
    if (idx >= 0) shieldTargetCombo->setCurrentIndex(idx);
}

void PrivacyPage::refreshAddresses()
{
    if (!model)
        return;

    zAddressList->clear();
    QStringList addrs = model->getShieldedAddresses();
    for (const QString& addr : addrs)
        zAddressList->addItem(addr);

    if (addrs.isEmpty())
        zAddressList->addItem(tr("No shielded addresses yet. Click 'New z-Address' to create one."));
}

void PrivacyPage::refreshSPAddresses()
{
    if (!model)
        return;

    spAddressList->clear();
    QStringList addrs = model->getSilentPaymentAddresses();
    for (const QString& addr : addrs)
        spAddressList->addItem(addr);

    if (addrs.isEmpty())
        spAddressList->addItem(tr("No silent payment addresses yet. Click 'New SP Address' to create one."));
}

void PrivacyPage::onNewZAddressClicked()
{
    if (!model)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    QString newAddr = model->getNewShieldedAddress();
    if (newAddr.isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("Failed to generate shielded address."));
        return;
    }

    statusLabel->setText(tr("New z-address created: %1").arg(newAddr.left(20) + "..."));
    refreshAddresses();
    refreshBalances();

    // Copy to clipboard
    QApplication::clipboard()->setText(newAddr);
    QMessageBox::information(this, tr("New Shielded Address"),
        tr("Your new shielded address has been created and copied to clipboard:\n\n%1").arg(newAddr));
}

void PrivacyPage::onNewSPAddressClicked()
{
    if (!model)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    QString newAddr = model->getNewSilentPaymentAddress();
    if (newAddr.isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("Failed to generate silent payment address. Check that your wallet is unlocked."));
        return;
    }

    statusLabel->setText(tr("New SP address created"));
    refreshSPAddresses();

    // Copy to clipboard
    QApplication::clipboard()->setText(newAddr);
    QMessageBox::information(this, tr("New Silent Payment Address"),
        tr("Your new silent payment address has been created and copied to clipboard:\n\n%1\n\n"
           "Share this address publicly. Each sender will derive a unique one-time address, "
           "so payments cannot be linked on the blockchain.").arg(newAddr));
}

void PrivacyPage::onCopyAddressClicked()
{
    QListWidgetItem *item = zAddressList->currentItem();
    if (item && !item->text().startsWith("No shielded"))
    {
        QApplication::clipboard()->setText(item->text());
        statusLabel->setText(tr("Address copied to clipboard"));
    }
}

void PrivacyPage::onCopySPAddressClicked()
{
    QListWidgetItem *item = spAddressList->currentItem();
    if (item && !item->text().startsWith("No silent"))
    {
        QApplication::clipboard()->setText(item->text());
        statusLabel->setText(tr("SP address copied to clipboard"));
    }
}

void PrivacyPage::onRefreshClicked()
{
    refreshBalances();
    refreshAddresses();
    refreshSPAddresses();
    statusLabel->setText(tr("Refreshed"));
}

void PrivacyPage::onShieldClicked()
{
    if (!model)
        return;

    QString targetAddr = shieldTargetCombo->currentText();
    if (targetAddr.isEmpty() || targetAddr.startsWith("("))
    {
        QMessageBox::warning(this, tr("Shield Coins"), tr("Please generate a z-address first."));
        return;
    }

    QString amountStr = shieldAmountEdit->text().trimmed();
    if (amountStr.isEmpty())
    {
        QMessageBox::warning(this, tr("Shield Coins"), tr("Please enter an amount to shield."));
        return;
    }

    // Validate amount
    if (amountStr != "*")
    {
        bool ok;
        double amt = amountStr.toDouble(&ok);
        if (!ok || amt <= 0)
        {
            QMessageBox::warning(this, tr("Shield Coins"), tr("Please enter a valid positive amount."));
            return;
        }
    }

    // Confirmation
    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Confirm Shield"),
        tr("Shield %1 INN to your private address?\n\nTo: %2").arg(amountStr, targetAddr.left(30) + "..."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    statusLabel->setText(tr("Shielding coins..."));
    QApplication::processEvents();

    QString result;
    WalletModel::StatusCode status = model->shieldCoins("*", amountStr, result);
    if (status == WalletModel::OK)
    {
        statusLabel->setText(tr("Shield transaction sent successfully"));
        shieldAmountEdit->clear();
        refreshBalances();
        QMessageBox::information(this, tr("Shield Coins"),
            tr("Coins are being shielded. The transaction has been broadcast.\n\n%1").arg(result));
    }
    else
    {
        statusLabel->setText(tr("Shield failed"));
        QMessageBox::warning(this, tr("Shield Coins"),
            tr("Failed to shield coins:\n\n%1").arg(result));
    }
}

void PrivacyPage::onUnshieldClicked()
{
    if (!model)
        return;

    QString toAddr = unshieldToEdit->text().trimmed();
    QString amountStr = unshieldAmountEdit->text().trimmed();

    if (toAddr.isEmpty() || amountStr.isEmpty())
    {
        QMessageBox::warning(this, tr("Unshield Coins"), tr("Please enter both a destination address and amount."));
        return;
    }

    // Validate amount
    bool amtOk;
    double amt = amountStr.toDouble(&amtOk);
    if (!amtOk || amt <= 0)
    {
        QMessageBox::warning(this, tr("Unshield Coins"), tr("Please enter a valid positive amount."));
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Confirm Unshield"),
        tr("Unshield %1 INN to transparent address?\n\nTo: %2").arg(amountStr, toAddr),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    statusLabel->setText(tr("Unshielding coins..."));
    QApplication::processEvents();

    // Use the first z-address as source
    QStringList zAddrs = model->getShieldedAddresses();
    if (zAddrs.isEmpty())
    {
        QMessageBox::warning(this, tr("Unshield Coins"), tr("No shielded addresses found. Cannot unshield."));
        return;
    }

    QString result;
    WalletModel::StatusCode status = model->unshieldCoins(zAddrs.first(), toAddr, amountStr, result);
    if (status == WalletModel::OK)
    {
        statusLabel->setText(tr("Unshield transaction sent successfully"));
        unshieldAmountEdit->clear();
        unshieldToEdit->clear();
        refreshBalances();
        QMessageBox::information(this, tr("Unshield Coins"),
            tr("Coins are being unshielded. The transaction has been broadcast.\n\n%1").arg(result));
    }
    else
    {
        statusLabel->setText(tr("Unshield failed"));
        QMessageBox::warning(this, tr("Unshield Coins"),
            tr("Failed to unshield coins:\n\n%1").arg(result));
    }
}

void PrivacyPage::onSendShieldedClicked()
{
    if (!model)
        return;

    QString toAddr = sendToEdit->text().trimmed();
    QString amountStr = sendAmountEdit->text().trimmed();

    if (toAddr.isEmpty() || amountStr.isEmpty())
    {
        QMessageBox::warning(this, tr("Send Private"), tr("Please enter a recipient address and amount."));
        return;
    }

    // Validate amount
    bool amtOk;
    double amt = amountStr.toDouble(&amtOk);
    if (!amtOk || amt <= 0)
    {
        QMessageBox::warning(this, tr("Send Private"), tr("Please enter a valid positive amount."));
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Confirm Private Send"),
        tr("Send %1 INN privately?\n\nTo: %2").arg(amountStr, toAddr.left(40) + "..."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    statusLabel->setText(tr("Sending privately..."));
    QApplication::processEvents();

    // Use specified from address or first z-address
    QString fromAddr = sendFromEdit->text().trimmed();
    if (fromAddr.isEmpty())
    {
        QStringList zAddrs = model->getShieldedAddresses();
        if (!zAddrs.isEmpty())
            fromAddr = zAddrs.first();
    }

    if (fromAddr.isEmpty())
    {
        QMessageBox::warning(this, tr("Send Private"), tr("No shielded address available to send from. Create a z-address first."));
        return;
    }

    QString result;
    WalletModel::StatusCode status = model->sendShielded(fromAddr, toAddr, amountStr, 0, result);
    if (status == WalletModel::OK)
    {
        statusLabel->setText(tr("Private send transaction broadcast"));
        sendAmountEdit->clear();
        sendToEdit->clear();
        sendMemoEdit->clear();
        refreshBalances();
        QMessageBox::information(this, tr("Send Private"),
            tr("Private transaction sent successfully.\n\n%1").arg(result));
    }
    else
    {
        statusLabel->setText(tr("Private send failed"));
        QMessageBox::warning(this, tr("Send Private"),
            tr("Failed to send privately:\n\n%1").arg(result));
    }
}
