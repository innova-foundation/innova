#include "stakingpage.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "bitcoinunits.h"
#include "base58.h"
#include "main.h"
#include "wallet.h"
#include "init.h"

#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QLineEdit>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QTimer>
#include <QMessageBox>
#include <QFont>
#include <QScrollArea>
#include <QTabWidget>
#include <QFrame>
#include <QGridLayout>

StakingPage::StakingPage(QWidget *parent) :
    QWidget(parent),
    model(0),
    updateTimer(0)
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // Status section (always visible)
    QGroupBox *statusGroup = new QGroupBox(tr("Staking Status"));
    QVBoxLayout *statusLayout = new QVBoxLayout(statusGroup);

    labelStakingMode = new QLabel(tr("Mode: Transparent"));
    QFont boldFont = labelStakingMode->font();
    boldFont.setBold(true);
    labelStakingMode->setFont(boldFont);
    statusLayout->addWidget(labelStakingMode);

    labelStakingStatus = new QLabel(tr("Status: Checking..."));
    statusLayout->addWidget(labelStakingStatus);

    labelStakingBalance = new QLabel(tr("Staking Balance: 0.00 INN"));
    statusLayout->addWidget(labelStakingBalance);

    labelEstimatedTime = new QLabel(tr("Estimated Time to Stake: N/A"));
    statusLayout->addWidget(labelEstimatedTime);

    mainLayout->addWidget(statusGroup);

    // Tab-based staking modes (replaces dropdown + stacked widget)
    stakingTabs = new QTabWidget();
    stakingTabs->setDocumentMode(true);

    setupTransparentPanel();
    setupNullStakePanel();
    setupColdStakingPanel();
    setupNullStakeColdPanel();

    stakingTabs->addTab(transparentPanel, tr("Transparent"));
    stakingTabs->addTab(nullstakePanel, tr("NullStake"));
    stakingTabs->addTab(coldStakingPanel, tr("Cold Staking"));
    stakingTabs->addTab(nullstakeColdPanel, tr("Private Cold Stake"));

    mainLayout->addWidget(stakingTabs);

    connect(stakingTabs, SIGNAL(currentChanged(int)), this, SLOT(onStakingModeChanged(int)));

    updateTimer = new QTimer(this);
    connect(updateTimer, SIGNAL(timeout()), this, SLOT(updateStakingStatus()));
    updateTimer->start(10000); // 10 second refresh
}

StakingPage::~StakingPage()
{
    if (updateTimer)
    {
        updateTimer->stop();
        updateTimer = 0;
    }
}

void StakingPage::setupTransparentPanel()
{
    transparentPanel = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(transparentPanel);

    QGroupBox *group = new QGroupBox(tr("Transparent Staking"));
    QVBoxLayout *groupLayout = new QVBoxLayout(group);

    QLabel *infoLabel = new QLabel(tr(
        "Transparent staking uses your regular (non-shielded) coins to stake. "
        "This is the standard Proof-of-Stake mechanism. Your coins remain visible "
        "on the blockchain while staking."));
    infoLabel->setWordWrap(true);
    groupLayout->addWidget(infoLabel);

    labelTransparentUTXOs = new QLabel(tr("Stakeable UTXOs: Checking..."));
    groupLayout->addWidget(labelTransparentUTXOs);

    labelTransparentWeight = new QLabel(tr("Staking Weight: Checking..."));
    groupLayout->addWidget(labelTransparentWeight);

    layout->addWidget(group);
    layout->addStretch();
}

void StakingPage::setupNullStakePanel()
{
    nullstakePanel = new QWidget();
    QVBoxLayout *outerLayout = new QVBoxLayout(nullstakePanel);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    QScrollArea *nsScroll = new QScrollArea();
    nsScroll->setWidgetResizable(true);
    nsScroll->setFrameShape(QFrame::NoFrame);
    QWidget *nsContent = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(nsContent);

    QGroupBox *group = new QGroupBox(tr("NullStake Private Staking (V1/V2)"));
    QVBoxLayout *groupLayout = new QVBoxLayout(group);

    QLabel *infoLabel = new QLabel(tr(
        "NullStake uses your shielded (private) coins for staking via Zero-Knowledge proofs. "
        "The amount you stake, the rewards you earn, and your identity as a staker are all hidden. "
        "You need shielded coins to use this mode — shield some coins below."));
    infoLabel->setWordWrap(true);
    groupLayout->addWidget(infoLabel);

    labelShieldedBalance = new QLabel(tr("Shielded Balance: Checking..."));
    QFont bf = labelShieldedBalance->font(); bf.setBold(true);
    labelShieldedBalance->setFont(bf);
    groupLayout->addWidget(labelShieldedBalance);

    labelShieldedStatus = new QLabel("");
    labelShieldedStatus->setWordWrap(true);
    groupLayout->addWidget(labelShieldedStatus);

    // Shield coins section with amount choice
    QFrame *shieldFrame = new QFrame();
    shieldFrame->setFrameShape(QFrame::StyledPanel);
    shieldFrame->setFrameShadow(QFrame::Sunken);
    QGridLayout *shieldGrid = new QGridLayout(shieldFrame);
    shieldGrid->setSpacing(12);

    QLabel *shieldAmtLabel = new QLabel(tr("Amount to Shield:"));
    shieldAmtLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    editShieldAmount = new QLineEdit();
    editShieldAmount->setPlaceholderText(tr("0.00000000 (or * for entire balance)"));
    editShieldAmount->setMaximumWidth(280);
    shieldGrid->addWidget(shieldAmtLabel, 0, 0);
    shieldGrid->addWidget(editShieldAmount, 0, 1);

    btnShieldCoins = new QPushButton(tr("Shield Coins"));
    btnShieldCoins->setToolTip(tr("Move the specified amount to shielded pool for private staking"));
    btnShieldCoins->setMinimumSize(150, 0);
    connect(btnShieldCoins, SIGNAL(clicked()), this, SLOT(onShieldCoinsClicked()));
    shieldGrid->addWidget(btnShieldCoins, 1, 1);

    groupLayout->addWidget(shieldFrame);
    layout->addWidget(group);
    layout->addStretch();

    nsScroll->setWidget(nsContent);
    outerLayout->addWidget(nsScroll);
}

void StakingPage::setupColdStakingPanel()
{
    coldStakingPanel = new QWidget();
    QVBoxLayout *outerLayout = new QVBoxLayout(coldStakingPanel);
    outerLayout->setContentsMargins(0, 0, 0, 0);

    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget *scrollContent = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(scrollContent);

    QGroupBox *infoGroup = new QGroupBox(tr("What is Cold Staking?"));
    QVBoxLayout *infoLayout = new QVBoxLayout(infoGroup);

    labelColdStakingInfo = new QLabel(tr(
        "Cold staking lets you earn staking rewards while keeping your spending keys "
        "completely offline. Your coins stay in your control - only the ability to stake "
        "is delegated to a hot node (typically a VPS).\n\n"
        "How it works:\n"
        "1. Create a staking address on your VPS node\n"
        "2. Delegate coins to that address from this wallet\n"
        "3. The VPS node stakes on your behalf 24/7\n"
        "4. Rewards go to your wallet, not the VPS\n"
        "5. You can revoke the delegation anytime\n\n"
        "Your Qt wallet can stay completely offline after delegation.\n"
        "The VPS staker node CANNOT spend your coins."));
    labelColdStakingInfo->setWordWrap(true);
    infoLayout->addWidget(labelColdStakingInfo);

    layout->addWidget(infoGroup);

    QGroupBox *setupGroup = new QGroupBox(tr("VPS Setup Instructions"));
    QVBoxLayout *setupLayout = new QVBoxLayout(setupGroup);

    labelColdInstructions = new QLabel(tr(
        "On your VPS, run these commands:\n\n"
        "  innovad -staking=1\n"
        "  innova-cli getnewstakingaddress\n\n"
        "Copy the staking address from your VPS and paste it below."));
    labelColdInstructions->setWordWrap(true);
    labelColdInstructions->setTextInteractionFlags(Qt::TextSelectableByMouse);
    setupLayout->addWidget(labelColdInstructions);

    layout->addWidget(setupGroup);

    QGroupBox *delegateGroup = new QGroupBox(tr("Delegate Coins"));
    QVBoxLayout *delegateLayout = new QVBoxLayout(delegateGroup);

    QHBoxLayout *addrRow = new QHBoxLayout();
    addrRow->addWidget(new QLabel(tr("VPS Staking Address:")));
    editStakerAddress = new QLineEdit();
    editStakerAddress->setPlaceholderText(tr("Paste staking address from your VPS"));
    addrRow->addWidget(editStakerAddress);
    delegateLayout->addLayout(addrRow);

    QHBoxLayout *amountRow = new QHBoxLayout();
    amountRow->addWidget(new QLabel(tr("Amount to Delegate:")));
    editDelegateAmount = new QLineEdit();
    editDelegateAmount->setPlaceholderText(tr("Amount in INN"));
    amountRow->addWidget(editDelegateAmount);
    delegateLayout->addLayout(amountRow);

    btnDelegate = new QPushButton(tr("Delegate Stake"));
    btnDelegate->setToolTip(tr("Delegate the specified amount to the VPS staking address"));
    btnDelegate->setMaximumWidth(200);
    connect(btnDelegate, SIGNAL(clicked()), this, SLOT(onDelegateClicked()));
    delegateLayout->addWidget(btnDelegate);

    layout->addWidget(delegateGroup);

    QGroupBox *activeGroup = new QGroupBox(tr("Active Delegations"));
    QVBoxLayout *activeLayout = new QVBoxLayout(activeGroup);

    labelColdBalance = new QLabel(tr("Total Delegated: 0.00 INN"));
    QFont boldFont = labelColdBalance->font();
    boldFont.setBold(true);
    labelColdBalance->setFont(boldFont);
    activeLayout->addWidget(labelColdBalance);

    tableDelegations = new QTableWidget(0, 4);
    tableDelegations->setHorizontalHeaderLabels(
        QStringList() << tr("Amount") << tr("Staker Address") << tr("Owner Address") << tr("Confirmations"));
    tableDelegations->horizontalHeader()->setStretchLastSection(true);
    tableDelegations->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableDelegations->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableDelegations->setMinimumHeight(150);
    activeLayout->addWidget(tableDelegations);

    QHBoxLayout *btnRow = new QHBoxLayout();
    btnRefreshDelegations = new QPushButton(tr("Refresh"));
    connect(btnRefreshDelegations, SIGNAL(clicked()), this, SLOT(onRefreshDelegations()));
    btnRow->addWidget(btnRefreshDelegations);
    btnRow->addStretch();
    activeLayout->addLayout(btnRow);

    layout->addWidget(activeGroup);

    scrollArea->setWidget(scrollContent);
    outerLayout->addWidget(scrollArea);
}

void StakingPage::setupNullStakeColdPanel()
{
    nullstakeColdPanel = new QWidget();
    QVBoxLayout *outerLayout = new QVBoxLayout(nullstakeColdPanel);
    outerLayout->setContentsMargins(0, 0, 0, 0);

    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget *scrollContent = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(scrollContent);

    QGroupBox *infoGroup = new QGroupBox(tr("NullStake V3 — Private Cold Staking"));
    QVBoxLayout *infoLayout = new QVBoxLayout(infoGroup);

    QLabel *infoLabel = new QLabel(tr(
        "Private Cold Staking combines the privacy of NullStake with the convenience of cold staking. "
        "Your shielded coins are delegated to a VPS staker, but the spending keys stay offline "
        "and the staking amount remains hidden via Zero-Knowledge proofs.\n\n"
        "How it works:\n"
        "1. Shield coins into your private pool\n"
        "2. Generate a staking address on your VPS\n"
        "3. Delegate your shielded coins to the VPS staker\n"
        "4. The VPS stakes privately on your behalf 24/7\n"
        "5. Rewards go to your shielded wallet\n"
        "6. Revoke anytime — VPS cannot spend your coins"));
    infoLabel->setWordWrap(true);
    infoLayout->addWidget(infoLabel);
    layout->addWidget(infoGroup);

    QGroupBox *delegateGroup = new QGroupBox(tr("Private Delegation"));
    QVBoxLayout *delegateLayout = new QVBoxLayout(delegateGroup);

    QFrame *formFrame = new QFrame();
    formFrame->setFrameShape(QFrame::StyledPanel);
    formFrame->setFrameShadow(QFrame::Sunken);
    QGridLayout *grid = new QGridLayout(formFrame);
    grid->setSpacing(12);

    QLabel *stakerLabel = new QLabel(tr("VPS Staker Address:"));
    stakerLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    editNullColdStakerAddr = new QLineEdit();
    editNullColdStakerAddr->setPlaceholderText(tr("Paste staking address from your VPS"));
    editNullColdStakerAddr->setFont(QFont("monospace"));
    grid->addWidget(stakerLabel, 0, 0);
    grid->addWidget(editNullColdStakerAddr, 0, 1);

    QLabel *amtLabel = new QLabel(tr("Amount:"));
    amtLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    editNullColdAmount = new QLineEdit();
    editNullColdAmount->setPlaceholderText(tr("0.00000000"));
    editNullColdAmount->setMaximumWidth(220);
    grid->addWidget(amtLabel, 1, 0);
    grid->addWidget(editNullColdAmount, 1, 1);

    delegateLayout->addWidget(formFrame);

    QHBoxLayout *btnRow = new QHBoxLayout();
    btnNullColdDelegate = new QPushButton(tr("Delegate Privately"));
    btnNullColdDelegate->setMinimumSize(150, 0);
    btnNullColdDelegate->setStyleSheet("QPushButton { background-color: #9C27B0; color: white; }");
    connect(btnNullColdDelegate, SIGNAL(clicked()), this, SLOT(onNullColdDelegateClicked()));
    btnRow->addWidget(btnNullColdDelegate);
    btnRow->addStretch();
    delegateLayout->addLayout(btnRow);

    layout->addWidget(delegateGroup);
    layout->addStretch();

    scrollArea->setWidget(scrollContent);
    outerLayout->addWidget(scrollArea);
}

void StakingPage::setModel(WalletModel *model)
{
    this->model = model;
    if (model)
    {
        {
            LOCK(cs_stakingMode);
            stakingTabs->setCurrentIndex((int)nStakingMode);
        }

        if (model->getOptionsModel())
        {
            connect(model->getOptionsModel(), SIGNAL(stakingModeChanged(int)),
                    stakingTabs, SLOT(setCurrentIndex(int)));
        }

        updateStakingStatus();
        updateBalances();
    }
}

void StakingPage::onStakingModeChanged(int index)
{
    if (index < 0 || index > 3)
        return;

    // Map tab index to staking mode: 0=transparent, 1=nullstake, 2=cold, 3=nullstake cold (uses cold mode)
    int modeIdx = (index == 3) ? 2 : index; // NullStake Cold uses STAKE_COLD mode internally
    {
        LOCK(cs_stakingMode);
        nStakingMode = (StakingMode)modeIdx;
    }

    updateModeDescription(index);

    if (model && model->getOptionsModel())
    {
        model->getOptionsModel()->setData(
            model->getOptionsModel()->index(OptionsModel::StakingModeOpt),
            QVariant(index), Qt::EditRole);
    }

    updateBalances();
}

void StakingPage::updateModeDescription(int mode)
{
    switch(mode)
    {
    case 0:
        labelStakingMode->setText(tr("Mode: Transparent Staking"));
        break;
    case 1:
        labelStakingMode->setText(tr("Mode: NullStake Private Staking"));
        break;
    case 2:
        labelStakingMode->setText(tr("Mode: Cold Staking (Delegated)"));
        break;
    default:
        labelStakingMode->setText(tr("Mode: Unknown"));
        break;
    }
}

void StakingPage::updateStakingStatus()
{
    if (!model)
        return;

    bool fStaking = GetBoolArg("-staking", true);
    bool fLocked = pwalletMain ? pwalletMain->IsLocked() : true;
    bool fConnected;
    {
        TRY_LOCK(cs_vNodes, lockNodes);
        if (!lockNodes)
            return; // Skip this update if lock is contended
        fConnected = !vNodes.empty();
    }
    bool fSyncing = IsInitialBlockDownload();

    if (!fStaking)
        labelStakingStatus->setText(tr("Status: Staking is disabled (-staking=0)"));
    else if (fLocked)
        labelStakingStatus->setText(tr("Status: Wallet is locked. Unlock for staking."));
    else if (!fConnected)
        labelStakingStatus->setText(tr("Status: Not connected to any peers."));
    else if (fSyncing)
        labelStakingStatus->setText(tr("Status: Synchronizing blockchain..."));
    else
        labelStakingStatus->setText(tr("Status: Staking active"));
}

void StakingPage::updateBalances()
{
    if (!model || !pwalletMain)
        return;

    TRY_LOCK(pwalletMain->cs_wallet, lockWallet);
    if (!lockWallet)
        return;

    int mode = stakingTabs->currentIndex();
    int unit = BitcoinUnits::BTC;
    if (model->getOptionsModel())
        unit = model->getOptionsModel()->getDisplayUnit();

    switch(mode)
    {
    case 0: // Transparent
    {
        int64_t nBalance = pwalletMain->GetBalance();
        labelStakingBalance->setText(tr("Staking Balance: %1")
            .arg(BitcoinUnits::formatWithUnit(unit, nBalance)));
        break;
    }
    case 1: // NullStake
    {
        int64_t nShielded = pwalletMain->GetShieldedBalance();
        int64_t nTransparent = pwalletMain->GetBalance();
        labelStakingBalance->setText(tr("Shielded Balance: %1")
            .arg(BitcoinUnits::formatWithUnit(unit, nShielded)));
        labelShieldedBalance->setText(tr("Shielded Balance: %1")
            .arg(BitcoinUnits::formatWithUnit(unit, nShielded)));

        // Shield button always enabled when transparent coins exist (ease of use)
        btnShieldCoins->setEnabled(nTransparent > 0);

        if (nShielded == 0 && nTransparent > 0)
        {
            labelShieldedStatus->setText(tr(
                "You have transparent coins but no shielded coins. "
                "Click 'Shield Coins' to move coins to the shielded pool for private staking."));
            labelShieldedStatus->setStyleSheet("QLabel { color: #CC6600; }");
        }
        else if (nShielded > 0 && nTransparent > 0)
        {
            labelShieldedStatus->setText(tr("Ready for private staking. You can shield more coins anytime."));
            labelShieldedStatus->setStyleSheet("QLabel { color: green; }");
        }
        else if (nShielded > 0)
        {
            labelShieldedStatus->setText(tr("Ready for private staking."));
            labelShieldedStatus->setStyleSheet("QLabel { color: green; }");
        }
        else
        {
            labelShieldedStatus->setText(tr("No coins available. Receive coins first."));
            labelShieldedStatus->setStyleSheet("");
        }
        break;
    }
    case 2: // Cold
    {
        int64_t nCold = pwalletMain->GetColdStakingBalance();
        labelStakingBalance->setText(tr("Cold Staking Balance: %1")
            .arg(BitcoinUnits::formatWithUnit(unit, nCold)));
        labelColdBalance->setText(tr("Total Delegated: %1")
            .arg(BitcoinUnits::formatWithUnit(unit, nCold)));
        break;
    }
    default:
        break;
    }
}

void StakingPage::onShieldCoinsClicked()
{
    if (!model || !pwalletMain)
        return;

    QString amountStr = editShieldAmount->text().trimmed();
    if (amountStr.isEmpty())
    {
        QMessageBox::warning(this, tr("Shield Coins"),
            tr("Please enter an amount to shield, or * to shield your entire balance."));
        return;
    }

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, tr("Shield Coins"),
        tr("Shield %1 to the shielded pool for private staking?\n\n"
           "A shielded address will be created automatically if you don't have one.\n"
           "Once shielded, NullStake will use these coins.").arg(amountStr),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    QString fromAddr = (amountStr == "*") ? "*" : "";
    QString resultOut;
    WalletModel::StatusCode status = model->shieldCoins(fromAddr, amountStr, resultOut);

    if (status == WalletModel::OK)
    {
        QMessageBox::information(this, tr("Shield Coins"),
            tr("Coins shielded successfully!\n\n%1\n\n"
               "Your shielded balance will update after confirmation.").arg(resultOut));
        editShieldAmount->clear();
        updateStakingStatus();
    }
    else
    {
        QMessageBox::warning(this, tr("Shield Coins"),
            tr("Failed to shield coins:\n\n%1").arg(resultOut));
    }
}

void StakingPage::onNullColdDelegateClicked()
{
    if (!model || !pwalletMain)
        return;

    QString stakerAddr = editNullColdStakerAddr->text().trimmed();
    QString amountStr = editNullColdAmount->text().trimmed();

    if (stakerAddr.isEmpty() || amountStr.isEmpty())
    {
        QMessageBox::warning(this, tr("Private Cold Staking"),
            tr("Please enter both the VPS staker address and the amount to delegate."));
        return;
    }

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, tr("Private Cold Delegation"),
        tr("Delegate %1 INN privately to VPS staker?\n\nStaker: %2\n\n"
           "Your spending keys stay offline. The VPS can only stake, not spend.")
           .arg(amountStr, stakerAddr.left(30) + "..."),
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes)
    {
        QString rpcCmd = QString("n_delegatestake \"%1\" %2").arg(stakerAddr, amountStr);
        QMessageBox::information(this, tr("Private Cold Staking"),
            tr("Execute in Debug Console:\n\n  %1\n\n"
               "Monitor with: n_coldstakeinfo").arg(rpcCmd));
    }
}

void StakingPage::onDelegateClicked()
{
    if (!model || !pwalletMain)
        return;

    QString stakerAddr = editStakerAddress->text().trimmed();
    QString amountStr = editDelegateAmount->text().trimmed();

    if (stakerAddr.isEmpty())
    {
        QMessageBox::warning(this, tr("Delegation Error"),
            tr("Please enter the VPS staking address."));
        return;
    }

    if (amountStr.isEmpty())
    {
        QMessageBox::warning(this, tr("Delegation Error"),
            tr("Please enter the amount to delegate."));
        return;
    }

    bool ok;
    double amountDbl = amountStr.toDouble(&ok);
    if (!ok || amountDbl <= 0 || amountDbl > 18000000.0) // MAX_MONEY is ~18M INN
    {
        QMessageBox::warning(this, tr("Delegation Error"),
            tr("Invalid amount. Please enter a positive number up to 18,000,000 INN."));
        return;
    }
    int64_t nAmount = (int64_t)(amountDbl * COIN + 0.5);
    if (nAmount <= 0 || nAmount > MAX_MONEY)
    {
        QMessageBox::warning(this, tr("Delegation Error"),
            tr("Amount out of valid range."));
        return;
    }

    CBitcoinAddress addrCheck(stakerAddr.toStdString());
    if (!addrCheck.IsValid())
    {
        QMessageBox::warning(this, tr("Delegation Error"),
            tr("Invalid staking address. Please check the address and try again."));
        return;
    }

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, tr("Confirm Delegation"),
        tr("Delegate %1 INN to staker address:\n%2\n\n"
           "The VPS will stake these coins on your behalf. "
           "You can revoke this delegation at any time.\n\nProceed?")
           .arg(amountStr, stakerAddr),
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes)
    {
        QMessageBox::information(this, tr("Delegate Stake"),
            tr("To delegate your stake, use the Debug Console (Help > Debug Window > Console):\n\n"
               "  delegatestake \"%1\" %2\n\n"
               "This will create a cold staking delegation transaction.\n"
               "This will be integrated directly in a future update.")
               .arg(stakerAddr, amountStr));
    }
}

void StakingPage::onRevokeDelegation()
{
    QMessageBox::information(this, tr("Revoke Delegation"),
        tr("To revoke a cold staking delegation, use the Debug Console:\n\n"
           "  revokecoldstaking <txid> <vout>\n\n"
           "Use 'listcoldutxos' to see your active delegations."));
}

void StakingPage::onRefreshDelegations()
{
    if (!model || !pwalletMain)
        return;

    tableDelegations->setRowCount(0);

    int64_t nCold = pwalletMain->GetColdStakingBalance();
    int unit = BitcoinUnits::BTC;
    if (model->getOptionsModel())
        unit = model->getOptionsModel()->getDisplayUnit();

    labelColdBalance->setText(tr("Total Delegated: %1")
        .arg(BitcoinUnits::formatWithUnit(unit, nCold)));

    if (nCold == 0)
    {
        QMessageBox::information(this, tr("Cold Staking"),
            tr("No active cold staking delegations found.\n\n"
               "To create a delegation, enter a VPS staking address and amount above."));
    }
}
