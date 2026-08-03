#include "nullsendpage.h"
#include "walletmodel.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "guiutil.h"
#include "main.h"
#include "privacyuipolicy.h"

#include <QMessageBox>
#include <QApplication>
#include <QClipboard>
#include <QFrame>
#include <QGridLayout>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QScrollArea>

NullSendPage::NullSendPage(QWidget *parent) :
    QWidget(parent),
    model(0),
    legacyNullSendEnabled(false)
{
    setupUI();
    applyPrivacyPolicy();
}

void NullSendPage::setupUI()
{
    // Wrap everything in a scroll area to prevent compression
    QVBoxLayout *outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    QScrollArea *scrollArea = new QScrollArea();
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    QWidget *scrollContent = new QWidget();
    QVBoxLayout *mainLayout = new QVBoxLayout(scrollContent);
    mainLayout->setContentsMargins(20, 20, 20, 20);

    // Title
    QLabel *titleLabel = new QLabel(tr("NullSend — Multi-Party Mixing"));
    titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 5px;");
    mainLayout->addWidget(titleLabel);

    QLabel *descLabel = new QLabel(
        tr("NullSend uses Chaumian blind signatures to mix your coins with multiple participants, "
           "breaking the transaction history and making your coins untraceable. "
           "Unlike selective privacy (FCMP++), NullSend completely severs the link between inputs and outputs."));
    descLabel->setWordWrap(true);
    descLabel->setStyleSheet("color: #888; margin-bottom: 15px; font-size: 12px;");
    mainLayout->addWidget(descLabel);

    availabilityLabel = new QLabel();
    availabilityLabel->setWordWrap(true);
    availabilityLabel->setStyleSheet(
        "color: #d98c00; font-weight: bold; margin-bottom: 8px;");
    mainLayout->addWidget(availabilityLabel);

    // Status section
    QGroupBox *statusGroup = new QGroupBox(tr("Mixing Status"));
    QHBoxLayout *statusLayout = new QHBoxLayout(statusGroup);
    mixingStatusLabel = new QLabel(tr("Not mixing"));
    mixingStatusLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    refreshStatusButton = new QPushButton(tr("Refresh"));
    statusLayout->addWidget(mixingStatusLabel);
    statusLayout->addStretch();
    statusLayout->addWidget(refreshStatusButton);
    mainLayout->addWidget(statusGroup);

    // Mix configuration — styled like transparent send entries
    QFrame *mixFrame = new QFrame();
    mixFrame->setFrameShape(QFrame::StyledPanel);
    mixFrame->setFrameShadow(QFrame::Sunken);
    QGridLayout *mixGrid = new QGridLayout(mixFrame);
    mixGrid->setSpacing(12);

    // From address
    QLabel *fromLabel = new QLabel(tr("From:"));
    fromLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    fromAddressEdit = new QLineEdit();
    fromAddressEdit->setPlaceholderText(tr("Your shielded z-address (funds to mix)"));
    fromAddressEdit->setFont(GUIUtil::bitcoinAddressFont());
    QToolButton *fromPasteBtn = new QToolButton();
    fromPasteBtn->setIcon(QIcon(":/icons/editpaste"));
    fromPasteBtn->setToolTip(tr("Paste address from clipboard"));
    connect(fromPasteBtn, &QToolButton::clicked, [this]() {
        fromAddressEdit->setText(QApplication::clipboard()->text());
    });
    QHBoxLayout *fromRow = new QHBoxLayout();
    fromRow->setSpacing(0);
    fromRow->addWidget(fromAddressEdit);
    fromRow->addWidget(fromPasteBtn);
    mixGrid->addWidget(fromLabel, 0, 0);
    mixGrid->addLayout(fromRow, 0, 1);

    // Amount
    QLabel *amtLabel = new QLabel(tr("A&mount:"));
    amtLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    amountEdit = new QLineEdit();
    amountEdit->setPlaceholderText(tr("0.00000000"));
    amountEdit->setMaximumWidth(200);
    mixGrid->addWidget(amtLabel, 1, 0);
    mixGrid->addWidget(amountEdit, 1, 1);

    // Pool size
    QLabel *poolLabel = new QLabel(tr("Pool Size:"));
    poolLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    poolSizeSpin = new QSpinBox();
    poolSizeSpin->setRange(2, 20);
    poolSizeSpin->setValue(5);
    poolSizeSpin->setToolTip(tr("Number of participants in the mixing pool. Higher = more privacy but longer wait."));
    poolSizeSpin->setMaximumWidth(120);
    mixGrid->addWidget(poolLabel, 2, 0);
    mixGrid->addWidget(poolSizeSpin, 2, 1);

    // Timeout
    QLabel *timeoutLabel = new QLabel(tr("Timeout:"));
    timeoutLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    timeoutSpin = new QSpinBox();
    timeoutSpin->setRange(30, 3600);
    timeoutSpin->setValue(300);
    timeoutSpin->setSuffix(tr(" seconds"));
    timeoutSpin->setToolTip(tr("Maximum time to wait for other participants to join the mix"));
    timeoutSpin->setMaximumWidth(200);
    mixGrid->addWidget(timeoutLabel, 3, 0);
    mixGrid->addWidget(timeoutSpin, 3, 1);

    mainLayout->addWidget(mixFrame);

    // Action buttons
    QHBoxLayout *btnLayout = new QHBoxLayout();
    startMixButton = new QPushButton(tr("Start NullSend Mix"));
    startMixButton->setMinimumSize(150, 0);
    startMixButton->setStyleSheet("QPushButton { background-color: #9C27B0; color: white; }");
    stopMixButton = new QPushButton(tr("Stop Mixing"));
    stopMixButton->setMinimumSize(150, 0);
    stopMixButton->setStyleSheet("QPushButton { background-color: #f44336; color: white; }");
    stopMixButton->setEnabled(false);
    btnLayout->addWidget(startMixButton);
    btnLayout->addWidget(stopMixButton);
    btnLayout->addStretch();
    mainLayout->addLayout(btnLayout);

    // Info section
    QGroupBox *infoGroup = new QGroupBox(tr("How NullSend Works"));
    QVBoxLayout *infoLayout = new QVBoxLayout(infoGroup);
    QLabel *infoLabel = new QLabel(
        tr("1. Your coins are combined with coins from other participants\n"
           "2. A blinded coordinator creates the mixed transaction\n"
           "3. No single party (including the coordinator) can link inputs to outputs\n"
           "4. The result is a standard-looking transaction with no traceable history\n\n"
           "Privacy guarantee: Even if all other participants collude, your specific "
           "input-output mapping cannot be determined."));
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("color: #aaa; font-size: 11px;");
    infoLayout->addWidget(infoLabel);
    mainLayout->addWidget(infoGroup);

    mainLayout->addStretch();

    // Status label at bottom
    statusLabel = new QLabel(tr("Ready"));
    statusLabel->setStyleSheet("color: #888;");
    mainLayout->addWidget(statusLabel);

    scrollArea->setWidget(scrollContent);
    outerLayout->addWidget(scrollArea);

    // Connections
    connect(startMixButton, SIGNAL(clicked()), this, SLOT(onStartMixClicked()));
    connect(stopMixButton, SIGNAL(clicked()), this, SLOT(onStopMixClicked()));
    connect(refreshStatusButton, SIGNAL(clicked()), this, SLOT(onRefreshStatusClicked()));
}

void NullSendPage::setModel(WalletModel *model)
{
    this->model = model;
    applyPrivacyPolicy();
}

void NullSendPage::applyPrivacyPolicy()
{
    const int currentHeight = pindexBest ? pindexBest->nHeight : 0;
    const PrivacyUiPolicy::Decision decision =
        PrivacyUiPolicy::EvaluateLegacyControls(
            fRegTest, IsBoundaryBActiveAtHeight(currentHeight), false);
    legacyNullSendEnabled = decision.legacyControlsEnabled;
    startMixButton->setEnabled(legacyNullSendEnabled);
    stopMixButton->setEnabled(false);

    if (legacyNullSendEnabled)
    {
        availabilityLabel->setText(tr(
            "Legacy NullSend is enabled for regtest historical testing only."));
    }
    else
    {
        availabilityLabel->setText(tr(
            "The unsafe legacy NullSend format is quarantined. Full-chain FCMP++ "
            "NullSend remains mandatory for privacy vNext, but is not yet available "
            "in this build."));
    }
}

void NullSendPage::onStartMixClicked()
{
    if (!model || !legacyNullSendEnabled)
        return;

    QString from = fromAddressEdit->text().trimmed();
    QString amount = amountEdit->text().trimmed();

    if (from.isEmpty() || amount.isEmpty())
    {
        QMessageBox::warning(this, tr("NullSend"), tr("Please enter your address and the amount to mix."));
        return;
    }

    int pool = poolSizeSpin->value();
    int timeout = timeoutSpin->value();

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Start NullSend"),
        tr("Start mixing %1 INN with %2 participants?\n\nTimeout: %3 seconds\n\n"
           "Your coins will be mixed with other participants to break transaction history.")
           .arg(amount).arg(pool).arg(timeout),
        QMessageBox::Yes | QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
        return;

    // This legacy RPC remains reachable only on regtest. Public-network vNext
    // will use a distinct transaction-2008 RPC and payload.
    bool ok = false;
    QStringList args;
    args << from << amount << QStringLiteral("7")
         << QString::number(pool) << QString::number(timeout);
    QString result = GUIUtil::executeRpc("z_nullsend", args, ok);
    if (ok)
    {
        statusLabel->setText(tr("Mixing started -- use Refresh Status to monitor."));
        QMessageBox::information(this, tr("NullSend"),
            tr("Mixing started for %1 INN.\n\n%2").arg(amount, result));
    }
    else
    {
        statusLabel->setText(tr("Mixing failed to start."));
        QMessageBox::warning(this, tr("NullSend"), tr("Could not start mixing:\n\n%1").arg(result));
    }
}

void NullSendPage::onStopMixClicked()
{
    statusLabel->setText(tr("Legacy NullSend sessions cannot be manually stopped."));
}

void NullSendPage::onRefreshStatusClicked()
{
    bool ok = false;
    QString result = GUIUtil::executeRpc("z_nullsendinfo", QStringList(), ok);
    mixingStatusLabel->setText(ok ? result.left(160) : tr("Status unavailable."));
    statusLabel->setText(ok ? tr("Legacy NullSend status refreshed.")
                            : tr("Status unavailable."));
}
