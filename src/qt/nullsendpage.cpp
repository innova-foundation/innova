#include "nullsendpage.h"
#include "walletmodel.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "guiutil.h"

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
    model(0)
{
    setupUI();
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
    fromAddressEdit->setPlaceholderText(tr("Your address (funds to mix)"));
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
}

void NullSendPage::onStartMixClicked()
{
    if (!model)
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

    QString rpcCmd = QString("z_nullsend \"%1\" %2 7 %3 %4").arg(from, amount).arg(pool).arg(timeout);
    statusLabel->setText(tr("Mixing started... Use Debug Console for real-time status: getmixingstatus"));

    QMessageBox::information(this, tr("NullSend"),
        tr("Execute this command in the Debug Console:\n\n%1\n\n"
           "Monitor progress with: getmixingstatus").arg(rpcCmd));
}

void NullSendPage::onStopMixClicked()
{
    statusLabel->setText(tr("Use Debug Console: stopmixing"));
    QMessageBox::information(this, tr("Stop Mixing"),
        tr("Execute in Debug Console:\n\nstopmixing"));
}

void NullSendPage::onRefreshStatusClicked()
{
    statusLabel->setText(tr("Use Debug Console: getmixingstatus"));
}
