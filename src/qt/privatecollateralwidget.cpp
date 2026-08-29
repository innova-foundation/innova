#include "privatecollateralwidget.h"
#include "iv5rpcbridge.h"
#include "walletmodel.h"

#include <QDateTime>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

PrivateCollateralWidget::PrivateCollateralWidget(QWidget *parent) :
    QWidget(parent),
    model(0)
{
    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *notice = new QLabel(tr(
        "A private registration attests one 25,000 INN note as collateral. It "
        "publishes that note's key image, and the chain keeps that record forever: "
        "the key image is a persistent pseudonym for this node by design, and it can "
        "never be registered again once released. Because the attestation is already "
        "identifying in that one way, consensus forces it to disclosure mask 7 so it "
        "leaks nothing else; the mask is not a choice here."));
    notice->setWordWrap(true);
    notice->setStyleSheet("color: #d98c00; font-weight: bold;");
    layout->addWidget(notice);

    // --- collateral notes ---
    QGroupBox *notesGroup = new QGroupBox(tr("Attestable notes"));
    QHBoxLayout *notesLayout = new QHBoxLayout(notesGroup);
    listNotesButton = new QPushButton(tr("List candidate notes"));
    notesLayout->addWidget(listNotesButton);
    QLabel *notesHint = new QLabel(tr(
        "Exactly 25,000 INN, unspent, and not already registered. A shield-funded "
        "note is never chosen by default: its link to a transparent address is "
        "certain rather than probabilistic."));
    notesHint->setWordWrap(true);
    notesHint->setStyleSheet("color: #888;");
    notesLayout->addWidget(notesHint, 1);
    layout->addWidget(notesGroup);

    // --- node registration ---
    QGroupBox *nodeGroup = new QGroupBox(tr("Register this node"));
    QFormLayout *nodeForm = new QFormLayout(nodeGroup);
    nodeEndpointEdit = new QLineEdit();
    nodeEndpointEdit->setPlaceholderText(tr("host:port this node is reachable on"));
    nodePayoutEdit = new QLineEdit();
    nodePayoutEdit->setPlaceholderText(tr("IV5 address to be paid"));
    nodeNoteEdit = new QLineEdit();
    nodeNoteEdit->setPlaceholderText(tr("optional txhash:index to pin a specific note"));
    nodeForm->addRow(tr("Endpoint:"), nodeEndpointEdit);
    nodeForm->addRow(tr("Pool payout:"), nodePayoutEdit);
    nodeForm->addRow(tr("Note:"), nodeNoteEdit);
    QHBoxLayout *nodeButtons = new QHBoxLayout();
    nodePreviewButton = new QPushButton(tr("Preview"));
    nodeRegisterButton = new QPushButton(tr("Register"));
    nodeButtons->addWidget(nodePreviewButton);
    nodeButtons->addWidget(nodeRegisterButton);
    nodeButtons->addStretch();
    nodeForm->addRow(QString(), nodeButtons);
    layout->addWidget(nodeGroup);

    // --- finality member registration ---
    QGroupBox *memberGroup = new QGroupBox(tr("Register as a finality-committee member"));
    QFormLayout *memberForm = new QFormLayout(memberGroup);
    QLabel *memberHint = new QLabel(tr(
        "The committee is drawn from these registrations; nothing is configured. The "
        "seats go to the first distinct member keys in the draw order, so registering "
        "several notes under one key claims one seat, not several. Registering a key "
        "whose private half this wallet does not hold seats a member that cannot sign."));
    memberHint->setWordWrap(true);
    memberHint->setStyleSheet("color: #888;");
    memberForm->addRow(memberHint);
    memberKeyEdit = new QLineEdit();
    memberKeyEdit->setPlaceholderText(tr("member pubkey hex, or 'new' for a fresh wallet key"));
    memberNoteEdit = new QLineEdit();
    memberNoteEdit->setPlaceholderText(tr("optional txhash:index to pin a specific note"));
    memberForm->addRow(tr("Member key:"), memberKeyEdit);
    memberForm->addRow(tr("Note:"), memberNoteEdit);
    QHBoxLayout *memberButtons = new QHBoxLayout();
    memberPreviewButton = new QPushButton(tr("Preview"));
    memberRegisterButton = new QPushButton(tr("Register"));
    memberButtons->addWidget(memberPreviewButton);
    memberButtons->addWidget(memberRegisterButton);
    memberButtons->addStretch();
    memberForm->addRow(QString(), memberButtons);
    layout->addWidget(memberGroup);

    // --- status and lifecycle ---
    QGroupBox *statusGroup = new QGroupBox(tr("Status and lifecycle"));
    QVBoxLayout *statusLayout = new QVBoxLayout(statusGroup);
    QHBoxLayout *statusButtons = new QHBoxLayout();
    statusButton = new QPushButton(tr("Node status"));
    finalityStatusButton = new QPushButton(tr("Member status"));
    announceButton = new QPushButton(tr("Announce"));
    statusButtons->addWidget(statusButton);
    statusButtons->addWidget(finalityStatusButton);
    statusButtons->addWidget(announceButton);
    statusButtons->addStretch();
    statusLayout->addLayout(statusButtons);

    QHBoxLayout *registryLayout = new QHBoxLayout();
    registryHeightEdit = new QLineEdit();
    registryHeightEdit->setPlaceholderText(tr("anchor height (blank for the tip)"));
    finalityRegistryButton = new QPushButton(tr("Member registry at height"));
    registryLayout->addWidget(registryHeightEdit, 1);
    registryLayout->addWidget(finalityRegistryButton);
    statusLayout->addLayout(registryLayout);

    QHBoxLayout *releaseLayout = new QHBoxLayout();
    releaseKeyImageEdit = new QLineEdit();
    releaseKeyImageEdit->setPlaceholderText(tr("key image to release"));
    releaseButton = new QPushButton(tr("Release"));
    releaseLayout->addWidget(releaseKeyImageEdit, 1);
    releaseLayout->addWidget(releaseButton);
    statusLayout->addLayout(releaseLayout);
    layout->addWidget(statusGroup);

    outputView = new QPlainTextEdit();
    outputView->setReadOnly(true);
    outputView->setStyleSheet("font-family: monospace; font-size: 11px;");
    layout->addWidget(outputView, 1);

    connect(listNotesButton, SIGNAL(clicked()), this, SLOT(onListNotes()));
    connect(nodePreviewButton, SIGNAL(clicked()), this, SLOT(onNodePreview()));
    connect(nodeRegisterButton, SIGNAL(clicked()), this, SLOT(onNodeRegister()));
    connect(memberPreviewButton, SIGNAL(clicked()), this, SLOT(onMemberPreview()));
    connect(memberRegisterButton, SIGNAL(clicked()), this, SLOT(onMemberRegister()));
    connect(announceButton, SIGNAL(clicked()), this, SLOT(onAnnounce()));
    connect(statusButton, SIGNAL(clicked()), this, SLOT(onStatusPrivate()));
    connect(finalityStatusButton, SIGNAL(clicked()), this, SLOT(onFinalityStatus()));
    connect(finalityRegistryButton, SIGNAL(clicked()), this, SLOT(onFinalityRegistry()));
    connect(releaseButton, SIGNAL(clicked()), this, SLOT(onRelease()));
}

void PrivateCollateralWidget::setModel(WalletModel *modelIn)
{
    model = modelIn;
}

void PrivateCollateralWidget::report(const QString& heading, const QString& body)
{
    const QString stamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    outputView->appendPlainText(QString("[%1] %2").arg(stamp).arg(heading));
    if (!body.isEmpty())
        outputView->appendPlainText(body);
    outputView->appendPlainText(QString());
}

void PrivateCollateralWidget::run(const QStringList& args, bool fNeedsUnlock)
{
    if (args.isEmpty())
        return;

    if (fNeedsUnlock)
    {
        if (model == 0)
        {
            report(tr("collateralnode %1").arg(args.at(0)),
                   tr("no wallet is loaded"));
            return;
        }
        WalletModel::UnlockContext ctx(model->requestUnlock());
        if (!ctx.isValid())
        {
            report(tr("collateralnode %1").arg(args.at(0)),
                   tr("the wallet stayed locked; nothing was sent"));
            return;
        }
        QString result;
        QString error;
        if (!Iv5Rpc::Call("collateralnode", args, result, error))
            report(tr("collateralnode %1 failed").arg(args.at(0)), error);
        else
            report(tr("collateralnode %1").arg(args.at(0)), result);
        return;
    }

    QString result;
    QString error;
    if (!Iv5Rpc::Call("collateralnode", args, result, error))
        report(tr("collateralnode %1 failed").arg(args.at(0)), error);
    else
        report(tr("collateralnode %1").arg(args.at(0)), result);
}

void PrivateCollateralWidget::onListNotes()
{
    run(QStringList() << "collateral-notes", false);
}

bool PrivateCollateralWidget::nodeArgs(bool fConfirm, QStringList& argsOut)
{
    const QString endpoint = nodeEndpointEdit->text().trimmed();
    const QString payout = nodePayoutEdit->text().trimmed();
    if (endpoint.isEmpty() || payout.isEmpty())
    {
        QMessageBox::warning(this, tr("Register this node"),
                             tr("An endpoint and a pool payout address are both required."));
        return false;
    }
    argsOut << "registerprivate" << endpoint << payout;
    const QString note = nodeNoteEdit->text().trimmed();
    if (!note.isEmpty())
        argsOut << note;
    if (fConfirm)
        argsOut << "confirm";
    return true;
}

void PrivateCollateralWidget::onNodePreview()
{
    QStringList args;
    if (nodeArgs(false, args))
        run(args, true);
}

void PrivateCollateralWidget::onNodeRegister()
{
    QStringList args;
    if (!nodeArgs(true, args))
        return;

    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Register this node"),
        tr("This publishes the note's key image permanently. That key image can "
           "never back another registration, on this node or any other, and it "
           "identifies this node for as long as the chain exists.\n\n"
           "Preview first if you have not. Register now?"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    run(args, true);
}

bool PrivateCollateralWidget::memberArgs(bool fConfirm, QStringList& argsOut)
{
    argsOut << "finality-register";
    const QString key = memberKeyEdit->text().trimmed();
    if (!key.isEmpty())
        argsOut << key;
    const QString note = memberNoteEdit->text().trimmed();
    if (!note.isEmpty())
        argsOut << note;
    if (fConfirm)
        argsOut << "confirm";
    return true;
}

void PrivateCollateralWidget::onMemberPreview()
{
    QStringList args;
    if (memberArgs(false, args))
        run(args, true);
}

void PrivateCollateralWidget::onMemberRegister()
{
    QStringList args;
    if (!memberArgs(true, args))
        return;

    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Register as a committee member"),
        tr("This publishes the note's key image permanently and enters this key in "
           "the draw the chain runs at the next term boundary.\n\n"
           "A seat is only useful if this wallet holds the private half of the "
           "member key: a seated member that cannot sign stalls the private "
           "certificate for the whole term. Register now?"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    run(args, true);
}

void PrivateCollateralWidget::onAnnounce()
{
    run(QStringList() << "announceprivate", true);
}

void PrivateCollateralWidget::onStatusPrivate()
{
    run(QStringList() << "statusprivate", false);
}

void PrivateCollateralWidget::onFinalityStatus()
{
    run(QStringList() << "finality-status", false);
}

void PrivateCollateralWidget::onFinalityRegistry()
{
    QStringList args;
    args << "finality-registry";
    const QString height = registryHeightEdit->text().trimmed();
    if (!height.isEmpty())
        args << height;
    run(args, false);
}

void PrivateCollateralWidget::onRelease()
{
    const QString keyImage = releaseKeyImageEdit->text().trimmed();
    if (keyImage.isEmpty())
    {
        QMessageBox::warning(this, tr("Release"),
                             tr("Enter the key image to release."));
        return;
    }

    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Release"),
        tr("Releasing hands the note back to ordinary spending, and the next spend "
           "that takes it deregisters this node. The chain keeps the watch record "
           "forever, so this key image can never be registered again.\n\n"
           "Release %1?").arg(keyImage),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    run(QStringList() << "releaseprivate" << keyImage, false);
}
