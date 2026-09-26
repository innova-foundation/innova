#include "nullsendmixwidget.h"
#include "iv5rpcbridge.h"

#include <QApplication>
#include <QComboBox>
#include <QDateTime>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <cmath>

NullSendMixWidget::NullSendMixWidget(QWidget *parent) :
    QWidget(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *about = new QLabel(tr(
        "A NullSend round spends one note from each seat into one transaction whose "
        "outputs all carry the same amount. Mixing hides which output is yours: each "
        "new note pays a key only its owner's seed can open, and no one, the "
        "coordinator included, can tell the outputs apart. It does not hide that you "
        "took part: the round's inputs are public on chain, so anyone can see your note "
        "was spent into this round. The anonymity set is the number of seats in the "
        "round, not the whole pool, and it does not multiply across rounds.\n\n"
        "If an output you received was sent with a mask that disclosed its receiver, "
        "mixing it is how to break that link going forward: the note you get back is "
        "unlinkable to the disclosed output, and later spends of it disclose no "
        "receiver. The disclosed output being spent into the round stays public."));
    about->setWordWrap(true);
    about->setStyleSheet("color: #888;");
    layout->addWidget(about);

    // --- service ---
    QGroupBox *serviceGroup = new QGroupBox(tr("Mix service"));
    QVBoxLayout *serviceLayout = new QVBoxLayout(serviceGroup);
    serviceLabel = new QLabel(tr("Checking..."));
    serviceLabel->setWordWrap(true);
    serviceLayout->addWidget(serviceLabel);
    QLabel *coordHint = new QLabel(tr(
        "Running a round as its coordinator is an operator task: it needs "
        "-mixcoordinatorport, an onion service of its own and -mixdir, and is started "
        "with the mixcoordinate RPC. A coordinator publishes its public key and the "
        "record slot its mixstatus shows; a seat enters those two values below."));
    coordHint->setWordWrap(true);
    coordHint->setStyleSheet("color: #888;");
    serviceLayout->addWidget(coordHint);
    layout->addWidget(serviceGroup);

    // --- prepare ---
    QGroupBox *prepareGroup = new QGroupBox(tr("1. Prepare a note"));
    QVBoxLayout *prepareLayout = new QVBoxLayout(prepareGroup);
    QLabel *prepareHint = new QLabel(tr(
        "A seat spends one note of exactly the tier plus one seat's fee share. Preparing "
        "makes that note with an ordinary transfer to this wallet and holds it so nothing "
        "else spends it. The note must be inside the round's anchor, which is hundreds of "
        "blocks behind the tip, so prepare well before the round. A mixed note is the "
        "tier alone and cannot enter the same tier again without a new prepare."));
    prepareHint->setWordWrap(true);
    prepareHint->setStyleSheet("color: #888;");
    prepareLayout->addWidget(prepareHint);

    QHBoxLayout *tierRow = new QHBoxLayout();
    tierCombo = new QComboBox();
    const QList<Iv5Rpc::MixTier> tiers = Iv5Rpc::MixTiers();
    for (int i = 0; i < tiers.size(); i++)
        tierCombo->addItem(tr("%1 INN tier (note of %2 INN)")
                               .arg(Iv5Rpc::FormatInn(tiers.at(i).nDenomination))
                               .arg(Iv5Rpc::FormatInn(tiers.at(i).nNoteAmount)),
                           QVariant(tiers.at(i).nDenomination));
    prepareButton = new QPushButton(tr("Prepare"));
    tierRow->addWidget(new QLabel(tr("Tier:")));
    tierRow->addWidget(tierCombo, 1);
    tierRow->addWidget(prepareButton);
    prepareLayout->addLayout(tierRow);

    prepareLayout->addWidget(new QLabel(tr("Held notes of a tier's size:")));
    notesList = new QListWidget();
    notesList->setMaximumHeight(110);
    prepareLayout->addWidget(notesList);
    QHBoxLayout *notesButtons = new QHBoxLayout();
    refreshNotesButton = new QPushButton(tr("Refresh"));
    releaseNoteButton = new QPushButton(tr("Release selected"));
    releaseNoteButton->setToolTip(tr(
        "Returns the note to ordinary spending and takes it out of mixing."));
    notesButtons->addWidget(refreshNotesButton);
    notesButtons->addWidget(releaseNoteButton);
    notesButtons->addStretch();
    prepareLayout->addLayout(notesButtons);
    layout->addWidget(prepareGroup);

    // --- join ---
    QGroupBox *joinGroup = new QGroupBox(tr("2. Join a round"));
    QFormLayout *joinForm = new QFormLayout(joinGroup);
    QLabel *joinHint = new QLabel(tr(
        "The seat waits for the coordinator's record slot to settle, fetches the "
        "announcement from the -mixdir directories over Tor, checks it against the "
        "chain, and spends a prepared note of the round's tier. The wallet stays "
        "unlocked until the round ends: locking it stops the seat."));
    joinHint->setWordWrap(true);
    joinHint->setStyleSheet("color: #888;");
    joinForm->addRow(joinHint);
    coordinatorEdit = new QLineEdit();
    coordinatorEdit->setPlaceholderText(tr("coordinator public key, 66 hex characters"));
    recordSlotEdit = new QLineEdit();
    recordSlotEdit->setPlaceholderText(tr("record slot from the coordinator"));
    joinForm->addRow(tr("Coordinator:"), coordinatorEdit);
    joinForm->addRow(tr("Record slot:"), recordSlotEdit);
    QHBoxLayout *joinButtons = new QHBoxLayout();
    joinButton = new QPushButton(tr("Join round"));
    joinButtons->addWidget(joinButton);
    joinButtons->addStretch();
    joinForm->addRow(QString(), joinButtons);
    layout->addWidget(joinGroup);

    // --- rounds ---
    QGroupBox *roundsGroup = new QGroupBox(tr("3. Rounds"));
    QVBoxLayout *roundsLayout = new QVBoxLayout(roundsGroup);
    jobsTable = new QTableWidget(0, 5);
    jobsTable->setHorizontalHeaderLabels(QStringList() << tr("Role") << tr("Record slot")
                                                       << tr("State") << tr("Status")
                                                       << tr("Round"));
    jobsTable->horizontalHeader()->setStretchLastSection(true);
    jobsTable->verticalHeader()->setVisible(false);
    jobsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    jobsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    jobsTable->setMinimumHeight(120);
    roundsLayout->addWidget(jobsTable);
    outcomeLabel = new QLabel();
    outcomeLabel->setWordWrap(true);
    outcomeLabel->setStyleSheet("font-weight: bold;");
    roundsLayout->addWidget(outcomeLabel);
    layout->addWidget(roundsGroup);

    outputView = new QPlainTextEdit();
    outputView->setReadOnly(true);
    outputView->setStyleSheet("font-family: monospace; font-size: 11px;");
    outputView->setMinimumHeight(100);
    layout->addWidget(outputView, 1);

    connect(prepareButton, SIGNAL(clicked()), this, SLOT(onPrepare()));
    connect(refreshNotesButton, SIGNAL(clicked()), this, SLOT(onRefreshNotes()));
    connect(releaseNoteButton, SIGNAL(clicked()), this, SLOT(onReleaseNote()));
    connect(joinButton, SIGNAL(clicked()), this, SLOT(onJoin()));

    statusTimer = new QTimer(this);
    connect(statusTimer, SIGNAL(timeout()), this, SLOT(onRefreshStatus()));
    statusTimer->start(5000);
    QTimer::singleShot(0, this, SLOT(onRefreshStatus()));
}

NullSendMixWidget::~NullSendMixWidget()
{
    // The wallet model is gone before the window at exit; a relock through it then
    // would touch freed memory, and the process is ending anyway.
    if (unlockHold && !model)
        (void)unlockHold.release();
}

void NullSendMixWidget::setModel(WalletModel *modelIn)
{
    if (modelIn != model)
        dropUnlockHold();
    model = modelIn;
    onRefreshNotes();
}

void NullSendMixWidget::report(const QString& heading, const QString& body)
{
    const QString stamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    outputView->appendPlainText(QString("[%1] %2").arg(stamp).arg(heading));
    if (!body.isEmpty())
        outputView->appendPlainText(body);
    outputView->appendPlainText(QString());
}

void NullSendMixWidget::dropUnlockHold()
{
    if (!unlockHold)
        return;
    if (model)
        unlockHold.reset();
    else
        (void)unlockHold.release();
}

void NullSendMixWidget::onPrepare()
{
    if (!model)
    {
        report(tr("Prepare"), tr("no wallet is loaded"));
        return;
    }
    const int nIndex = tierCombo->currentIndex();
    const QList<Iv5Rpc::MixTier> tiers = Iv5Rpc::MixTiers();
    if (nIndex < 0 || nIndex >= tiers.size())
        return;
    const Iv5Rpc::MixTier tier = tiers.at(nIndex);
    const QString denom = Iv5Rpc::FormatInn(tier.nDenomination);

    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Prepare a note"),
        tr("This sends %1 INN from the pool to this wallet as one note and holds it for "
           "the %2 INN tier. The transfer pays an ordinary fee, and the note stays held "
           "until a round spends it or you release it.\n\nContinue?")
            .arg(Iv5Rpc::FormatInn(tier.nNoteAmount)).arg(denom),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if (!ctx.isValid())
    {
        report(tr("Prepare"), tr("the wallet stayed locked; nothing was sent"));
        return;
    }

    prepareButton->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QApplication::processEvents();
    QString result;
    QString error;
    const bool fOk = Iv5Rpc::Call("mixprepare", QStringList() << denom, result, error);
    QApplication::restoreOverrideCursor();
    prepareButton->setEnabled(true);
    if (!fOk)
    {
        report(tr("mixprepare %1 failed").arg(denom), error);
        return;
    }
    report(tr("mixprepare %1").arg(denom),
           tr("transaction %1; the note can join a round once it is deep enough to be "
              "inside the round's anchor").arg(result));
    onRefreshNotes();
}

void NullSendMixWidget::onRefreshNotes()
{
    notesList->clear();
    QList<Iv5Rpc::HeldNote> holds;
    QString error;
    if (!Iv5Rpc::FetchHolds(holds, error))
    {
        notesList->addItem(tr("Could not read held notes: %1").arg(error));
        return;
    }
    const QList<Iv5Rpc::MixTier> tiers = Iv5Rpc::MixTiers();
    for (int i = 0; i < holds.size(); i++)
    {
        const Iv5Rpc::HeldNote& note = holds.at(i);
        if (!note.fHaveAmount || note.fSpent)
            continue;
        const qint64 nAmount = (qint64)std::llround(note.dAmount * 100000000.0);
        for (int j = 0; j < tiers.size(); j++)
        {
            if (tiers.at(j).nNoteAmount != nAmount)
                continue;
            QListWidgetItem *item = new QListWidgetItem(
                tr("%1 INN tier  %2").arg(Iv5Rpc::FormatInn(tiers.at(j).nDenomination))
                    .arg(note.strNote));
            item->setData(Qt::UserRole, note.strNote);
            notesList->addItem(item);
            break;
        }
    }
    if (notesList->count() == 0)
        notesList->addItem(tr("No held note of a tier's size. Prepare one above."));
}

void NullSendMixWidget::onReleaseNote()
{
    QListWidgetItem *item = notesList->currentItem();
    const QString note = item ? item->data(Qt::UserRole).toString() : QString();
    if (note.isEmpty())
    {
        QMessageBox::warning(this, tr("Release"), tr("Select a held note first."));
        return;
    }
    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Release"),
        tr("Release %1 back to ordinary spending?\n\nIf this note's final share in a "
           "round has already left, that round's coordinator may still publish a "
           "transaction spending it, and any other spend of the note races it.")
            .arg(note),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    QString result;
    QString error;
    if (!Iv5Rpc::Call("z_holdiv5note", QStringList() << note << "false", result, error))
        report(tr("z_holdiv5note %1 false failed").arg(note), error);
    else
        report(tr("z_holdiv5note %1 false").arg(note), result);
    onRefreshNotes();
}

void NullSendMixWidget::onJoin()
{
    if (!model)
    {
        report(tr("Join"), tr("no wallet is loaded"));
        return;
    }
    const QString key = coordinatorEdit->text().trimmed();
    const QString slotText = recordSlotEdit->text().trimmed();
    bool fSlotOk = false;
    const qint64 nSlot = slotText.toLongLong(&fSlotOk);
    if (!QRegularExpression("^0[23][0-9a-fA-F]{64}$").match(key).hasMatch())
    {
        QMessageBox::warning(this, tr("Join a round"),
                             tr("The coordinator key is a compressed public key: 66 hex "
                                "characters starting 02 or 03."));
        return;
    }
    if (!fSlotOk || nSlot <= 0)
    {
        QMessageBox::warning(this, tr("Join a round"),
                             tr("The record slot is a positive whole number."));
        return;
    }
    if (Iv5Rpc::MixDirectoriesConfigured() == 0)
    {
        QMessageBox::warning(this, tr("Join a round"),
                             tr("No mix directory is configured. Add one or more "
                                "mixdir=<onion>:<port> lines to innova.conf and restart; "
                                "a seat fetches the round's announcement from them."));
        return;
    }

    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Join a round"),
        tr("This takes one seat in record slot %1 of coordinator %2.\n\n"
           "Your prepared note's spend into the round is public; which of the round's "
           "outputs is yours is not, among as many seats as the round has.\n\n"
           "The wallet stays unlocked until the round ends. Join?")
            .arg(nSlot).arg(key.left(16) + "..."),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;

    if (!unlockHold)
    {
        unlockHold.reset(new WalletModel::UnlockContext(model->requestUnlock()));
        if (!unlockHold->isValid())
        {
            unlockHold.reset();
            report(tr("Join"), tr("the wallet stayed locked; no seat was taken"));
            return;
        }
    }

    QString result;
    QString error;
    if (!Iv5Rpc::Call("mixjoin", QStringList() << key << QString::number(nSlot), result, error))
    {
        report(tr("mixjoin failed"), error);
        onRefreshStatus();
        return;
    }
    QString runs;
    Iv5Rpc::ReadField(result, "runs", runs);
    const QDateTime when = QDateTime::fromSecsSinceEpoch(runs.toLongLong());
    report(tr("mixjoin slot %1").arg(nSlot),
           tr("seat taken; the round runs from about %1")
               .arg(when.toString("yyyy-MM-dd hh:mm:ss")));
    onRefreshStatus();
}

void NullSendMixWidget::onRefreshStatus()
{
    Iv5Rpc::MixSnapshot snap;
    QString error;
    if (!Iv5Rpc::FetchMix(snap, error))
    {
        serviceLabel->setText(tr("Could not read the mix service: %1").arg(error));
        return;
    }

    const int nDirs = Iv5Rpc::MixDirectoriesConfigured();
    QString service = nDirs > 0
        ? tr("%n mix directory(ies) configured.", "", nDirs)
        : tr("No mix directory configured: joining needs mixdir=<onion>:<port> in "
             "innova.conf and a restart.");
    if (snap.nRecords > 0 || snap.nDirectoryEntries > 0)
        service += " " + tr("This node's directory holds %1 announcement(s) and indexes %2 "
                            "record(s).").arg(snap.nDirectoryEntries).arg(snap.nRecords);
    serviceLabel->setText(service);

    jobsTable->setRowCount(snap.vJobs.size());
    bool fSeatRunning = false;
    QString outcome;
    for (int i = 0; i < snap.vJobs.size(); i++)
    {
        const Iv5Rpc::MixJob& job = snap.vJobs.at(i);
        const bool fSeat = job.strRole == "seat";
        jobsTable->setItem(i, 0, new QTableWidgetItem(fSeat ? tr("seat") : tr("coordinator")));
        jobsTable->setItem(i, 1, new QTableWidgetItem(
            job.nRecordSlot > 0 ? QString::number(job.nRecordSlot) : tr("not planned")));
        jobsTable->setItem(i, 2, new QTableWidgetItem(job.StateName()));
        QTableWidgetItem *statusItem = new QTableWidgetItem(job.strStatus);
        statusItem->setToolTip(job.strStatus);
        jobsTable->setItem(i, 3, statusItem);
        const bool fNoRound = job.strRound.isEmpty() ||
                              job.strRound.count(QChar('0')) == job.strRound.size();
        jobsTable->setItem(i, 4, new QTableWidgetItem(fNoRound ? QString() : job.strRound));
        if (fSeat && !job.Terminal())
            fSeatRunning = true;
        if (fSeat && job.Terminal())
            outcome = tr("Slot %1: %2. %3").arg(job.nRecordSlot).arg(job.StateName())
                          .arg(job.strStatus);
    }
    jobsTable->resizeColumnsToContents();
    jobsTable->horizontalHeader()->setStretchLastSection(true);
    if (fSeatRunning)
        outcomeLabel->setText(tr("A seat is in progress; keep the wallet unlocked and "
                                 "this node running."));
    else
        outcomeLabel->setText(outcome);

    if (unlockHold && !fSeatRunning)
    {
        dropUnlockHold();
        report(tr("Rounds"), tr("no seat is running; the wallet's unlock for mixing "
                                "was released"));
        onRefreshNotes();
    }
}
