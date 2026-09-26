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
    QFormLayout *settingsForm = new QFormLayout();
    QHBoxLayout *dirRow = new QHBoxLayout();
    directoriesEdit = new QLineEdit();
    directoriesEdit->setPlaceholderText(tr("<onion>:<port>, comma separated"));
    applyDirectoriesButton = new QPushButton(tr("Apply"));
    applyDirectoriesButton->setToolTip(tr(
        "Seats started from now on fetch rounds from these directories. Kept across "
        "restarts in mixsettings.conf, which takes precedence over innova.conf; an empty "
        "field goes back to innova.conf."));
    dirRow->addWidget(directoriesEdit, 1);
    dirRow->addWidget(applyDirectoriesButton);
    settingsForm->addRow(tr("Directories:"), dirRow);
    QHBoxLayout *proxyRow = new QHBoxLayout();
    proxyEdit = new QLineEdit();
    proxyEdit->setPlaceholderText(tr("SOCKS5 proxy, e.g. 127.0.0.1:9050"));
    applyProxyButton = new QPushButton(tr("Apply"));
    applyProxyButton->setToolTip(tr(
        "Every mix exchange goes through this Tor SOCKS proxy; there is no direct "
        "fallback. An empty field goes back to innova.conf or the default."));
    checkProxyButton = new QPushButton(tr("Check"));
    checkProxyButton->setToolTip(tr(
        "Connects to the proxy and reads its SOCKS5 greeting, then closes. No destination "
        "is named."));
    proxyRow->addWidget(proxyEdit, 1);
    proxyRow->addWidget(applyProxyButton);
    proxyRow->addWidget(checkProxyButton);
    settingsForm->addRow(tr("Proxy:"), proxyRow);
    serviceLayout->addLayout(settingsForm);
    proxyLabel = new QLabel();
    proxyLabel->setWordWrap(true);
    serviceLayout->addWidget(proxyLabel);
    fSettingsLoaded = false;
    QLabel *coordHint = new QLabel(tr(
        "Running a round as its coordinator is an operator task: it needs "
        "-mixcoordinatorport, an onion service of its own and a directory, and is started "
        "with the mixcoordinate RPC."));
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

    prepareLayout->addWidget(new QLabel(tr("Notes of a tier's size, and when a round can take them:")));
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
        "Find rounds asks the directories, over Tor and on a circuit of its own, for every "
        "round still open to join; the request carries nothing about this wallet. Pick one, "
        "or enter a coordinator's key and record slot by hand. The seat waits for the record "
        "slot to settle, fetches the announcement, checks it against the chain, and spends a "
        "note of the round's tier. The wallet stays unlocked until the round ends: locking it "
        "stops the seat."));
    joinHint->setWordWrap(true);
    joinHint->setStyleSheet("color: #888;");
    joinForm->addRow(joinHint);
    QHBoxLayout *findRow = new QHBoxLayout();
    findRoundsButton = new QPushButton(tr("Find rounds"));
    findRow->addWidget(findRoundsButton);
    findRow->addStretch();
    joinForm->addRow(findRow);
    roundsTable = new QTableWidget(0, 8);
    roundsTable->setHorizontalHeaderLabels(QStringList() << tr("Tier") << tr("Seats")
                                                         << tr("Starts") << tr("Join closes")
                                                         << tr("Record") << tr("Your notes")
                                                         << tr("Record slot")
                                                         << tr("Coordinator"));
    roundsTable->horizontalHeader()->setStretchLastSection(true);
    roundsTable->verticalHeader()->setVisible(false);
    roundsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    roundsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    roundsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    roundsTable->setMinimumHeight(90);
    joinForm->addRow(roundsTable);
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
    eligibilityLabel = new QLabel();
    eligibilityLabel->setWordWrap(true);
    joinForm->addRow(eligibilityLabel);
    layout->addWidget(joinGroup);

    // --- rounds ---
    QGroupBox *roundsGroup = new QGroupBox(tr("3. Rounds"));
    QVBoxLayout *roundsLayout = new QVBoxLayout(roundsGroup);
    jobsTable = new QTableWidget(0, 8);
    jobsTable->setHorizontalHeaderLabels(QStringList() << tr("Id") << tr("Role")
                                                       << tr("Record slot") << tr("State")
                                                       << tr("Started") << tr("Updated")
                                                       << tr("Status") << tr("Round"));
    jobsTable->horizontalHeader()->setStretchLastSection(true);
    jobsTable->verticalHeader()->setVisible(false);
    jobsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    jobsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    jobsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    jobsTable->setMinimumHeight(120);
    roundsLayout->addWidget(jobsTable);
    QHBoxLayout *jobButtons = new QHBoxLayout();
    cancelSeatButton = new QPushButton(tr("Cancel selected seat"));
    cancelSeatButton->setToolTip(tr(
        "Free before the seat's key image has gone to the coordinator. After that it ends "
        "the round for every seat; after the final share it is refused."));
    clearFinishedButton = new QPushButton(tr("Clear finished"));
    jobButtons->addWidget(cancelSeatButton);
    jobButtons->addWidget(clearFinishedButton);
    jobButtons->addStretch();
    roundsLayout->addLayout(jobButtons);
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
    connect(applyDirectoriesButton, SIGNAL(clicked()), this, SLOT(onApplyDirectories()));
    connect(applyProxyButton, SIGNAL(clicked()), this, SLOT(onApplyProxy()));
    connect(checkProxyButton, SIGNAL(clicked()), this, SLOT(onCheckProxy()));
    connect(findRoundsButton, SIGNAL(clicked()), this, SLOT(onFindRounds()));
    connect(roundsTable, SIGNAL(itemSelectionChanged()), this, SLOT(onRoundSelected()));
    connect(cancelSeatButton, SIGNAL(clicked()), this, SLOT(onCancelSeat()));
    connect(clearFinishedButton, SIGNAL(clicked()), this, SLOT(onClearFinished()));

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
    QList<Iv5Rpc::MixNoteRow> notes;
    QString error;
    if (!Iv5Rpc::FetchMixNotes(QString(), notes, error))
    {
        notesList->addItem(tr("Could not read the notes: %1").arg(error));
        return;
    }
    const QList<Iv5Rpc::MixTier> tiers = Iv5Rpc::MixTiers();
    for (int i = 0; i < notes.size(); i++)
    {
        const Iv5Rpc::MixNoteRow& note = notes.at(i);
        const qint64 nAmount = (qint64)std::llround(note.dAmount * 100000000.0);
        QString tier;
        for (int j = 0; j < tiers.size(); j++)
            if (tiers.at(j).nNoteAmount == nAmount)
                tier = Iv5Rpc::FormatInn(tiers.at(j).nDenomination);
        QString when;
        if (!note.fUsable)
            when = note.strReason;
        else if (note.nEligibleInBlocks > 0 && note.nEligibleTime > 0)
            when = tr("a round's anchor covers it from height %1, about %2")
                       .arg(note.nEligibleHeight)
                       .arg(QDateTime::fromSecsSinceEpoch(note.nEligibleTime)
                                .toString("yyyy-MM-dd hh:mm"));
        else if (note.nEligibleInBlocks > 0)
            when = tr("a round's anchor covers it from height %1").arg(note.nEligibleHeight);
        else
            when = tr("ready for a round planned from now on");
        QListWidgetItem *item = new QListWidgetItem(
            tr("%1 INN tier%2  %3  -  %4")
                .arg(tier)
                .arg(note.fPrepared ? tr(" (prepared)") : QString())
                .arg(note.strNote)
                .arg(when));
        item->setData(Qt::UserRole, note.strNote);
        item->setToolTip(when);
        notesList->addItem(item);
    }
    if (notesList->count() == 0)
        notesList->addItem(tr("No note of a tier's size. Prepare one above."));
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
                             tr("No mix directory is configured. Enter one or more under "
                                "Directories above and press Apply; a seat fetches the "
                                "round's announcement from them."));
        return;
    }

    // Every exchange goes through the proxy, and a seat whose proxy is down fails only when
    // its first exchange times out.
    Iv5Rpc::MixProxyView proxy;
    QString proxyError;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    const bool fProbed = Iv5Rpc::FetchMixProxy(proxy, proxyError);
    QApplication::restoreOverrideCursor();
    if (!fProbed || !proxy.fReady)
    {
        const QString why = fProbed ? proxy.strError : proxyError;
        proxyLabel->setText(tr("Proxy %1 is not ready: %2").arg(proxy.strProxy).arg(why));
        QMessageBox::warning(this, tr("Join a round"),
                             tr("The mix proxy %1 (%2) is not ready: %3\n\nEvery exchange of "
                                "a round goes through it and there is no direct fallback. "
                                "Start Tor, or set the proxy under Proxy above, then join.")
                                 .arg(proxy.strProxy).arg(proxy.strSource).arg(why));
        return;
    }

    const int nListed = listedRoundIndex();
    const QString noNote = whyNoNote(nListed >= 0 ? vListedRounds.at(nListed).strRound
                                                  : QString());
    if (!noNote.isEmpty())
    {
        eligibilityLabel->setText(noNote);
        QMessageBox::warning(this, tr("Join a round"), noNote);
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

    if (!fSettingsLoaded)
        refreshSettings();
    const int nDirs = snap.nDirectories;
    QString service = nDirs > 0
        ? tr("%n mix directory(ies) configured.", "", nDirs)
        : tr("No mix directory configured: joining needs one; enter it under Directories "
             "below.");
    if (snap.nRecords > 0 || snap.nDirectoryEntries > 0)
        service += " " + tr("This node's directory holds %1 announcement(s) and indexes %2 "
                            "record(s).").arg(snap.nDirectoryEntries).arg(snap.nRecords);
    serviceLabel->setText(service);

    const int nSelectedRow = jobsTable->currentRow();
    jobsTable->setRowCount(snap.vJobs.size());
    bool fSeatRunning = false;
    QString outcome;
    for (int i = 0; i < snap.vJobs.size(); i++)
    {
        const Iv5Rpc::MixJob& job = snap.vJobs.at(i);
        const bool fSeat = job.strRole == "seat";
        jobsTable->setItem(i, 0, new QTableWidgetItem(fSeat ? QString::number(job.nId)
                                                            : QString()));
        QTableWidgetItem *roleItem =
            new QTableWidgetItem(fSeat ? tr("seat") : tr("coordinator"));
        roleItem->setData(Qt::UserRole, job.strRole);
        jobsTable->setItem(i, 1, roleItem);
        jobsTable->setItem(i, 2, new QTableWidgetItem(
            job.nRecordSlot > 0 ? QString::number(job.nRecordSlot) : tr("not planned")));
        QString stateName = job.StateName();
        if (job.fCancelled)
            stateName = tr("cancelled");
        else if (job.fCancelPending)
            stateName += tr(" (cancelling)");
        jobsTable->setItem(i, 3, new QTableWidgetItem(stateName));
        jobsTable->setItem(i, 4, new QTableWidgetItem(
            job.nStarted > 0 ? QDateTime::fromSecsSinceEpoch(job.nStarted).toString("hh:mm:ss")
                             : QString()));
        jobsTable->setItem(i, 5, new QTableWidgetItem(
            job.nUpdated > 0 ? QDateTime::fromSecsSinceEpoch(job.nUpdated).toString("hh:mm:ss")
                             : QString()));
        QTableWidgetItem *statusItem = new QTableWidgetItem(job.strStatus);
        statusItem->setToolTip(job.strStatus);
        jobsTable->setItem(i, 6, statusItem);
        const bool fNoRound = job.strRound.isEmpty() ||
                              job.strRound.count(QChar('0')) == job.strRound.size();
        jobsTable->setItem(i, 7, new QTableWidgetItem(fNoRound ? QString() : job.strRound));
        if (fSeat && !job.Terminal())
            fSeatRunning = true;
        if (fSeat && job.Terminal())
            outcome = tr("Slot %1: %2. %3").arg(job.nRecordSlot).arg(job.StateName())
                          .arg(job.strStatus);
    }
    jobsTable->resizeColumnsToContents();
    jobsTable->horizontalHeader()->setStretchLastSection(true);
    if (nSelectedRow >= 0 && nSelectedRow < jobsTable->rowCount())
        jobsTable->selectRow(nSelectedRow);
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

void NullSendMixWidget::refreshSettings()
{
    Iv5Rpc::MixSettingsView settings;
    QString error;
    if (!Iv5Rpc::FetchMixSettings(settings, error))
    {
        proxyLabel->setText(tr("Could not read the mix settings: %1").arg(error));
        return;
    }
    // Filled once, so a poll does not overwrite what the user is typing.
    if (!fSettingsLoaded)
    {
        directoriesEdit->setText(settings.vDirectories.join(", "));
        proxyEdit->setText(settings.strProxy);
        fSettingsLoaded = true;
    }
    QString text = tr("Proxy in use: %1 (%2).").arg(settings.strProxy)
                       .arg(settings.strProxySource);
    if (settings.fRestartRequired)
        text += " " + tr("Some settings take effect at the next start.");
    if (!settings.fRunning)
        text += " " + tr("The mix service is not running.");
    proxyLabel->setText(text);
}

bool NullSendMixWidget::applySetting(const QString& name, const QString& value)
{
    QString result;
    QString error;
    if (!Iv5Rpc::Call("mixsetsetting", QStringList() << name << value, result, error))
    {
        report(tr("mixsetsetting %1 failed").arg(name), error);
        QMessageBox::warning(this, tr("Mix settings"), error);
        return false;
    }
    report(tr("mixsetsetting %1").arg(name), result);
    fSettingsLoaded = false;
    refreshSettings();
    onRefreshStatus();
    return true;
}

void NullSendMixWidget::onApplyDirectories()
{
    applySetting("mixdir", directoriesEdit->text().trimmed());
}

void NullSendMixWidget::onApplyProxy()
{
    if (applySetting("mixproxy", proxyEdit->text().trimmed()))
        onCheckProxy();
}

void NullSendMixWidget::onCheckProxy()
{
    Iv5Rpc::MixProxyView proxy;
    QString error;
    checkProxyButton->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QApplication::processEvents();
    const bool fOk = Iv5Rpc::FetchMixProxy(proxy, error);
    QApplication::restoreOverrideCursor();
    checkProxyButton->setEnabled(true);
    if (!fOk)
    {
        proxyLabel->setText(tr("Could not check the proxy: %1").arg(error));
        return;
    }
    if (proxy.fReady)
        proxyLabel->setText(tr("Proxy %1 (%2) is ready: SOCKS5 with per-exchange "
                               "credentials, answered in %3 ms.")
                                .arg(proxy.strProxy).arg(proxy.strSource)
                                .arg(proxy.nLatencyMs));
    else
        proxyLabel->setText(tr("Proxy %1 (%2) is not ready: %3")
                                .arg(proxy.strProxy).arg(proxy.strSource)
                                .arg(proxy.strError));
}

void NullSendMixWidget::onFindRounds()
{
    findRoundsButton->setEnabled(false);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QApplication::processEvents();
    QList<Iv5Rpc::MixRoundRow> rounds;
    QStringList failures;
    QString error;
    const bool fOk = Iv5Rpc::FetchMixRounds(rounds, failures, error);
    QApplication::restoreOverrideCursor();
    findRoundsButton->setEnabled(true);
    if (!fOk)
    {
        report(tr("mixlistrounds failed"), error);
        eligibilityLabel->setText(tr("Could not list rounds: %1").arg(error));
        return;
    }
    vListedRounds = rounds;
    roundsTable->setRowCount(rounds.size());
    for (int i = 0; i < rounds.size(); i++)
    {
        const Iv5Rpc::MixRoundRow& r = rounds.at(i);
        const qint64 nDenom = (qint64)std::llround(r.dDenomination * 100000000.0);
        roundsTable->setItem(i, 0, new QTableWidgetItem(tr("%1 INN").arg(Iv5Rpc::FormatInn(nDenom))));
        roundsTable->setItem(i, 1, new QTableWidgetItem(QString::number(r.nSeats)));
        roundsTable->setItem(i, 2, new QTableWidgetItem(
            QDateTime::fromSecsSinceEpoch(r.nStarts).toString("hh:mm:ss")));
        roundsTable->setItem(i, 3, new QTableWidgetItem(
            QDateTime::fromSecsSinceEpoch(r.nJoinCloses).toString("hh:mm:ss")));
        QTableWidgetItem *record = new QTableWidgetItem(r.strRecord);
        record->setToolTip(tr("What this node's chain says about the coordinator's record: "
                              "settled and matching, pending (not settled yet; the seat "
                              "waits for it), none, or another round."));
        roundsTable->setItem(i, 4, record);
        roundsTable->setItem(i, 5, new QTableWidgetItem(QString::number(r.nEligibleNotes)));
        roundsTable->setItem(i, 6, new QTableWidgetItem(QString::number(r.nRecordSlot)));
        QTableWidgetItem *coord = new QTableWidgetItem(r.strCoordinator);
        coord->setToolTip(tr("Listed by %1").arg(r.vDirectories.join(", ")));
        roundsTable->setItem(i, 7, coord);
    }
    roundsTable->resizeColumnsToContents();
    roundsTable->horizontalHeader()->setStretchLastSection(true);
    QString body = tr("%n round(s) open to join.", "", rounds.size());
    if (!failures.isEmpty())
        body += "\n" + tr("Directories that did not answer: %1").arg(failures.join("; "));
    report(tr("mixlistrounds"), body);
    eligibilityLabel->setText(rounds.isEmpty() ? tr("No round is open to join right now.")
                                               : tr("Select a round to see whether a note "
                                                    "can take a seat in it."));
    onRefreshNotes();
}

void NullSendMixWidget::onRoundSelected()
{
    const QList<QTableWidgetItem*> selected = roundsTable->selectedItems();
    if (selected.isEmpty())
        return;
    const int nRow = selected.first()->row();
    if (nRow < 0 || nRow >= vListedRounds.size())
        return;
    const Iv5Rpc::MixRoundRow& r = vListedRounds.at(nRow);
    coordinatorEdit->setText(r.strCoordinator);
    recordSlotEdit->setText(QString::number(r.nRecordSlot));
    const QString why = whyNoNote(r.strRound);
    if (!why.isEmpty())
        eligibilityLabel->setText(why);
    else if (!r.fJoinable)
        eligibilityLabel->setText(tr("A note can take a seat, but this node's chain does not "
                                     "show the round's record as %1; the seat will refuse "
                                     "it.").arg(tr("settled or pending")));
    else
        eligibilityLabel->setText(tr("A note can take a seat in this round."));
}

int NullSendMixWidget::listedRoundIndex() const
{
    const QString key = coordinatorEdit->text().trimmed().toLower();
    const qint64 nSlot = recordSlotEdit->text().trimmed().toLongLong();
    for (int i = 0; i < vListedRounds.size(); i++)
        if (vListedRounds.at(i).strCoordinator.toLower() == key &&
            vListedRounds.at(i).nRecordSlot == nSlot)
            return i;
    return -1;
}

QString NullSendMixWidget::whyNoNote(const QString& strRound) const
{
    QList<Iv5Rpc::MixNoteRow> notes;
    QString error;
    if (!Iv5Rpc::FetchMixNotes(strRound, notes, error))
        return tr("Could not check the notes: %1").arg(error);
    QStringList reasons;
    qint64 nSoonest = 0;
    for (int i = 0; i < notes.size(); i++)
    {
        const Iv5Rpc::MixNoteRow& note = notes.at(i);
        if (strRound.isEmpty() ? note.fUsable : note.fEligible)
            return QString();
        const QString why = strRound.isEmpty() || note.strRoundReason.isEmpty()
                                ? note.strReason : note.strRoundReason;
        if (!why.isEmpty() && !reasons.contains(why))
            reasons << why;
        if (note.fUsable && note.nEligibleTime > 0 &&
            (nSoonest == 0 || note.nEligibleTime < nSoonest))
            nSoonest = note.nEligibleTime;
    }
    if (notes.isEmpty())
        return tr("No note of a tier's size is in this wallet. Prepare one first; a round "
                  "can take it once its epoch is built and the round's anchor covers it.");
    QString text = tr("No note can take a seat %1: %2.")
                       .arg(strRound.isEmpty() ? tr("yet") : tr("in this round"))
                       .arg(reasons.join("; "));
    if (nSoonest > 0)
        text += " " + tr("A round planned after about %1 can take one.")
                          .arg(QDateTime::fromSecsSinceEpoch(nSoonest)
                                   .toString("yyyy-MM-dd hh:mm"));
    return text;
}

void NullSendMixWidget::onCancelSeat()
{
    const QList<QTableWidgetItem*> selected = jobsTable->selectedItems();
    if (selected.isEmpty())
    {
        QMessageBox::warning(this, tr("Cancel a seat"), tr("Select a seat first."));
        return;
    }
    const int nRow = selected.first()->row();
    QTableWidgetItem *idItem = jobsTable->item(nRow, 0);
    QTableWidgetItem *roleItem = jobsTable->item(nRow, 1);
    if (!idItem || !roleItem || roleItem->data(Qt::UserRole).toString() != "seat")
    {
        QMessageBox::warning(this, tr("Cancel a seat"),
                             tr("Only a seat can be cancelled here; a coordinator's round "
                                "runs to its end."));
        return;
    }
    const QString id = idItem->text();
    if (QMessageBox::question(this, tr("Cancel a seat"),
                              tr("Cancel seat %1? Before its key image has gone out this costs "
                                 "nothing and the note goes back to held.").arg(id),
                              QMessageBox::Yes | QMessageBox::No, QMessageBox::No) !=
        QMessageBox::Yes)
        return;
    QString result;
    QString error;
    if (!Iv5Rpc::Call("mixcancel", QStringList() << id, result, error))
    {
        if (!error.contains("force"))
        {
            report(tr("mixcancel %1 refused").arg(id), error);
            QMessageBox::warning(this, tr("Cancel a seat"), error);
            onRefreshStatus();
            return;
        }
        const QMessageBox::StandardButton reply = QMessageBox::warning(
            this, tr("Cancel a seat"),
            tr("This seat's key image has already gone to the round's coordinator. "
               "Cancelling now does not take it back, and the round then ends for every "
               "seat in it.\n\nCancel anyway?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (reply != QMessageBox::Yes)
            return;
        if (!Iv5Rpc::Call("mixcancel", QStringList() << id << "true", result, error))
        {
            report(tr("mixcancel %1 true refused").arg(id), error);
            QMessageBox::warning(this, tr("Cancel a seat"), error);
            onRefreshStatus();
            return;
        }
    }
    report(tr("mixcancel %1").arg(id), result);
    onRefreshStatus();
    onRefreshNotes();
}

void NullSendMixWidget::onClearFinished()
{
    QString result;
    QString error;
    if (!Iv5Rpc::Call("mixclear", QStringList(), result, error))
        report(tr("mixclear failed"), error);
    else
        report(tr("mixclear"), result);
    onRefreshStatus();
}
