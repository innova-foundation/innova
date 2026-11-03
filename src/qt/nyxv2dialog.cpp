#include "nyxv2dialog.h"

#include "innovarpc.h"
#include "json/json_spirit_writer_template.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QSettings>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextBrowser>
#include <QTextEdit>
#include <QVBoxLayout>

using namespace json_spirit;

namespace {

const Value& Get(const Value& v, const char* k)
{
    static const Value null;
    if (v.type() != obj_type)
        return null;
    const Object& o = v.get_obj();
    for (size_t i = 0; i < o.size(); ++i)
        if (o[i].name_ == k)
            return o[i].value_;
    return null;
}

QString Str(const Value& v, const char* k)
{
    const Value& x = Get(v, k);
    if (x.type() == str_type)
        return QString::fromStdString(x.get_str());
    if (x.type() == int_type)
        return QString::number((qlonglong)x.get_int64());
    return QString();
}

bool Bool(const Value& v, const char* k)
{
    const Value& x = Get(v, k);
    return x.type() == bool_type && x.get_bool();
}

qint64 Int(const Value& v, const char* k)
{
    const Value& x = Get(v, k);
    return x.type() == int_type ? (qint64)x.get_int64() : 0;
}

QWidget* Banner(const QString& colour, QLabel*& text, QPushButton* button = 0)
{
    QWidget* w = new QWidget();
    w->setObjectName("nyxBanner");
    w->setAttribute(Qt::WA_StyledBackground, true);
    w->setStyleSheet(QString("#nyxBanner { background-color: %1; border-radius: 6px; }"
                             "#nyxBanner QLabel { color: white; background: transparent; }").arg(colour));
    QHBoxLayout* l = new QHBoxLayout(w);
    text = new QLabel();
    text->setWordWrap(true);
    text->setTextInteractionFlags(Qt::TextSelectableByMouse);
    l->addWidget(text, 1);
    if (button)
        l->addWidget(button);
    w->hide();
    return w;
}

QString Esc(const QString& s)
{
    return s.toHtmlEscaped();
}

} // namespace

bool NyxV2Dialog::Call(const QStringList& params, Value& out, QString& err)
{
    Array a;
    for (int i = 0; i < params.size(); ++i)
        a.push_back(params[i].toStdString());
    try
    {
        out = tableRPC.execute("nyx", a);
        return true;
    }
    catch (Object& e)
    {
        err = Str(Value(e), "message");
        if (err.isEmpty())
            err = tr("the node refused the call");
    }
    catch (std::exception& e)
    {
        err = QString::fromStdString(e.what());
    }
    return false;
}

NyxV2Dialog::NyxV2Dialog(QWidget *parent) : QDialog(parent)
{
    setWindowTitle(tr("Nyx v2 secure sessions"));
    resize(860, 640);
    QVBoxLayout* root = new QVBoxLayout(this);

    QHBoxLayout* top = new QHBoxLayout();
    top->addWidget(new QLabel(tr("My address:")));
    addrEdit = new QLineEdit();
    addrEdit->setPlaceholderText(tr("Wallet address that owns this identity"));
    addrEdit->setText(QSettings().value("nyxv2/address").toString());
    top->addWidget(addrEdit, 1);
    top->addWidget(new QLabel(tr("Keys:")));
    modeBox = new QComboBox();
    modeBox->addItem(tr("Post-quantum (ML-KEM-768 + ML-DSA-65)"), "pq");
    modeBox->addItem(tr("Classical (X25519 + Ed25519)"), "classical");
    modeBox->setToolTip(tr("Applies to new identities and new devices. Post-quantum is recommended."));
    top->addWidget(modeBox);
    QPushButton* load = new QPushButton(tr("Load"));
    top->addWidget(load);
    root->addLayout(top);

    tabs = new QTabWidget();
    root->addWidget(tabs, 1);

    // Identity and devices
    {
        QWidget* page = new QWidget();
        QVBoxLayout* l = new QVBoxLayout(page);
        QPushButton* confirm = new QPushButton(tr("This device is the real one"));
        alarmBanner = Banner("#b3261e", alarmText, confirm);
        l->addWidget(alarmBanner);
        idStatus = new QLabel();
        idStatus->setWordWrap(true);
        idStatus->setTextFormat(Qt::PlainText);
        l->addWidget(idStatus);
        ownSafety = new QLabel();
        ownSafety->setTextFormat(Qt::PlainText);
        ownSafety->setTextInteractionFlags(Qt::TextSelectableByMouse);
        ownSafety->setStyleSheet("font-family: monospace; font-size: 14px;");
        l->addWidget(ownSafety);
        deviceTable = new QTableWidget(0, 5);
        deviceTable->setHorizontalHeaderLabels(QStringList() << tr("Device") << tr("This node") << tr("Usable")
                                                             << tr("Expires") << tr("Cert hash"));
        deviceTable->horizontalHeader()->setStretchLastSection(true);
        deviceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        deviceTable->setSelectionMode(QAbstractItemView::SingleSelection);
        deviceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        l->addWidget(deviceTable, 1);
        QHBoxLayout* b = new QHBoxLayout();
        QPushButton* init = new QPushButton(tr("Create identity"));
        QPushButton* reset = new QPushButton(tr("Reset identity..."));
        QPushButton* revoke = new QPushButton(tr("Revoke selected device"));
        b->addWidget(init);
        b->addWidget(reset);
        b->addStretch();
        b->addWidget(revoke);
        l->addLayout(b);
        l->addWidget(new QLabel(tr("Add a device: pair on the new node, approve the request on an existing "
                                   "device, then install the returned cert on the new node.")));
        pairText = new QTextEdit();
        pairText->setPlaceholderText(tr("Pairing request or approved cert (hex)"));
        pairText->setMaximumHeight(80);
        l->addWidget(pairText);
        QHBoxLayout* p = new QHBoxLayout();
        QPushButton* pair = new QPushButton(tr("1. Pair this node"));
        QPushButton* approve = new QPushButton(tr("2. Approve request"));
        QPushButton* install = new QPushButton(tr("3. Install cert"));
        p->addWidget(pair);
        p->addWidget(approve);
        p->addWidget(install);
        p->addStretch();
        l->addLayout(p);
        tabs->addTab(page, tr("Identity and devices"));
        connect(init, SIGNAL(clicked()), this, SLOT(onInit()));
        connect(reset, SIGNAL(clicked()), this, SLOT(onReset()));
        connect(confirm, SIGNAL(clicked()), this, SLOT(onConfirm()));
        connect(revoke, SIGNAL(clicked()), this, SLOT(onRevoke()));
        connect(pair, SIGNAL(clicked()), this, SLOT(onPair()));
        connect(approve, SIGNAL(clicked()), this, SLOT(onApprove()));
        connect(install, SIGNAL(clicked()), this, SLOT(onInstall()));
    }

    // Contact verification
    {
        QWidget* page = new QWidget();
        QVBoxLayout* l = new QVBoxLayout(page);
        QHBoxLayout* h = new QHBoxLayout();
        contactEdit = new QLineEdit();
        contactEdit->setPlaceholderText(tr("Contact address"));
        QPushButton* verify = new QPushButton(tr("Fetch and verify"));
        h->addWidget(contactEdit, 1);
        h->addWidget(verify);
        connect(contactEdit, SIGNAL(textChanged(QString)), this, SLOT(clearContact()));
        l->addLayout(h);
        QLabel* frozenText;
        frozenBanner = Banner("#b3261e", frozenText);
        frozenText->setText(tr("<b>Address frozen.</b> Two different keyrings were published for this address at "
                               "the same sequence. Nothing is sent to it until its owner confirms on exactly one "
                               "device."));
        l->addWidget(frozenBanner);
        QPushButton* accept = new QPushButton(tr("Accept new identity"));
        resetBanner = Banner("#a15c00", resetText, accept);
        l->addWidget(resetBanner);
        downgradeBox = new QCheckBox(tr("Allow the reset to replace post-quantum keys with classical ones"));
        downgradeBox->hide();
        l->addWidget(downgradeBox);
        contactStatus = new QLabel();
        contactStatus->setWordWrap(true);
        contactStatus->setTextFormat(Qt::PlainText);
        l->addWidget(contactStatus);
        contactSafety = new QLabel();
        contactSafety->setTextFormat(Qt::PlainText);
        contactSafety->setTextInteractionFlags(Qt::TextSelectableByMouse);
        contactSafety->setStyleSheet("font-family: monospace; font-size: 14px;");
        l->addWidget(contactSafety);
        l->addWidget(new QLabel(tr("Compare the safety number with your contact over another channel. It "
                                   "changes when their devices change.")));
        l->addStretch();
        tabs->addTab(page, tr("Contacts"));
        connect(verify, SIGNAL(clicked()), this, SLOT(onVerifyContact()));
        connect(accept, SIGNAL(clicked()), this, SLOT(onAcceptReset()));
    }

    // Threads
    {
        QWidget* page = new QWidget();
        QHBoxLayout* l = new QHBoxLayout(page);
        QSplitter* split = new QSplitter();
        QWidget* left = new QWidget();
        QVBoxLayout* ll = new QVBoxLayout(left);
        ll->setContentsMargins(0, 0, 0, 0);
        threadList = new QListWidget();
        ll->addWidget(threadList, 1);
        QHBoxLayout* lb = new QHBoxLayout();
        QPushButton* newDirect = new QPushButton(tr("New chat"));
        QPushButton* newGroup = new QPushButton(tr("New group"));
        QPushButton* refresh = new QPushButton(tr("Refresh"));
        lb->addWidget(newDirect);
        lb->addWidget(newGroup);
        lb->addWidget(refresh);
        ll->addLayout(lb);
        split->addWidget(left);
        QWidget* right = new QWidget();
        QVBoxLayout* rl = new QVBoxLayout(right);
        rl->setContentsMargins(0, 0, 0, 0);
        threadInfo = new QLabel();
        threadInfo->setWordWrap(true);
        threadInfo->setTextFormat(Qt::PlainText);
        rl->addWidget(threadInfo);
        threadView = new QTextBrowser();
        rl->addWidget(threadView, 1);
        QHBoxLayout* g = new QHBoxLayout();
        QPushButton* add = new QPushButton(tr("Add member"));
        QPushButton* rem = new QPushButton(tr("Remove member"));
        QPushButton* leave = new QPushButton(tr("Leave group"));
        g->addWidget(add);
        g->addWidget(rem);
        g->addWidget(leave);
        g->addStretch();
        rl->addLayout(g);
        QHBoxLayout* c = new QHBoxLayout();
        composer = new QLineEdit();
        composer->setPlaceholderText(tr("Message"));
        QPushButton* send = new QPushButton(tr("Send"));
        c->addWidget(composer, 1);
        c->addWidget(send);
        rl->addLayout(c);
        split->addWidget(right);
        split->setStretchFactor(1, 3);
        l->addWidget(split);
        tabs->addTab(page, tr("Chats"));
        connect(threadList, SIGNAL(itemSelectionChanged()), this, SLOT(onThreadSelected()));
        connect(refresh, SIGNAL(clicked()), this, SLOT(refreshThreads()));
        connect(send, SIGNAL(clicked()), this, SLOT(onSend()));
        connect(composer, SIGNAL(returnPressed()), this, SLOT(onSend()));
        connect(newGroup, SIGNAL(clicked()), this, SLOT(onGroupCreate()));
        connect(newDirect, &QPushButton::clicked, this, [this]() {
            bool ok = false;
            QString peer = QInputDialog::getText(this, tr("New chat"), tr("Contact address:"),
                                                 QLineEdit::Normal, QString(), &ok).trimmed();
            if (!ok || peer.isEmpty())
                return;
            QListWidgetItem* it = new QListWidgetItem(peer, threadList);
            it->setData(Qt::UserRole, "peer");
            it->setData(Qt::UserRole + 1, peer);
            threadList->setCurrentItem(it);
        });
        connect(add, &QPushButton::clicked, this, [this]() { onGroupMember("groupadd"); });
        connect(rem, &QPushButton::clicked, this, [this]() { onGroupMember("groupremove"); });
        connect(leave, &QPushButton::clicked, this, [this]() { onGroupMember("groupleave"); });
    }

    resultView = new QTextBrowser();
    resultView->setMaximumHeight(90);
    root->addWidget(resultView);

    connect(load, SIGNAL(clicked()), this, SLOT(refreshIdentity()));
    connect(addrEdit, SIGNAL(returnPressed()), this, SLOT(refreshIdentity()));
    if (!addrEdit->text().isEmpty())
        refreshIdentity();
}

QString NyxV2Dialog::self() const
{
    return addrEdit->text().trimmed();
}

QString NyxV2Dialog::mode() const
{
    return modeBox->currentData().toString();
}

bool NyxV2Dialog::run(const QStringList& params, Value& out)
{
    QString err;
    if (Call(params, out, err))
        return true;
    resultView->setPlainText(tr("Error: %1").arg(err));
    return false;
}

void NyxV2Dialog::showResult(const Value& v)
{
    resultView->setPlainText(QString::fromStdString(write_string(v, true)));
}

void NyxV2Dialog::refreshIdentity()
{
    if (self().isEmpty())
        return;
    QSettings().setValue("nyxv2/address", self());
    Value v;
    alarmBanner->hide();
    deviceTable->setRowCount(0);
    ownSafety->clear();
    if (!run(QStringList() << "keyring" << "show" << self(), v))
    {
        idStatus->setText(tr("No Nyx v2 identity on this node for this address. Create one, or pair this node "
                             "with an existing device."));
        return;
    }
    const Value& kr = Get(v, "keyring");
    QString s = tr("Device %1 (%2), %3.").arg(Str(v, "device"), Str(v, "device_mode"),
                                              Bool(v, "paired") ? tr("paired") : tr("not yet paired"));
    if (kr.type() == obj_type)
        s += " " + tr("Keyring epoch %1, sequence %2, %3 keys.").arg(Str(kr, "epoch"), Str(kr, "seq"),
                                                                    Str(kr, "mode"));
    idStatus->setText(s);
    if (kr.type() == obj_type)
        ownSafety->setText(tr("Your safety number: %1").arg(Str(kr, "safety_number")));
    const Value& tip = Get(v, "network_tip");
    if (Bool(v, "clone_alarm") || Bool(tip, "conflict"))
    {
        alarmText->setText(Bool(v, "clone_alarm")
                               ? tr("<b>Another node is sending with this device's keys.</b> %1 If this node is "
                                    "the real one, confirm it; it gets fresh keys.").arg(Esc(Str(v, "alarm_reason")))
                               : tr("<b>Keyring conflict.</b> Two keyrings exist for your address at the same "
                                    "sequence and contacts have frozen it. Confirm on exactly one device."));
        alarmBanner->show();
    }

    Value d;
    QString err;
    if (Call(QStringList() << "devices" << self(), d, err) && d.type() == array_type)
    {
        const Array& a = d.get_array();
        deviceTable->setRowCount(a.size());
        for (size_t i = 0; i < a.size(); ++i)
        {
            qint64 exp = Int(a[i], "expiry");
            QStringList cols;
            cols << Str(a[i], "device") << (Bool(a[i], "this_node") ? tr("yes") : QString())
                 << (Bool(a[i], "usable") ? tr("yes") : tr("no"))
                 << (exp ? QDateTime::fromSecsSinceEpoch(exp).toString(Qt::ISODate) : QString())
                 << Str(a[i], "cert_hash");
            for (int c = 0; c < cols.size(); ++c)
                deviceTable->setItem(i, c, new QTableWidgetItem(cols[c]));
        }
        deviceTable->resizeColumnsToContents();
    }
    refreshThreads();
}

void NyxV2Dialog::onInit()
{
    Value v;
    if (run(QStringList() << "keyring" << "init" << self() << mode(), v))
    {
        showResult(v);
        refreshIdentity();
    }
}

void NyxV2Dialog::onReset()
{
    if (QMessageBox::warning(this, tr("Reset identity"),
                             tr("This replaces every device of %1 with a new one on this node. Every contact "
                                "sees an identity reset warning and must accept it before you can talk again. "
                                "Other devices stop working.\n\nOnly do this if you lost your devices.").arg(self()),
                             QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;
    Value v;
    if (run(QStringList() << "keyring" << "reset" << self() << mode(), v))
    {
        showResult(v);
        refreshIdentity();
    }
}

void NyxV2Dialog::onConfirm()
{
    if (QMessageBox::question(this, tr("Confirm this device"),
                              tr("Confirm on one device only. The others lose this identity."),
                              QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;
    Value v;
    if (run(QStringList() << "keyring" << "confirm" << self(), v))
    {
        showResult(v);
        refreshIdentity();
    }
}

void NyxV2Dialog::onPair()
{
    Value v;
    if (!run(QStringList() << "device" << "pair" << self() << mode(), v))
        return;
    pairText->setPlainText(Str(v, "request"));
    resultView->setPlainText(tr("Pairing code %1. Check that the approving device shows the same code. "
                                "Copy the request above to it.").arg(Str(v, "pairing_code")));
}

void NyxV2Dialog::onApprove()
{
    const QString req = pairText->toPlainText().trimmed();
    if (req.isEmpty())
        return;
    Value v;
    if (!run(QStringList() << "device" << "code" << req, v))
        return;
    bool fOk = false;
    const QString typed = QInputDialog::getText(
        this, tr("Approve device"),
        tr("This request has pairing code:\n%1\n\nType the code shown on the new device. Approve only if they "
           "match.").arg(Str(v, "pairing_code")),
        QLineEdit::Normal, QString(), &fOk).trimmed();
    if (!fOk || typed.isEmpty())
        return;
    if (!run(QStringList() << "device" << "approve" << self() << req << typed, v))
        return;
    pairText->setPlainText(Str(v, "cert"));
    resultView->setPlainText(tr("Approved. Copy the cert above to the new node and install it there."));
    refreshIdentity();
}

void NyxV2Dialog::onInstall()
{
    const QString cert = pairText->toPlainText().trimmed();
    if (cert.isEmpty())
        return;
    Value v;
    if (run(QStringList() << "device" << "install" << self() << cert, v))
    {
        showResult(v);
        pairText->clear();
        refreshIdentity();
    }
}

void NyxV2Dialog::onRevoke()
{
    QList<QTableWidgetItem*> sel = deviceTable->selectedItems();
    if (sel.isEmpty())
        return;
    const QString dev = deviceTable->item(sel.first()->row(), 0)->text();
    if (QMessageBox::warning(this, tr("Revoke device"), tr("Remove device %1 from this identity?").arg(dev),
                             QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;
    Value v;
    if (run(QStringList() << "device" << "revoke" << self() << dev, v))
    {
        showResult(v);
        refreshIdentity();
    }
}

void NyxV2Dialog::clearContact()
{
    frozenBanner->hide();
    resetBanner->hide();
    downgradeBox->hide();
    downgradeBox->setChecked(false);
    contactStatus->clear();
    contactSafety->clear();
    resetText->clear();
    shownContact.clear();
    shownResetHash.clear();
}

void NyxV2Dialog::onVerifyContact()
{
    const QString c = contactEdit->text().trimmed();
    clearContact();
    if (c.isEmpty())
        return;
    Value v;
    if (!run(QStringList() << "keyring" << "contact" << c, v))
    {
        contactStatus->setText(tr("No verified keyring found for this address."));
        return;
    }
    showResult(v);
    QString s = Bool(v, "can_send") ? tr("Verified. Messages to this contact are end-to-end encrypted.")
                                    : tr("Sending to this contact is blocked.");
    const Value& kr = Get(v, "keyring");
    if (kr.type() == obj_type)
        s += " " + tr("Epoch %1, %2 keys.").arg(Str(kr, "epoch"), Str(kr, "mode"));
    contactStatus->setText(s);
    if (!Str(v, "safety_number").isEmpty())
        contactSafety->setText(tr("Safety number: %1").arg(Str(v, "safety_number")));
    if (Bool(v, "frozen"))
        frozenBanner->show();
    if (Bool(v, "reset_pending"))
    {
        const Value& r = Get(v, "reset");
        const bool fDown = Str(kr, "mode") == "pq" && Str(r, "mode") == "classical";
        resetText->setText(tr("<b>Identity reset.</b> Every device of this address was replaced. This is what a "
                              "stolen wallet key looks like. Compare the new safety number with the owner "
                              "before accepting.<br>New safety number: <tt>%1</tt>%2")
                               .arg(Esc(Str(r, "new_safety_number")),
                                    fDown ? tr("<br><b>The new keys are classical, not post-quantum.</b>") : QString()));
        downgradeBox->setVisible(fDown);
        downgradeBox->setChecked(false);
        shownContact = c;
        shownResetHash = Str(r, "keyring_hash");
        resetBanner->setVisible(!shownResetHash.isEmpty());
    }
}

void NyxV2Dialog::onAcceptReset()
{
    if (shownContact.isEmpty() || shownResetHash.isEmpty() || shownContact != contactEdit->text().trimmed())
    {
        resultView->setPlainText(tr("Fetch and verify the contact again before accepting."));
        return;
    }
    QStringList p;
    p << "keyring" << "accept" << shownContact << shownResetHash;
    if (downgradeBox->isVisible() && downgradeBox->isChecked())
        p << "downgrade";
    Value v;
    if (run(p, v))
    {
        onVerifyContact();
        return;
    }
    const QString err = resultView->toPlainText();
    onVerifyContact();
    resultView->setPlainText(err);
}

void NyxV2Dialog::refreshThreads()
{
    if (self().isEmpty())
        return;
    QString cur;
    if (threadList->currentItem())
        cur = threadList->currentItem()->data(Qt::UserRole + 1).toString();
    threadList->clear();
    QStringList peers;
    Value v;
    QString err;
    if (Call(QStringList() << "session" << "list" << self(), v, err) && v.type() == array_type)
        for (const Value& s : v.get_array())
            if (!peers.contains(Str(s, "peer")))
                peers << Str(s, "peer");
    if (Call(QStringList() << "session" << "messages" << self(), v, err) && v.type() == array_type)
        for (const Value& m : v.get_array())
            if (!peers.contains(Str(m, "peer")))
                peers << Str(m, "peer");
    for (const QString& p : peers)
    {
        QListWidgetItem* it = new QListWidgetItem(p, threadList);
        it->setData(Qt::UserRole, "peer");
        it->setData(Qt::UserRole + 1, p);
    }
    if (Call(QStringList() << "session" << "grouplist" << self(), v, err) && v.type() == array_type)
        for (const Value& g : v.get_array())
        {
            QString label = tr("# %1").arg(Str(g, "name"));
            if (Bool(g, "frozen"))
                label += " " + tr("(frozen)");
            else if (!Bool(g, "member"))
                label += " " + tr("(left)");
            QListWidgetItem* it = new QListWidgetItem(label, threadList);
            it->setData(Qt::UserRole, "group");
            it->setData(Qt::UserRole + 1, Str(g, "gid"));
            QStringList members;
            const Value& a = Get(g, "members");
            if (a.type() == array_type)
                for (const Value& m : a.get_array())
                    members << (m.type() == str_type ? QString::fromStdString(m.get_str()) : Str(m, "address"));
            it->setToolTip(tr("Owner %1\nMembers: %2").arg(Str(g, "owner"), members.join(", ")));
        }
    for (int i = 0; i < threadList->count(); ++i)
        if (threadList->item(i)->data(Qt::UserRole + 1).toString() == cur)
            threadList->setCurrentRow(i);
}

void NyxV2Dialog::onThreadSelected()
{
    threadView->clear();
    threadInfo->clear();
    QListWidgetItem* it = threadList->currentItem();
    if (!it)
        return;
    const bool fGroup = it->data(Qt::UserRole).toString() == "group";
    const QString id = it->data(Qt::UserRole + 1).toString();
    Value v;
    QString err;
    QStringList p;
    if (fGroup)
        p << "session" << "groupmessages" << self() << id;
    else
        p << "session" << "messages" << self() << id;
    threadInfo->setText(fGroup ? it->toolTip() : tr("Direct session with %1").arg(id));
    if (!Call(p, v, err) || v.type() != array_type)
    {
        threadView->setPlainText(err);
        return;
    }
    QString html;
    for (const Value& m : v.get_array())
    {
        const bool fOut = Str(m, "direction") == "out";
        const QString who = fOut ? tr("You") : (fGroup ? Str(m, "sender") : Str(m, "peer"));
        const QString kind = Str(m, "kind");
        const QString when = QDateTime::fromSecsSinceEpoch(Int(m, "time")).toString("yyyy-MM-dd hh:mm");
        const QString tag = Str(m, "mode") == "pq" ? tr("PQ") : tr("classical");
        if (fGroup && !kind.isEmpty() && kind != "msg")
            html += QString("<p><i>%1 %2: %3</i></p>").arg(Esc(when), Esc(who), Esc(kind));
        else
            html += QString("<p><b>%1</b> <small>%2 [%3]</small><br>%4</p>")
                        .arg(Esc(who), Esc(when), Esc(tag), Esc(Str(m, "text")).replace("\n", "<br>"));
    }
    threadView->setHtml(html);
}

void NyxV2Dialog::onSend()
{
    QListWidgetItem* it = threadList->currentItem();
    const QString text = composer->text();
    if (!it || text.trimmed().isEmpty())
        return;
    const bool fGroup = it->data(Qt::UserRole).toString() == "group";
    const QString id = it->data(Qt::UserRole + 1).toString();
    Value v;
    if (!run(QStringList() << "session" << (fGroup ? "groupsend" : "send") << self() << id << text, v))
        return;
    composer->clear();
    showResult(v);
    onThreadSelected();
}

void NyxV2Dialog::onGroupCreate()
{
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("New group"), tr("Group name:"), QLineEdit::Normal,
                                               QString(), &ok).trimmed();
    if (!ok || name.isEmpty())
        return;
    const QString list = QInputDialog::getText(this, tr("New group"),
                                               tr("Member addresses, separated by spaces (up to 9):"),
                                               QLineEdit::Normal, QString(), &ok);
    QStringList members = list.split(QRegularExpression("[\\s,]+"), Qt::SkipEmptyParts);
    if (!ok || members.isEmpty())
        return;
    Value v;
    if (run(QStringList() << "session" << "groupcreate" << self() << name << members, v))
    {
        showResult(v);
        refreshThreads();
    }
}

void NyxV2Dialog::onGroupMember(const QString& op)
{
    QListWidgetItem* it = threadList->currentItem();
    if (!it || it->data(Qt::UserRole).toString() != "group")
        return;
    QStringList p;
    p << "session" << op << self() << it->data(Qt::UserRole + 1).toString();
    if (op != "groupleave")
    {
        bool ok = false;
        const QString a = QInputDialog::getText(this, tr("Group member"), tr("Member address:"),
                                                QLineEdit::Normal, QString(), &ok).trimmed();
        if (!ok || a.isEmpty())
            return;
        p << a;
    }
    else if (QMessageBox::question(this, tr("Leave group"), tr("Leave this group?"),
                                   QMessageBox::Yes | QMessageBox::Cancel) != QMessageBox::Yes)
        return;
    Value v;
    if (run(p, v))
    {
        showResult(v);
        refreshThreads();
    }
}
