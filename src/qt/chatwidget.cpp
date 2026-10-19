#include "chatwidget.h"
#include "messagemodel.h"
#include "walletmodel.h"
#include "sendmessagesdialog.h"
#include "smessage.h"
#include "guiutil.h"
#include "wallet.h"
#include "init.h"
#include "base58.h"
#include "emojipicker.h"
#include "nyxembed.h"

#include <QApplication>
#include <QScrollBar>
#include <QDateTime>
#include <QInputDialog>
#include <QMessageBox>
#include <QFrame>
#include <QSizePolicy>
#include <QFileDialog>
#include <QFileInfo>
#include <QTemporaryFile>
#include <QDir>
#include <QStandardPaths>
#include <QRegularExpression>
#include <QtConcurrent/QtConcurrent>
#include <QFutureWatcher>
#include <QTimer>
#include <QKeyEvent>
#include <QGridLayout>
#include <QPainter>
#include <QDesktopServices>
#include <QUrl>
#include <QPainterPath>
#include <QEvent>

#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef USE_IPFS
#include <ipfs/client.h>
#include <ipfs/http/transport.h>
#endif

// ---- File message protocol ----
// Format: [file:CID:encKeyHex:filename:sizeBytes]
// Example: [file:QmXyz123:a1b2c3d4...64hex:photo.jpg:153280]

bool ChatWidget::isFileMessage(const QString& text)
{
    // Validate format without calling parseFileMessage (avoids recursion)
    if (!text.startsWith("[file:") || !text.endsWith("]") || text.count(':') < 4)
        return false;
    QString cid, key, fname;
    qint64 sz;
    // Quick inline validation
    QString inner = text.mid(6, text.length() - 7);
    int lastColon = inner.lastIndexOf(':');
    if (lastColon < 0) return false;
    inner = inner.left(lastColon);
    int firstColon = inner.indexOf(':');
    if (firstColon < 0) return false;
    QString remainder = inner.mid(firstColon + 1);
    if (remainder.length() < 89) return false;
    int secondColon = remainder.indexOf(':', 88);
    if (secondColon < 0) return false;
    return remainder.left(secondColon).length() == 88;
}

bool ChatWidget::parseFileMessage(const QString& text, QString& cid, QString& encKeyHex,
                                  QString& filename, qint64& size)
{
    // Prefix/suffix check
    if (!text.startsWith("[file:") || !text.endsWith("]") || text.count(':') < 4)
        return false;

    // Strip [file: and ]
    QString inner = text.mid(6, text.length() - 7);

    // Split on : but filename might not contain colons (we split from right for size)
    int lastColon = inner.lastIndexOf(':');
    if (lastColon < 0) return false;
    size = inner.mid(lastColon + 1).toLongLong();
    inner = inner.left(lastColon);

    // Now inner = CID:encKeyHex:filename
    // CID and encKeyHex are fixed format, filename is the rest
    int firstColon = inner.indexOf(':');
    if (firstColon < 0) return false;
    cid = inner.left(firstColon);
    inner = inner.mid(firstColon + 1);

    // encKeyHex is 64 hex chars (32 bytes AES-256 key) + 24 hex chars (12 bytes GCM nonce) = 88 hex
    if (inner.length() < 89) return false; // 88 hex + at least 1 char filename
    int secondColon = inner.indexOf(':', 88);
    if (secondColon < 0) return false;
    encKeyHex = inner.left(secondColon);
    filename = inner.mid(secondColon + 1);

    return !cid.isEmpty() && encKeyHex.length() == 88 && !filename.isEmpty() && size > 0;
}

enum ComposerGlyph { GLYPH_ATTACH, GLYPH_EMOJI };

static QIcon composerIcon(ComposerGlyph g, const QColor& c, qreal dpr)
{
    const int px = 20;
    QPixmap pm(QSize(px, px) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    QPen pen(c, 1.7, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);
    if (g == GLYPH_ATTACH)
    {
        // Paperclip: three nested U-loops, rotated.
        p.translate(10, 10);
        p.rotate(40);
        QPainterPath clip;
        clip.moveTo(1.4, -3.0);
        clip.lineTo(1.4, 5.0);
        clip.arcTo(QRectF(-4.4, 2.0, 5.8, 5.8), 0, -180);
        clip.lineTo(-4.4, -5.0);
        clip.arcTo(QRectF(-4.4, -9.4, 8.8, 8.8), 180, -180);
        clip.lineTo(4.4, 4.0);
        p.drawPath(clip);
    }
    else
    {
        p.drawEllipse(QRectF(2.5, 2.5, 15, 15));
        p.setBrush(c);
        p.setPen(Qt::NoPen);
        p.drawEllipse(QPointF(7.4, 8.3), 1.15, 1.35);
        p.drawEllipse(QPointF(12.6, 8.3), 1.15, 1.35);
        p.setPen(pen);
        p.setBrush(Qt::NoBrush);
        p.drawArc(QRectF(6.0, 7.0, 8.0, 7.0), 200 * 16, 140 * 16);
    }
    return QIcon(pm);
}

void ChatWidget::refreshComposerIcons()
{
    const qreal dpr = devicePixelRatioF() > 0 ? devicePixelRatioF() : 1.0;
    const QColor c = palette().color(QPalette::Text);
    attachButton->setIcon(composerIcon(GLYPH_ATTACH, c, dpr));
    emojiButton->setIcon(composerIcon(GLYPH_EMOJI, c, dpr));
}

ChatWidget::ChatWidget(QWidget *parent) :
    QWidget(parent),
    msgModel(0),
    walletModel(0),
    pendingUploadFileSize(0),
    uploadWatcher(0),
    typingSendPending(false),
    cachedIPFSMaxSize(0)
{
    QHBoxLayout *mainLayout = new QHBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // === Left panel: Contacts ===
    QWidget *leftPanel = new QWidget();
    leftPanel->setMinimumWidth(200);
    leftPanel->setMaximumWidth(280);
    leftPanel->setStyleSheet("background-color: palette(window);");
    QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(0);

    // Contacts header
    QLabel *contactsTitle = new QLabel(tr("  Nyx Messenger"));
    contactsTitle->setStyleSheet("font-size: 14px; font-weight: bold; color: palette(text); padding: 12px 8px; background-color: palette(alternate-base);");
    contactsTitle->setMinimumHeight(44);
    leftLayout->addWidget(contactsTitle);

    // Contact list
    contactList = new QListWidget();
    contactList->setStyleSheet(
        "QListWidget { background-color: palette(window); border: none; color: palette(text); font-size: 12px; }"
        "QListWidget::item { border-bottom: 1px solid palette(mid); }"
        "QListWidget::item:selected { background-color: palette(highlight); }"
        "QListWidget::item:hover:!selected { background-color: palette(base); }");
    contactList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    leftLayout->addWidget(contactList);

    contactsEmptyLabel = new QLabel(tr("No conversations yet.\n\nPress \"+ New\" and enter an Innova address to start one."));
    contactsEmptyLabel->setWordWrap(true);
    contactsEmptyLabel->setAlignment(Qt::AlignCenter);
    contactsEmptyLabel->setStyleSheet("color: palette(dark); padding: 24px 16px; font-size: 12px;");
    contactsEmptyLabel->hide();
    leftLayout->addWidget(contactsEmptyLabel, 1);

    // Button row: New Chat + Delete
    QHBoxLayout *contactButtons = new QHBoxLayout();
    contactButtons->setContentsMargins(0, 0, 0, 0);
    contactButtons->setSpacing(0);

    newChatButton = new QPushButton(tr("+ New"));
    newChatButton->setStyleSheet(
        "QPushButton { background-color: #4CAF50; color: white; border: none; padding: 10px; font-weight: bold; }"
        "QPushButton:hover { background-color: #45a049; }");
    contactButtons->addWidget(newChatButton);

    renameConversationButton = new QPushButton(tr("Rename"));
    renameConversationButton->setStyleSheet(
        "QPushButton { background-color: #2196F3; color: white; border: none; padding: 10px; font-weight: bold; }"
        "QPushButton:hover { background-color: #1976D2; }");
    renameConversationButton->setEnabled(false);
    contactButtons->addWidget(renameConversationButton);

    deleteConversationButton = new QPushButton(tr("Delete"));
    deleteConversationButton->setStyleSheet(
        "QPushButton { background-color: #c0392b; color: white; border: none; padding: 10px; font-weight: bold; }"
        "QPushButton:hover { background-color: #e74c3c; }");
    deleteConversationButton->setEnabled(false);
    contactButtons->addWidget(deleteConversationButton);

    leftLayout->addLayout(contactButtons);

    mainLayout->addWidget(leftPanel);

    // === Right panel: Chat ===
    QWidget *rightPanel = new QWidget();
    rightPanel->setStyleSheet("background-color: palette(base);");
    QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(0);

    // Chat header
    chatHeader = new QLabel(tr("  Select a conversation"));
    chatHeader->setStyleSheet("font-size: 14px; font-weight: bold; color: palette(text); padding: 12px 8px; background-color: palette(alternate-base); border-left: 1px solid palette(mid);");
    chatHeader->setMinimumHeight(44);
    rightLayout->addWidget(chatHeader);

    // Messaging-disabled banner (hidden by default)
    messagingDisabledBanner = new QWidget();
    messagingDisabledBanner->setAttribute(Qt::WA_StyledBackground, true);
    messagingDisabledBanner->setStyleSheet("background-color: #8a5b12;");
    {
        QHBoxLayout *bl = new QHBoxLayout(messagingDisabledBanner);
        bl->setContentsMargins(12, 6, 8, 6);
        QLabel *bt = new QLabel(tr("Nyx Messenger is off, so messages cannot be sent or received."));
        bt->setWordWrap(true);
        bt->setStyleSheet("color: white; font-size: 12px; font-weight: bold;");
        bl->addWidget(bt, 1);
        enableMessagingButton = new QPushButton(tr("Enable messaging"));
        enableMessagingButton->setStyleSheet(
            "QPushButton { background-color: white; color: #8a5b12; border: none; border-radius: 4px; padding: 5px 12px; font-weight: bold; }");
        bl->addWidget(enableMessagingButton);
    }
    messagingDisabledBanner->hide();
    rightLayout->addWidget(messagingDisabledBanner);

    encryptionNote = new QLabel(tr("Messages are end-to-end encrypted to the recipient's address key. "
                                   "Only that address's wallet can read them."));
    encryptionNote->setWordWrap(true);
    encryptionNote->setStyleSheet("color: palette(dark); font-size: 11px; padding: 4px 12px; background-color: palette(alternate-base); border-left: 1px solid palette(mid);");
    rightLayout->addWidget(encryptionNote);

    // IPFS gateway banner (hidden by default)
    ipfsBanner = new QLabel();
    ipfsBanner->setWordWrap(true);
    ipfsBanner->setStyleSheet(
        "background-color: #c0392b; color: white; padding: 8px 12px; font-size: 12px; font-weight: bold;");
    ipfsBanner->hide();
    rightLayout->addWidget(ipfsBanner);

    // Chat messages area
    chatView = new QListWidget();
    chatView->setStyleSheet(
        "QListWidget { background-color: palette(base); border: none; }"
        "QListWidget::item { background: transparent; border: none; padding: 2px 8px; }");
    chatView->setWordWrap(true);
    chatView->setSpacing(2);
    chatView->setSelectionMode(QAbstractItemView::NoSelection);
    chatView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    rightLayout->addWidget(chatView);

    // Message input area
    QFrame *inputFrame = new QFrame();
    inputFrame->setStyleSheet("background-color: palette(window); border-top: 1px solid palette(mid);");
    QHBoxLayout *inputLayout = new QHBoxLayout(inputFrame);
    inputLayout->setContentsMargins(8, 8, 8, 8);

    messageInput = new QTextEdit();
    messageInput->setPlaceholderText(tr("Type a message..."));
    messageInput->setMaximumHeight(60);
    messageInput->setAcceptRichText(false);
    messageInput->installEventFilter(this);
    messageInput->setStyleSheet(
        "QTextEdit { background-color: palette(alternate-base); color: palette(text); border: 1px solid palette(mid); border-radius: 8px; padding: 6px; }");
    messageInput->setFont(GUIUtil::emojiFont(13));
    inputLayout->addWidget(messageInput);

    // Composer buttons draw their glyphs as icons so no style padding can clip them.
    const QString toolCss =
        "QToolButton { background-color: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px; padding: 0px; }"
        "QToolButton:hover { background-color: palette(highlight); }";
    attachButton = new QToolButton();
    attachButton->setStyleSheet(toolCss);
    attachButton->setIconSize(QSize(20, 20));
    attachButton->setFixedSize(40, 40);
    attachButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    attachButton->setToolTip(tr("Attach file (encrypted, uploaded via IPFS)"));
    inputLayout->addWidget(attachButton);

    emojiButton = new QToolButton();
    emojiButton->setStyleSheet(toolCss);
    emojiButton->setIconSize(QSize(20, 20));
    emojiButton->setFixedSize(40, 40);
    emojiButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    emojiButton->setToolTip(tr("Open emoji picker"));
    inputLayout->addWidget(emojiButton);
    refreshComposerIcons();

    sendButton = new QPushButton(tr("Send"));
    sendButton->setMinimumSize(70, 40);
    sendButton->setStyleSheet(
        "QPushButton { background-color: #4CAF50; color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 13px; }"
        "QPushButton:hover { background-color: #45a049; }"
        "QPushButton:disabled { background-color: palette(mid); color: palette(dark); }");
    sendButton->setToolTip(tr("Send (Enter). Shift+Enter inserts a new line."));
    sendButton->setEnabled(false);
    inputLayout->addWidget(sendButton);

    // Emoji picker popup
    emojiPicker = new EmojiPicker(this);
    emojiPicker->hide();
    connect(emojiPicker, &EmojiPicker::emojiSelected, [this](const QString& emoji) {
        messageInput->insertPlainText(emoji);
        messageInput->setFocus();
    });
    connect(emojiButton, &QToolButton::clicked, [this]() {
        QPoint pos = emojiButton->mapToGlobal(QPoint(0, -emojiPicker->height() - 5));
        emojiPicker->move(pos);
        emojiPicker->show();
    });

    // Emoji autocomplete for :shortcode: typing
    emojiAutocomplete = new EmojiAutocomplete(this);
    emojiAutocomplete->hide();
    connect(emojiAutocomplete, &EmojiAutocomplete::emojiChosen, [this](const QString& emoji) {
        // Replace the :partial text with the emoji
        QTextCursor cursor = messageInput->textCursor();
        QString text = messageInput->toPlainText();
        int pos = cursor.position();
        int colonPos = text.lastIndexOf(':', pos - 1);
        if (colonPos >= 0)
        {
            cursor.setPosition(colonPos);
            cursor.setPosition(pos, QTextCursor::KeepAnchor);
            cursor.insertText(emoji);
        }
        messageInput->setFocus();
    });
    connect(messageInput, &QTextEdit::textChanged, [this]() {
        // Send typing notification (rate-limited)
        if (fSecMsgEnabled && !currentContact.isEmpty() && !messageInput->toPlainText().trimmed().isEmpty())
            onSendTypingNotification();
        updateSendButton();

        // Check for :shortcode pattern
        QString text = messageInput->toPlainText();
        int cursorPos = messageInput->textCursor().position();
        int colonPos = text.lastIndexOf(':', cursorPos - 1);
        if (colonPos >= 0 && cursorPos - colonPos > 1 && cursorPos - colonPos < 20)
        {
            QString partial = text.mid(colonPos + 1, cursorPos - colonPos - 1);
            if (!partial.contains(' ') && !partial.contains(':'))
            {
                QPoint pos = messageInput->mapToGlobal(QPoint(0, -emojiAutocomplete->height() - 5));
                emojiAutocomplete->move(pos);
                emojiAutocomplete->updateSuggestions(partial);
                return;
            }
        }
        emojiAutocomplete->hide();
    });

    rightLayout->addWidget(inputFrame);

    mainLayout->addWidget(rightPanel);

    // Connections
    connect(contactList, SIGNAL(currentRowChanged(int)), this, SLOT(onContactSelected(int)));
    connect(sendButton, SIGNAL(clicked()), this, SLOT(onSendClicked()));
    connect(newChatButton, SIGNAL(clicked()), this, SLOT(onNewChatClicked()));
    connect(attachButton, SIGNAL(clicked()), this, SLOT(onFileAttachClicked()));
    connect(deleteConversationButton, SIGNAL(clicked()), this, SLOT(onDeleteConversationClicked()));
    connect(renameConversationButton, SIGNAL(clicked()), this, SLOT(onRenameConversationClicked()));
    connect(enableMessagingButton, SIGNAL(clicked()), this, SLOT(onEnableMessagingClicked()));

    // Load saved nicknames from settings
    {
        QSettings settings;
        int count = settings.beginReadArray("chatNicknames");
        for (int i = 0; i < count; i++)
        {
            settings.setArrayIndex(i);
            mapContactNicknames[settings.value("address").toString()] = settings.value("name").toString();
        }
        settings.endArray();

        settings.beginGroup("chatLastRead");
        foreach (const QString& k, settings.childKeys())
            mapLastReadTime[k] = settings.value(k).toLongLong();
        settings.endGroup();
    }

    showEmptyConversation();

    // Typing indicator timers
    typingDisplayTimer = new QTimer(this);
    typingDisplayTimer->setInterval(1000); // Check every 1 second
    connect(typingDisplayTimer, SIGNAL(timeout()), this, SLOT(onTypingTimeout()));
    typingDisplayTimer->start();

    typingSendTimer = new QTimer(this);
    typingSendTimer->setSingleShot(true);
    typingSendTimer->setInterval(3000); // Rate limit: 1 typing notification per 3 seconds
}

// Bridge: boost signal -> Qt slot (thread-safe via mutex + QMetaObject::invokeMethod)
#include <QMutex>
#include <boost/bind/bind.hpp>
using boost::placeholders::_1;
static QMutex g_chatWidgetMutex;
static ChatWidget* g_chatWidget = NULL;

static boost::signals2::connection g_typingConnection;

static void NotifyTypingCallbackImpl(std::string senderAddr)
{
    QMutexLocker lock(&g_chatWidgetMutex);
    if (g_chatWidget)
    {
        QString addr = QString::fromStdString(senderAddr);
        QMetaObject::invokeMethod(g_chatWidget, "onTypingReceived",
            Qt::QueuedConnection, Q_ARG(QString, addr));
    }
}

ChatWidget::~ChatWidget()
{
    QMutexLocker lock(&g_chatWidgetMutex);
    g_typingConnection.disconnect();
    g_chatWidget = NULL;
}

void ChatWidget::setModel(MessageModel *msgModel, WalletModel *walletModel)
{
    this->msgModel = msgModel;
    this->walletModel = walletModel;

    if (msgModel)
    {
        connect(msgModel, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(onNewMessage()));
        refreshContacts();
    }

    applyMessagingPreference();
    refreshMessagingEnabled();

    // Connect typing notification signal from smessage layer (thread-safe)
    {
        QMutexLocker lock(&g_chatWidgetMutex);
        g_chatWidget = this;
    }
    g_typingConnection = NotifySecMsgTyping.connect(boost::bind(&NotifyTypingCallbackImpl, _1));

    // Check IPFS gateway connectivity on startup (async, caches result)
    QtConcurrent::run([this]() {
        qint64 maxSize = checkIPFSGateway();
        QMetaObject::invokeMethod(this, [this, maxSize]() {
            cachedIPFSMaxSize = maxSize;
            if (maxSize == 0)
            {
                ipfsBanner->setText(
                    tr("IPFS Gateway Unreachable - File sharing disabled. "
                       "Add to innova.conf: hyperfilelocal=1 and hyperfileip=ipfs.innova-foundation.com:5001 then restart."));
                ipfsBanner->show();
            }
            else
            {
                ipfsBanner->hide();
            }
        });
    });
}

QString ChatWidget::displayNameFor(const QString& address) const
{
    return mapContactNicknames.value(address, address.left(12) + QString::fromUtf8("\xE2\x80\xA6") + address.right(6));
}

void ChatWidget::markRead(const QString& address)
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    mapLastReadTime[address] = now;
    QSettings settings;
    settings.beginGroup("chatLastRead");
    settings.setValue(address, now);
    settings.endGroup();
}

void ChatWidget::refreshContacts()
{
    if (!msgModel)
        return;

    QString prevContact = currentContact;
    contactList->blockSignals(true);
    contactList->clear();

    struct ContactInfo { QString preview; QDateTime last; int unread; bool lastMine; };
    QMap<QString, ContactInfo> contacts;

    for (int i = 0; i < msgModel->rowCount(QModelIndex()); i++)
    {
        QModelIndex mi = msgModel->index(i, 0, QModelIndex());
        int type = msgModel->data(mi, MessageModel::TypeRole).toInt();
        QString from = msgModel->data(msgModel->index(i, MessageModel::FromAddress, QModelIndex()), Qt::DisplayRole).toString();
        QString to = msgModel->data(msgModel->index(i, MessageModel::ToAddress, QModelIndex()), Qt::DisplayRole).toString();
        QString msg = msgModel->data(msgModel->index(i, MessageModel::Message, QModelIndex()), Qt::DisplayRole).toString();
        QDateTime dt = msgModel->data(msgModel->index(i, MessageModel::ReceivedDateTime, QModelIndex()), Qt::DisplayRole).toDateTime();

        bool isMine = (type == MessageTableEntry::Sent);
        QString contactAddr = isMine ? to : from;

        ContactInfo& ci = contacts[contactAddr];
        if (!isMine && dt.toMSecsSinceEpoch() > mapLastReadTime.value(contactAddr, 0))
            ci.unread++;

        if (ci.last.isNull() || dt > ci.last)
        {
            QString preview;
            QString cid, key, fname;
            qint64 sz;
            if (parseFileMessage(msg, cid, key, fname, sz))
                preview = tr("[File: %1]").arg(fname);
            else if (isFileMessage(msg))
                preview = tr("[File attachment]");
            else
                preview = msg.simplified();
            if (preview.length() > 48)
                preview = preview.left(48) + QString::fromUtf8("\xE2\x80\xA6");
            ci.preview = preview;
            ci.last = dt;
            ci.lastMine = isMine;
        }
    }

    QList<QPair<QDateTime, QString>> sorted;
    for (auto it = contacts.begin(); it != contacts.end(); ++it)
        sorted.append(qMakePair(it.value().last, it.key()));
    std::sort(sorted.begin(), sorted.end(), [](const QPair<QDateTime,QString>& a, const QPair<QDateTime,QString>& b) {
        return a.first > b.first;
    });

    int restoreRow = -1;
    for (int i = 0; i < sorted.size(); i++)
    {
        const QString& addr = sorted[i].second;
        const ContactInfo& ci = contacts[addr];

        QString timeStr;
        qint64 secsAgo = ci.last.secsTo(QDateTime::currentDateTime());
        if (secsAgo < 60) timeStr = tr("now");
        else if (secsAgo < 3600) timeStr = tr("%1m").arg(secsAgo / 60);
        else if (secsAgo < 86400) timeStr = tr("%1h").arg(secsAgo / 3600);
        else timeStr = ci.last.toString("MMM d");

        int unread = (addr == currentContact) ? 0 : ci.unread;
        bool typing = mapTypingContacts.contains(addr);

        QWidget *row = new QWidget();
        row->setAttribute(Qt::WA_TranslucentBackground);
        QGridLayout *g = new QGridLayout(row);
        g->setContentsMargins(12, 8, 10, 8);
        g->setHorizontalSpacing(6);
        g->setVerticalSpacing(2);

        QLabel *name = new QLabel(displayNameFor(addr));
        name->setTextFormat(Qt::PlainText);
        name->setStyleSheet(QString("font-size: 13px; font-weight: %1; background: transparent;").arg(unread ? "bold" : "600"));
        QLabel *when = new QLabel(timeStr);
        when->setStyleSheet("font-size: 10px; color: palette(dark); background: transparent;");
        QString prevText = typing ? tr("typing...") : ((ci.lastMine ? tr("You: ") : QString()) + ci.preview);
        QLabel *prev = new QLabel(prevText);
        prev->setTextFormat(Qt::PlainText);
        prev->setStyleSheet(QString("font-size: 11px; color: %1; background: transparent;")
                            .arg(typing ? "#4CAF50" : "palette(dark)"));
        prev->setMinimumWidth(10);
        prev->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);

        g->addWidget(name, 0, 0);
        g->addWidget(when, 0, 1, Qt::AlignRight);
        g->addWidget(prev, 1, 0);
        if (unread > 0)
        {
            QLabel *badge = new QLabel(unread > 99 ? QString("99+") : QString::number(unread));
            badge->setAlignment(Qt::AlignCenter);
            badge->setMinimumWidth(20);
            badge->setStyleSheet("background-color: #2196F3; color: white; border-radius: 9px; font-size: 10px; font-weight: bold; padding: 1px 6px;");
            g->addWidget(badge, 1, 1, Qt::AlignRight);
        }
        g->setColumnStretch(0, 1);

        QListWidgetItem *item = new QListWidgetItem();
        item->setData(Qt::UserRole, addr);
        item->setToolTip(addr);
        item->setSizeHint(QSize(0, 54));
        contactList->addItem(item);
        contactList->setItemWidget(item, row);

        if (addr == prevContact)
            restoreRow = i;
    }

    if (restoreRow >= 0)
        contactList->setCurrentRow(restoreRow);
    contactList->blockSignals(false);

    bool empty = sorted.isEmpty();
    contactList->setVisible(!empty);
    contactsEmptyLabel->setVisible(empty);
}

void ChatWidget::onContactSelected(int row)
{
    if (row < 0 || !contactList->item(row))
        return;

    currentContact = contactList->item(row)->data(Qt::UserRole).toString();

    chatHeader->setText(tr("  Chat with %1").arg(displayNameFor(currentContact)));
    chatHeader->setToolTip(currentContact);

    deleteConversationButton->setEnabled(true);
    renameConversationButton->setEnabled(true);
    updateSendButton();

    markRead(currentContact);

    loadConversation(currentContact);
    refreshContacts();
    messageInput->setFocus();
}

void ChatWidget::addCenteredNote(const QString& text)
{
    QLabel *lbl = new QLabel(text);
    lbl->setTextFormat(Qt::PlainText);
    lbl->setWordWrap(true);
    lbl->setAlignment(Qt::AlignCenter);
    lbl->setStyleSheet("color: palette(dark); font-size: 12px; padding: 24px; background: transparent;");
    QListWidgetItem *item = new QListWidgetItem();
    item->setFlags(Qt::NoItemFlags);
    item->setSizeHint(QSize(0, lbl->sizeHint().height() + 40));
    chatView->addItem(item);
    chatView->setItemWidget(item, lbl);
}

void ChatWidget::showEmptyConversation()
{
    chatView->clear();
    addCenteredNote(tr("Select a conversation, or press \"+ New\" to message an Innova address.\n\n"
                       "Messages are end-to-end encrypted with the recipient's address key and "
                       "relayed by peers that run Nyx Messenger. Nobody but the recipient can read them."));
}

void ChatWidget::addDateSeparator(const QDate& date)
{
    QString text;
    if (date == QDate::currentDate()) text = tr("Today");
    else if (date == QDate::currentDate().addDays(-1)) text = tr("Yesterday");
    else text = date.toString("dddd, MMMM d, yyyy");

    QLabel *lbl = new QLabel(text);
    lbl->setAlignment(Qt::AlignCenter);
    lbl->setStyleSheet("color: palette(dark); font-size: 10px; font-weight: bold; padding: 6px; background: transparent;");
    QListWidgetItem *item = new QListWidgetItem();
    item->setFlags(Qt::NoItemFlags);
    item->setSizeHint(QSize(0, 26));
    chatView->addItem(item);
    chatView->setItemWidget(item, lbl);
}

void ChatWidget::loadConversation(const QString& address)
{
    chatView->clear();

    if (!msgModel)
        return;

    QList<QPair<QDateTime, int>> msgIndices;

    for (int i = 0; i < msgModel->rowCount(QModelIndex()); i++)
    {
        QString from = msgModel->data(msgModel->index(i, MessageModel::FromAddress, QModelIndex()), Qt::DisplayRole).toString();
        QString to = msgModel->data(msgModel->index(i, MessageModel::ToAddress, QModelIndex()), Qt::DisplayRole).toString();

        if (from == address || to == address)
        {
            QDateTime dt = msgModel->data(msgModel->index(i, MessageModel::ReceivedDateTime, QModelIndex()), Qt::DisplayRole).toDateTime();
            msgIndices.append(qMakePair(dt, i));
        }
    }

    std::sort(msgIndices.begin(), msgIndices.end());

    if (msgIndices.isEmpty())
        addCenteredNote(tr("No messages yet. Say hello."));

    QDate lastDate;
    for (const auto& pair : msgIndices)
    {
        int row = pair.second;
        int type = msgModel->data(msgModel->index(row, 0, QModelIndex()), MessageModel::TypeRole).toInt();
        QString msg = msgModel->data(msgModel->index(row, MessageModel::Message, QModelIndex()), Qt::DisplayRole).toString();
        QDateTime dt = pair.first;

        if (dt.date() != lastDate)
        {
            addDateSeparator(dt.date());
            lastDate = dt.date();
        }

        bool isMine = (type == MessageTableEntry::Sent);

        QString cid, encKeyHex, filename;
        qint64 fileSize;
        if (parseFileMessage(msg, cid, encKeyHex, filename, fileSize))
            addFileBubble(cid, encKeyHex, filename, fileSize, dt.toString("hh:mm"), isMine);
        else
            addChatBubble(msg, dt.toString("hh:mm"), isMine);
    }

    chatView->scrollToBottom();
}

void ChatWidget::addChatBubble(const QString& text, const QString& time, bool isMine,
                               bool fFailed, const QString& failReason)
{
    QWidget *bubbleWidget = new QWidget();
    QHBoxLayout *bubbleLayout = new QHBoxLayout(bubbleWidget);
    bubbleLayout->setContentsMargins(8, 2, 8, 2);

    QFrame *bubble = new QFrame();
    bubble->setObjectName("bubble");
    QVBoxLayout *bl = new QVBoxLayout(bubble);
    bl->setContentsMargins(12, 8, 12, 6);
    bl->setSpacing(2);

    // Untrusted text: everything is escaped; only http(s) anchors are added. Links open via a confirm.
    QLabel *body = new QLabel();
    body->setTextFormat(Qt::RichText);
    body->setText("<span style=\"white-space: pre-wrap;\">"
                  + QString::fromStdString(NyxLinkify(text.toStdString())) + "</span>");
    body->setOpenExternalLinks(false);
    body->setWordWrap(true);
    body->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::LinksAccessibleByMouse);
    connect(body, &QLabel::linkActivated, this, &ChatWidget::confirmOpenUrl);
    body->setMaximumWidth(400);
    body->setFont(GUIUtil::emojiFont(13));
    body->setStyleSheet("background: transparent;");
    bl->addWidget(body);

    QString status;
    if (isMine)
        status = fFailed ? tr("  Not sent") : QString::fromUtf8("  \xE2\x9C\x93 ") + tr("Sent");
    QLabel *meta = new QLabel(time + status);
    meta->setTextFormat(Qt::PlainText);
    meta->setAlignment(isMine ? Qt::AlignRight : Qt::AlignLeft);
    if (fFailed && !failReason.isEmpty())
        meta->setToolTip(failReason);
    bl->addWidget(meta);

    if (isMine)
    {
        bubble->setStyleSheet(fFailed
            ? "QFrame#bubble { background-color: transparent; border: 1px solid #c0392b; border-radius: 12px; }"
              "QLabel { color: palette(text); }"
            : "QFrame#bubble { background-color: #2a5298; border-radius: 12px; } QLabel { color: white; }");
        meta->setStyleSheet(QString("background: transparent; font-size: 10px; color: %1;").arg(fFailed ? "#c0392b" : "#c8d8ff"));
        bubbleLayout->addStretch();
        bubbleLayout->addWidget(bubble);
    }
    else
    {
        bubble->setStyleSheet("QFrame#bubble { background-color: palette(alternate-base); border: 1px solid palette(mid); border-radius: 12px; }"
                              "QLabel { color: palette(text); }");
        meta->setStyleSheet("background: transparent; font-size: 10px; color: palette(dark);");
        bubbleLayout->addWidget(bubble);
        bubbleLayout->addStretch();
    }

    QListWidgetItem *item = new QListWidgetItem();
    item->setFlags(Qt::NoItemFlags);
    bubbleWidget->adjustSize();
    int bubbleH = bubbleWidget->sizeHint().height() + 4;
    item->setSizeHint(QSize(0, qMax(bubbleH, 44)));
    chatView->addItem(item);
    chatView->setItemWidget(item, bubbleWidget);
}

void ChatWidget::addFileBubble(const QString& cid, const QString& encKeyHex,
                               const QString& filename, qint64 size, const QString& time, bool isMine)
{
    QWidget *bubbleWidget = new QWidget();
    QHBoxLayout *outerLayout = new QHBoxLayout(bubbleWidget);
    outerLayout->setContentsMargins(8, 2, 8, 2);

    QWidget *fileCard = new QWidget();
    QVBoxLayout *cardLayout = new QVBoxLayout(fileCard);
    cardLayout->setContentsMargins(10, 8, 10, 8);
    cardLayout->setSpacing(4);

    // File icon + name
    QString sizeStr;
    if (size < 1024) sizeStr = QString("%1 B").arg(size);
    else if (size < 1024 * 1024) sizeStr = QString("%1 KB").arg(size / 1024);
    else sizeStr = QString("%1 MB").arg(size / (1024 * 1024));

    QLabel *fileLabel = new QLabel();
    fileLabel->setTextFormat(Qt::RichText);
    fileLabel->setText(QString("<b>%1</b><br><span style='font-size: 11px; color: palette(dark);'>%2 | Encrypted</span>")
                       .arg(filename.toHtmlEscaped(), sizeStr));
    fileLabel->setStyleSheet("color: palette(text); font-size: 13px;");
    cardLayout->addWidget(fileLabel);

    // Download button
    QPushButton *dlButton = new QPushButton(tr("Download"));
    dlButton->setStyleSheet(
        "QPushButton { background-color: #4CAF50; color: white; border: none; border-radius: 4px; padding: 5px 12px; font-weight: bold; font-size: 11px; }"
        "QPushButton:hover { background-color: #45a049; }");
    dlButton->setFixedWidth(120);
    cardLayout->addWidget(dlButton);

    // Connect download — capture cid/key/filename by value
    QString capCid = cid, capKey = encKeyHex, capName = filename;
    connect(dlButton, &QPushButton::clicked, [this, capCid, capKey, capName]() {
        onFileDownloadClicked(capCid, capKey, capName);
    });

    // Timestamp
    QString checkMark = isMine ? QString::fromUtf8(" \xE2\x9C\x93") : ""; // single check = delivered
    QLabel *timeLabel = new QLabel();
    timeLabel->setText(time + checkMark);
    timeLabel->setStyleSheet(QString("font-size:9px;color:%1;letter-spacing:0px;").arg(isMine ? "#8ab4f8" : "palette(dark)"));
    cardLayout->addWidget(timeLabel);

    QString bgColor = isMine ? "#1e3a6e" : "palette(base)";
    fileCard->setStyleSheet(QString("background-color: %1; border-radius: 12px; border: 1px solid palette(mid);").arg(bgColor));
    fileCard->setMaximumWidth(320);

    if (isMine)
    {
        outerLayout->addStretch();
        outerLayout->addWidget(fileCard);
    }
    else
    {
        outerLayout->addWidget(fileCard);
        outerLayout->addStretch();
    }

    QListWidgetItem *item = new QListWidgetItem();
    item->setSizeHint(QSize(chatView->viewport()->width(), 90));
    chatView->addItem(item);
    chatView->setItemWidget(item, bubbleWidget);
}

void ChatWidget::refreshMessagingEnabled()
{
    const bool fEnabled = fSecMsgEnabled;

    messagingDisabledBanner->setVisible(!fEnabled);
    enableMessagingButton->setVisible(!GetBoolArg("-nosmsg", false));

    messageInput->setReadOnly(!fEnabled);
    messageInput->setPlaceholderText(fEnabled
        ? tr("Type a message...  (Enter sends, Shift+Enter for a new line)")
        : tr("Nyx Messenger is off. Enable it above or in Settings > Options > Messaging."));

    attachButton->setEnabled(fEnabled);
    newChatButton->setEnabled(fEnabled);
    updateSendButton();
}

void ChatWidget::updateSendButton()
{
    sendButton->setEnabled(fSecMsgEnabled && !currentContact.isEmpty()
                           && !messageInput->toPlainText().trimmed().isEmpty());
}

static const char* NYX_PREF_KEY = "fNyxMessenger";

bool ChatWidget::messagingPreference()
{
    QSettings settings;
    return settings.value(NYX_PREF_KEY, (bool)fSecMsgEnabled).toBool();
}

bool ChatWidget::setMessagingEnabled(bool fEnable, QString *pError)
{
    if (fEnable && GetBoolArg("-nosmsg", false))
    {
        if (pError) *pError = tr("Messaging is forced off by -nosmsg.");
        return fSecMsgEnabled;
    }
    QSettings settings;
    settings.setValue(NYX_PREF_KEY, fEnable);
    if (fEnable && !fSecMsgEnabled)
    {
        if (!SecureMsgEnable() && pError)
            *pError = tr("Messaging could not be started. See debug.log.");
    }
    else if (!fEnable && fSecMsgEnabled)
        SecureMsgDisable();
    return fSecMsgEnabled;
}

void ChatWidget::applyMessagingPreference()
{
    QSettings settings;
    if (!settings.contains(NYX_PREF_KEY))
        return;
    bool fWant = settings.value(NYX_PREF_KEY).toBool();
    // An explicit -smsg on the command line or in innova.conf wins over the saved toggle.
    if (!fWant && mapArgs.count("-smsg"))
        return;
    if (fWant != (bool)fSecMsgEnabled)
        setMessagingEnabled(fWant);
}

void ChatWidget::onEnableMessagingClicked()
{
    QString err;
    setMessagingEnabled(true, &err);
    if (!err.isEmpty())
        QMessageBox::warning(this, tr("Nyx Messenger"), err);
    refreshMessagingEnabled();
    refreshContacts();
}

void ChatWidget::confirmOpenUrl(const QString& link)
{
    if (!NyxIsLinkableUrl(link.toStdString()))
        return;
    QUrl url(link, QUrl::StrictMode);
    if (!url.isValid() || (url.scheme() != "https" && url.scheme() != "http") || url.host().isEmpty())
        return;
    QMessageBox box(QMessageBox::Warning, tr("Open link"),
                    tr("You are leaving Innova:") + "\n\n" + url.toString(QUrl::FullyEncoded),
                    QMessageBox::NoButton, this);
    QPushButton *open = box.addButton(tr("Open"), QMessageBox::AcceptRole);
    QPushButton *cancel = box.addButton(QMessageBox::Cancel);
    box.setDefaultButton(cancel);
    box.setEscapeButton(cancel);
    box.exec();
    if (box.clickedButton() == open)
        QDesktopServices::openUrl(url);
}

void ChatWidget::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::PaletteChange || event->type() == QEvent::StyleChange)
        refreshComposerIcons();
    QWidget::changeEvent(event);
}

bool ChatWidget::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == messageInput && event->type() == QEvent::KeyPress)
    {
        QKeyEvent *ke = static_cast<QKeyEvent*>(event);
        if ((ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter)
            && !(ke->modifiers() & Qt::ShiftModifier)
            && !emojiAutocomplete->isVisible())
        {
            if (sendButton->isEnabled())
                onSendClicked();
            return true;
        }
    }
    return QWidget::eventFilter(obj, event);
}

QString ChatWidget::pickSendFromAddress() const
{
    // Prefer the address this contact last wrote to, so replies come from the same identity.
    if (msgModel)
    {
        QDateTime best;
        QString addr;
        for (int i = 0; i < msgModel->rowCount(QModelIndex()); i++)
        {
            int type = msgModel->data(msgModel->index(i, 0, QModelIndex()), MessageModel::TypeRole).toInt();
            QString from = msgModel->data(msgModel->index(i, MessageModel::FromAddress, QModelIndex()), Qt::DisplayRole).toString();
            QString to = msgModel->data(msgModel->index(i, MessageModel::ToAddress, QModelIndex()), Qt::DisplayRole).toString();
            QDateTime dt = msgModel->data(msgModel->index(i, MessageModel::ReceivedDateTime, QModelIndex()), Qt::DisplayRole).toDateTime();
            QString mine;
            if (type == MessageTableEntry::Received && from == currentContact) mine = to;
            else if (type == MessageTableEntry::Sent && to == currentContact) mine = from;
            if (!mine.isEmpty() && (best.isNull() || dt > best)) { best = dt; addr = mine; }
        }
        if (!addr.isEmpty())
            return addr;
    }

    if (!pwalletMain)
        return QString();
    LOCK(pwalletMain->cs_wallet);
    for (const auto& pair : pwalletMain->mapAddressBook)
    {
        if (IsMine(*pwalletMain, pair.first))
            return QString::fromStdString(CBitcoinAddress(pair.first).ToString());
    }
    std::set<CKeyID> setKeyID;
    pwalletMain->GetKeys(setKeyID);
    if (!setKeyID.empty())
        return QString::fromStdString(CBitcoinAddress(*setKeyID.begin()).ToString());
    return QString();
}

void ChatWidget::onSendClicked()
{
    if (!msgModel || currentContact.isEmpty())
        return;

    if (!fSecMsgEnabled)
    {
        refreshMessagingEnabled();
        return;
    }

    QString message = EmojiPicker::replaceShortcodes(messageInput->toPlainText().trimmed());
    if (message.isEmpty())
        return;

    if (!pwalletMain)
    {
        QMessageBox::warning(this, tr("Send Message"), tr("Wallet not loaded."));
        return;
    }

    std::string addFrom = pickSendFromAddress().toStdString();
    if (addFrom.empty())
    {
        QMessageBox::warning(this, tr("Send Message"), tr("No address available to send from."));
        return;
    }

    std::string sError;
    QString cid, encKeyHex, filename;
    qint64 fileSize;
    bool fFile = parseFileMessage(message, cid, encKeyHex, filename, fileSize);
    QString now = QDateTime::currentDateTime().toString("hh:mm");

    std::string sendTo = currentContact.toStdString();
    std::string msgText = message.toStdString();
    if (SecureMsgSend(addFrom, sendTo, msgText, sError) != 0)
    {
        QString reason = QString::fromStdString(sError);
        if (reason.contains("public key", Qt::CaseInsensitive))
            reason += tr("\nThe recipient's public key is not known yet. It is learned once they send you "
                         "a message or have sent any transaction from that address.");
        // Text stays in the composer so it can be retried.
        addChatBubble(message, now, true, true, reason);
        chatView->scrollToBottom();
        return;
    }

    messageInput->clear();

    // Model refresh rebuilds the view; paint now so the send feels immediate.
    if (fFile)
        addFileBubble(cid, encKeyHex, filename, fileSize, now, true);
    else
        addChatBubble(message, now, true);
    chatView->scrollToBottom();
}

void ChatWidget::onNewChatClicked()
{
    if (!msgModel)
        return;

    // Open the existing send messages dialog for new conversations
    SendMessagesDialog dlg(SendMessagesDialog::Encrypted, SendMessagesDialog::Dialog, this);
    dlg.setModel(msgModel);
    dlg.exec();

    // Refresh contacts after dialog closes
    refreshContacts();
}

void ChatWidget::onFileAttachClicked()
{
    if (currentContact.isEmpty())
    {
        QMessageBox::warning(this, tr("Attach File"), tr("Please select a conversation first."));
        return;
    }

#ifndef USE_IPFS
    QMessageBox::warning(this, tr("IPFS Not Available"),
        tr("This build was compiled without IPFS support. File sharing requires IPFS."));
    return;
#else
    QString filePath = QFileDialog::getOpenFileName(this, tr("Select File to Share"),
        QString(), tr("All Files (*);;Images (*.png *.jpg *.gif *.bmp);;Documents (*.pdf *.txt *.doc *.docx)"));
    if (filePath.isEmpty())
        return;

    QFileInfo fi(filePath);
    // Use cached gateway result (CHAT-CRYPTO-5: avoid blocking UI thread)
    qint64 maxFileSize = cachedIPFSMaxSize;
    if (maxFileSize == 0) maxFileSize = 50 * 1024 * 1024; // fallback 50MB if not yet checked
    if (fi.size() > maxFileSize)
    {
        QMessageBox::warning(this, tr("File Too Large"),
            tr("Maximum file size is %1 MB for current gateway. Selected file is %2 MB.")
            .arg(maxFileSize / (1024 * 1024)).arg(fi.size() / (1024 * 1024)));
        return;
    }

    // Confirm
    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Send Encrypted File"),
        tr("Encrypt and send \"%1\" (%2 bytes) via IPFS?\n\n"
           "The file will be AES-256-GCM encrypted before upload. "
           "Only the recipient can decrypt it.")
        .arg(fi.fileName()).arg(fi.size()),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
        return;

    // Store pending upload metadata
    pendingUploadFilePath = filePath;
    pendingUploadFileSize = fi.size();

    // Disable UI during upload
    attachButton->setEnabled(false);
    sendButton->setEnabled(false);
    attachButton->setToolTip(tr("Encrypting and uploading..."));

    // Returns (CID, keyHex) on success or (error, "") on failure
    uploadWatcher = new QFutureWatcher<QPair<QString, QString>>(this);
    connect(uploadWatcher, SIGNAL(finished()), this, SLOT(onFileUploadFinished()));

    QFuture<QPair<QString, QString>> future = QtConcurrent::run([this, filePath]() -> QPair<QString, QString> {
        QString outCID, outKeyHex, outError;
        if (encryptAndUploadFile(filePath, outCID, outKeyHex, outError))
            return qMakePair(outCID, outKeyHex);
        // Return error as first element, empty second signals failure
        return qMakePair(outError, QString());
    });

    uploadWatcher->setFuture(future);
#endif
}

void ChatWidget::onFileUploadFinished()
{
#ifdef USE_IPFS
    // Re-enable UI
    attachButton->setEnabled(fSecMsgEnabled);
    sendButton->setEnabled(fSecMsgEnabled && !currentContact.isEmpty());
    attachButton->setToolTip(tr("Attach file (encrypted, uploaded via IPFS)"));

    QPair<QString, QString> result = uploadWatcher->result();
    uploadWatcher->deleteLater();
    uploadWatcher = 0;

    QString outCID = result.first;
    QString outKeyHex = result.second;

    if (outKeyHex.isEmpty())
    {
        // Upload failed — outCID contains the error message
        if (!outCID.isEmpty())
            QMessageBox::warning(this, tr("File Upload Failed"), outCID);
        return;
    }

    // Sanitize filename: strip protocol-breaking chars and cap length
    QFileInfo fi(pendingUploadFilePath);
    QString safeName = fi.fileName().left(255);
    safeName.remove(QRegularExpression("[\\[\\]\\n\\r:]")); // Strip colons too (CHAT-CRYPTO-3)
    safeName = QFileInfo(safeName).fileName();
    if (safeName.isEmpty()) safeName = "file";

    // Compose file message and send it
    QString fileMsg = QString("[file:%1:%2:%3:%4]")
                      .arg(outCID, outKeyHex, safeName).arg(pendingUploadFileSize);

    messageInput->setPlainText(fileMsg);
    onSendClicked();
#endif
}

qint64 ChatWidget::checkIPFSGateway()
{
#ifndef USE_IPFS
    return 0;
#else
    try {
        bool fLocal = GetBoolArg("-hyperfilelocal");
        std::string ipfsip = GetArg("-hyperfileip", "ipfs.innova-foundation.com:5001");

        std::unique_ptr<ipfs::Client> client;
        if (!fLocal)
            throw std::runtime_error("Hyperfile is off. Set hyperfilelocal=1 and "
                                     "hyperfileip=ipfs.innova-foundation.com:5001 in innova.conf. "
                                     "There is no public fallback endpoint.");
        client.reset(new ipfs::Client(ipfsip));

        ipfs::Json version;
        client->Version(&version);

        if (!version["Version"].dump().empty())
        {
            // Read max file size from conf (nyxmaxfilesize), fallback to 100MB for public gateways
            if (fLocal)
            {
                std::string sMax = GetArg("-nyxmaxfilesize", "10995116277760");
                return atoll(sMax.c_str());
            }
            else
                return 100 * 1024 * 1024;  // 100MB public gateway fallback
        }
    }
    catch (...) {}
    return 0;
#endif
}

QByteArray ChatWidget::encryptChunk(const QByteArray& plainData, const unsigned char* key,
                                     const unsigned char* baseNonce, uint32_t chunkIndex)
{
    // Derive per-chunk nonce: baseNonce XOR chunkIndex (last 4 bytes)
    unsigned char nonce[12];
    memcpy(nonce, baseNonce, 12);
    nonce[8] ^= (chunkIndex >> 24) & 0xFF;
    nonce[9] ^= (chunkIndex >> 16) & 0xFF;
    nonce[10] ^= (chunkIndex >> 8) & 0xFF;
    nonce[11] ^= chunkIndex & 0xFF;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return QByteArray();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(nonce, 12);
        return QByteArray();
    }

    QByteArray cipherData(plainData.size(), 0);
    int outLen1 = 0, outLen2 = 0;

    if (EVP_EncryptUpdate(ctx, (unsigned char*)cipherData.data(), &outLen1,
                          (const unsigned char*)plainData.constData(), plainData.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(nonce, 12);
        return QByteArray();
    }

    if (EVP_EncryptFinal_ex(ctx, (unsigned char*)cipherData.data() + outLen1, &outLen2) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(nonce, 12);
        return QByteArray();
    }
    cipherData.resize(outLen1 + outLen2);

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, 12);

    // Return: tag(16) + ciphertext
    QByteArray result;
    result.append((const char*)tag, 16);
    result.append(cipherData);
    OPENSSL_cleanse(tag, 16);
    return result;
}

QByteArray ChatWidget::decryptChunk(const QByteArray& cipherBlob, const unsigned char* key,
                                     const unsigned char* baseNonce, uint32_t chunkIndex)
{
    if (cipherBlob.size() < 17) return QByteArray(); // tag(16) + 1 byte min

    unsigned char nonce[12];
    memcpy(nonce, baseNonce, 12);
    nonce[8] ^= (chunkIndex >> 24) & 0xFF;
    nonce[9] ^= (chunkIndex >> 16) & 0xFF;
    nonce[10] ^= (chunkIndex >> 8) & 0xFF;
    nonce[11] ^= chunkIndex & 0xFF;

    unsigned char tag[16];
    memcpy(tag, cipherBlob.constData(), 16);
    QByteArray cipher = cipherBlob.mid(16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { OPENSSL_cleanse(nonce, 12); return QByteArray(); }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(nonce, 12);
        return QByteArray();
    }

    QByteArray plainData(cipher.size(), 0);
    int outLen1 = 0, outLen2 = 0;

    if (EVP_DecryptUpdate(ctx, (unsigned char*)plainData.data(), &outLen1,
                          (const unsigned char*)cipher.constData(), cipher.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(nonce, 12);
        return QByteArray();
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    if (EVP_DecryptFinal_ex(ctx, (unsigned char*)plainData.data() + outLen1, &outLen2) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(nonce, 12);
        return QByteArray(); // Authentication failed
    }

    EVP_CIPHER_CTX_free(ctx);
    plainData.resize(outLen1 + outLen2);
    OPENSSL_cleanse(nonce, 12);
    return plainData;
}

bool ChatWidget::encryptAndUploadFile(const QString& filePath, QString& outCID, QString& outKeyHex, QString& outError)
{
#ifndef USE_IPFS
    outError = "IPFS support not compiled in.";
    return false;
#else
    // 1. Read file
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
    {
        outError = QString("Cannot open file: %1").arg(file.errorString());
        return false;
    }
    qint64 fileSize = file.size();

    // Check dynamic size limit
    qint64 maxSize = checkIPFSGateway();
    if (maxSize == 0)
    {
        file.close();
        outError = "IPFS gateway unreachable. Check innova.conf: hyperfilelocal=1 hyperfileip=ipfs.innova-foundation.com:5001";
        return false;
    }
    if (fileSize > maxSize)
    {
        file.close();
        outError = QString("File too large. Maximum: %1 MB for current gateway.").arg(maxSize / (1024 * 1024));
        return false;
    }

    // 2. Generate random AES-256-GCM key (32 bytes) + base nonce (12 bytes)
    unsigned char aesKey[32];
    unsigned char aesNonce[12];
    if (RAND_bytes(aesKey, 32) != 1 || RAND_bytes(aesNonce, 12) != 1)
    {
        file.close();
        OPENSSL_cleanse(aesKey, 32);
        OPENSSL_cleanse(aesNonce, 12);
        outError = "Failed to generate random encryption key.";
        return false;
    }

    // 3. Create IPFS client
    bool fLocal = GetBoolArg("-hyperfilelocal");
    std::string ipfsip = GetArg("-hyperfileip", "ipfs.innova-foundation.com:5001");
    std::unique_ptr<ipfs::Client> client;
    try {
        if (!fLocal)
            throw std::runtime_error("Hyperfile is off. Set hyperfilelocal=1 and "
                                     "hyperfileip=ipfs.innova-foundation.com:5001 in innova.conf. "
                                     "There is no public fallback endpoint.");
        client.reset(new ipfs::Client(ipfsip));
    } catch (const std::exception& e) {
        file.close();
        OPENSSL_cleanse(aesKey, 32);
        OPENSSL_cleanse(aesNonce, 12);
        outError = QString("IPFS client init failed: %1").arg(e.what());
        return false;
    }

    // 4. Encrypt and upload — adaptive chunk size + parallel uploads for large files
    int chunkSize = getChunkSize(fileSize);
    int nParallel = getParallelUploads(fileSize);
    uint32_t nChunks = (uint32_t)((fileSize + chunkSize - 1) / chunkSize);
    QStringList chunkCIDs;
    chunkCIDs.reserve(nChunks);
    for (uint32_t i = 0; i < nChunks; i++) chunkCIDs.append(QString()); // pre-fill slots

    // Cap chunk count to prevent resource exhaustion
    if (nChunks > 500000)
    {
        file.close();
        OPENSSL_cleanse(aesKey, 32);
        OPENSSL_cleanse(aesNonce, 12);
        outError = "File requires too many chunks. Increase chunk size or reduce file.";
        return false;
    }

    // Pipeline: read+encrypt+upload in batches
    // Only nParallel temp files exist at any time
    struct ChunkWork { uint32_t index; QString tempPath; };
    std::string uploadError;
    bool uploadFailed = false;

    for (uint32_t batch = 0; batch < nChunks && !uploadFailed; batch += nParallel)
    {
        uint32_t batchEnd = qMin(batch + (uint32_t)nParallel, nChunks);
        QList<ChunkWork> batchFiles;
        QList<QFuture<QPair<int, QString>>> futures;

        // Read + encrypt this batch
        for (uint32_t i = batch; i < batchEnd; i++)
        {
            QByteArray chunk = file.read(chunkSize);
            if (chunk.isEmpty())
            {
                uploadFailed = true;
                uploadError = QString("Failed to read chunk %1").arg(i).toStdString();
                break;
            }

            QByteArray encChunk = encryptChunk(chunk, aesKey, aesNonce, i);
            OPENSSL_cleanse(chunk.data(), chunk.size());

            if (encChunk.isEmpty())
            {
                uploadFailed = true;
                uploadError = QString("Encryption failed for chunk %1").arg(i).toStdString();
                break;
            }

            QTemporaryFile tempFile;
            tempFile.setAutoRemove(false);
            if (!tempFile.open())
            {
                uploadFailed = true;
                uploadError = "Cannot create temp file.";
                break;
            }
            tempFile.write(encChunk);
            ChunkWork work;
            work.index = i;
            work.tempPath = tempFile.fileName();
            tempFile.close();
            batchFiles.append(work);
        }

        if (uploadFailed)
        {
            for (const ChunkWork& w : batchFiles) QFile::remove(w.tempPath);
            break;
        }

        // Upload batch in parallel
        for (const ChunkWork& w : batchFiles)
        {
            QString tp = w.tempPath;
            int idx = w.index;
            futures.append(QtConcurrent::run([fLocal, ipfsip, tp, idx]() -> QPair<int, QString> {
                try {
                    std::unique_ptr<ipfs::Client> cl;
                    if (!fLocal)
                        throw std::runtime_error("Hyperfile is off. Set hyperfilelocal=1 and "
                                     "hyperfileip=ipfs.innova-foundation.com:5001 in innova.conf. "
                                     "There is no public fallback endpoint.");
                    cl.reset(new ipfs::Client(ipfsip));

                    ipfs::Json add_result;
                    std::string bn = QFileInfo(tp).fileName().toStdString();
                    cl->FilesAdd(
                        {{bn.c_str(), ipfs::http::FileUpload::Type::kFileName, tp.toStdString().c_str()}},
                        &add_result);

                    const std::string& hash = add_result[0]["hash"];
                    if (hash.empty())
                        return qMakePair(idx, QString("ERROR:Empty hash for chunk %1").arg(idx));

                    // Validate CID format
                    QString cidStr = QString::fromStdString(hash);
                    QRegularExpression cidRegex("^[A-Za-z0-9]+$");
                    if (!cidRegex.match(cidStr).hasMatch())
                        return qMakePair(idx, QString("ERROR:Invalid CID format"));

                    return qMakePair(idx, cidStr);
                }
                catch (const std::exception& e)
                {
                    return qMakePair(idx, QString("ERROR:%1").arg(e.what()));
                }
            }));
        }

        // Wait for all futures in batch
        for (int j = 0; j < futures.size(); j++)
        {
            futures[j].waitForFinished();
            QPair<int, QString> result = futures[j].result();
            if (result.second.startsWith("ERROR:") && !uploadFailed)
            {
                uploadFailed = true;
                uploadError = result.second.mid(6).toStdString();
            }
            else if (!result.second.startsWith("ERROR:"))
            {
                chunkCIDs[result.first] = result.second;
            }
        }

        // Cleanup this batch's temp files immediately
        for (const ChunkWork& w : batchFiles) QFile::remove(w.tempPath);
    }

    file.close();

    if (uploadFailed)
    {
        outError = QString("IPFS upload failed: %1").arg(QString::fromStdString(uploadError));
        OPENSSL_cleanse(aesKey, 32);
        OPENSSL_cleanse(aesNonce, 12);
        return false;
    }

    file.close();

    // 5. If single chunk, CID is the chunk CID directly. Otherwise, upload a JSON manifest.
    if (nChunks == 1)
    {
        outCID = chunkCIDs.first();
    }
    else
    {
        // Build manifest: {"v":1,"chunks":["QmXxx","QmYyy",...],"size":12345}
        std::string manifest = "{\"v\":1,\"chunks\":[";
        for (int i = 0; i < chunkCIDs.size(); i++)
        {
            if (i > 0) manifest += ",";
            manifest += "\"" + chunkCIDs[i].toStdString() + "\"";
        }
        manifest += "],\"size\":" + std::to_string(fileSize) + "}";

        // Upload manifest
        QTemporaryFile manifestFile;
        manifestFile.setAutoRemove(false);
        if (!manifestFile.open())
        {
            outError = "Cannot create temp file for manifest.";
            OPENSSL_cleanse(aesKey, 32);
            OPENSSL_cleanse(aesNonce, 12);
            return false;
        }
        QString manifestPath = manifestFile.fileName();
        manifestFile.write(manifest.c_str(), manifest.size());
        manifestFile.close();

        try {
            ipfs::Json add_result;
            std::string basename = QFileInfo(manifestPath).fileName().toStdString();
            client->FilesAdd(
                {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, manifestPath.toStdString().c_str()}},
                &add_result);

            const std::string& hash = add_result[0]["hash"];
            if (hash.empty())
            {
                QFile::remove(manifestPath);
                outError = "IPFS returned empty hash for manifest.";
                OPENSSL_cleanse(aesKey, 32);
                OPENSSL_cleanse(aesNonce, 12);
                return false;
            }
            outCID = QString::fromStdString(hash);
        }
        catch (const std::exception& e)
        {
            QFile::remove(manifestPath);
            outError = QString("Failed to upload manifest: %1").arg(e.what());
            OPENSSL_cleanse(aesKey, 32);
            OPENSSL_cleanse(aesNonce, 12);
            return false;
        }
        QFile::remove(manifestPath);
    }

    // 6. Encode key+nonce as hex (32 bytes key + 12 bytes nonce = 44 bytes = 88 hex chars)
    QByteArray keyAndNonce((const char*)aesKey, 32);
    keyAndNonce.append((const char*)aesNonce, 12);
    outKeyHex = keyAndNonce.toHex();

    // Cleanse all key material
    OPENSSL_cleanse(aesKey, 32);
    OPENSSL_cleanse(aesNonce, 12);
    OPENSSL_cleanse(keyAndNonce.data(), keyAndNonce.size());

    return true;
#endif
}

void ChatWidget::onFileDownloadClicked(const QString& cid, const QString& encKeyHex, const QString& filename)
{
#ifndef USE_IPFS
    QMessageBox::warning(this, tr("Error"), tr("IPFS support not compiled in."));
    return;
#else
    // Sanitize filename from untrusted peer
    QString safeName = QFileInfo(filename).fileName();
    safeName.remove(QRegularExpression("[\\[\\]\\n\\r]"));
    if (safeName.isEmpty()) safeName = "download";

    QString savePath = QFileDialog::getSaveFileName(this, tr("Save File As"), safeName);
    if (savePath.isEmpty())
        return;

    // Run download+decrypt off UI thread
    attachButton->setEnabled(false);
    attachButton->setToolTip(tr("Downloading..."));

    // Capture by value for the worker thread
    QString capCid = cid, capKey = encKeyHex, capSavePath = savePath;
    QtConcurrent::run([this, capCid, capKey, capSavePath]() {
        QByteArray decryptedData;
        bool ok = downloadAndDecryptFile(capCid, capKey, decryptedData);

        QMetaObject::invokeMethod(this, [this, ok, capSavePath, decryptedData]() {
            attachButton->setEnabled(true);
            attachButton->setToolTip(tr("Attach file (encrypted, uploaded via IPFS)"));

            if (!ok)
                return; // Error already shown by downloadAndDecryptFile

            QFile outFile(capSavePath);
            if (!outFile.open(QIODevice::WriteOnly))
            {
                QMessageBox::warning(this, tr("Error"), tr("Cannot write file: %1").arg(outFile.errorString()));
                return;
            }
            outFile.write(decryptedData);
            outFile.close();

            QMessageBox::information(this, tr("File Saved"),
                tr("File saved:\n%1\n\nSize: %2 bytes").arg(capSavePath).arg(decryptedData.size()));
        });
    });
#endif
}

bool ChatWidget::downloadAndDecryptFile(const QString& cid, const QString& encKeyHex, QByteArray& outData)
{
#ifndef USE_IPFS
    return false;
#else
    // 1. Decode key+nonce from hex (32 bytes key + 12 bytes GCM nonce = 44 bytes = 88 hex)
    QByteArray keyAndNonce = QByteArray::fromHex(encKeyHex.toLatin1());
    if (keyAndNonce.size() != 44)
    {
        QMessageBox::warning(this, tr("Error"), tr("Invalid encryption key (expected 88 hex characters)."));
        return false;
    }

    unsigned char aesKey[32];
    unsigned char aesNonce[12];
    memcpy(aesKey, keyAndNonce.constData(), 32);
    memcpy(aesNonce, keyAndNonce.constData() + 32, 12);
    OPENSSL_cleanse(keyAndNonce.data(), keyAndNonce.size());

    // 2. Create IPFS client and download root CID
    bool fLocal = GetBoolArg("-hyperfilelocal");
    std::string ipfsip = GetArg("-hyperfileip", "ipfs.innova-foundation.com:5001");
    std::unique_ptr<ipfs::Client> client;
    QByteArray downloadedBlob;

    // In-memory download cap. The CID is sender-chosen, so check the cap against the stream
    // before copying the buffer; the transport enforces its own cap too.
    const qint64 dlMaxSize = 500 * 1024 * 1024;

    try {
        if (!fLocal)
            throw std::runtime_error("Hyperfile is off. Set hyperfilelocal=1 and "
                                     "hyperfileip=ipfs.innova-foundation.com:5001 in innova.conf. "
                                     "There is no public fallback endpoint.");
        client.reset(new ipfs::Client(ipfsip));

        std::stringstream ss;
        client->FilesGet(cid.toStdString(), &ss);

        const std::streampos got = ss.tellp();
        if (got < 0 || (qint64)got > dlMaxSize)
        {
            OPENSSL_cleanse(aesKey, 32);
            OPENSSL_cleanse(aesNonce, 12);
            QMessageBox::warning(this, tr("Error"), tr("Downloaded data exceeds the 500 MB limit."));
            return false;
        }

        std::string data = ss.str();
        downloadedBlob = QByteArray(data.c_str(), data.size());
    }
    catch (const std::exception& e)
    {
        OPENSSL_cleanse(aesKey, 32);
        OPENSSL_cleanse(aesNonce, 12);
        QMessageBox::warning(this, tr("IPFS Error"),
            tr("Failed to download from IPFS: %1").arg(QString::fromStdString(e.what())));
        return false;
    }

    // Check if this is a chunked manifest or a single encrypted blob
    // Manifest starts with {"v":1,"chunks":
    bool isManifest = (downloadedBlob.size() < 10 * 1024 * 1024) && // manifests are small
                      downloadedBlob.startsWith("{\"v\":");

    if (isManifest)
    {
        // Parse JSON manifest to get chunk CIDs
        std::string manifestStr(downloadedBlob.constData(), downloadedBlob.size());

        // Simple JSON parse for chunk CIDs (no heavy JSON lib dependency)
        QStringList chunkCIDs;
        int chunksStart = manifestStr.find("[");
        int chunksEnd = manifestStr.find("]");
        if (chunksStart < 0 || chunksEnd < 0 || chunksEnd <= chunksStart)
        {
            OPENSSL_cleanse(aesKey, 32);
            OPENSSL_cleanse(aesNonce, 12);
            QMessageBox::warning(this, tr("Error"), tr("Invalid chunk manifest format."));
            return false;
        }

        std::string chunksArray = manifestStr.substr(chunksStart + 1, chunksEnd - chunksStart - 1);
        // Parse "CID1","CID2" format
        size_t pos = 0;
        while ((pos = chunksArray.find('"', pos)) != std::string::npos)
        {
            size_t end = chunksArray.find('"', pos + 1);
            if (end == std::string::npos) break;
            chunkCIDs.append(QString::fromStdString(chunksArray.substr(pos + 1, end - pos - 1)));
            pos = end + 1;
        }

        if (chunkCIDs.isEmpty())
        {
            OPENSSL_cleanse(aesKey, 32);
            OPENSSL_cleanse(aesNonce, 12);
            QMessageBox::warning(this, tr("Error"), tr("Manifest contains no chunk CIDs."));
            return false;
        }

        // Cap chunk count to prevent resource exhaustion (CHAT-CRYPTO-6)
        int maxChunks = (int)(dlMaxSize / CHUNK_SIZE) + 1;
        if (chunkCIDs.size() > maxChunks)
        {
            OPENSSL_cleanse(aesKey, 32);
            OPENSSL_cleanse(aesNonce, 12);
            QMessageBox::warning(this, tr("Error"),
                tr("Manifest has %1 chunks (max %2). File may be malicious.").arg(chunkCIDs.size()).arg(maxChunks));
            return false;
        }

        // Download and decrypt each chunk (with cumulative size tracking)
        outData.clear();
        qint64 cumulativeSize = 0;
        for (int i = 0; i < chunkCIDs.size(); i++)
        {
            QByteArray chunkBlob;
            try {
                std::stringstream ss;
                client->FilesGet(chunkCIDs[i].toStdString(), &ss);
                std::string data = ss.str();
                chunkBlob = QByteArray(data.c_str(), data.size());
            }
            catch (const std::exception& e)
            {
                OPENSSL_cleanse(aesKey, 32);
                OPENSSL_cleanse(aesNonce, 12);
                QMessageBox::warning(this, tr("IPFS Error"),
                    tr("Failed to download chunk %1/%2: %3").arg(i + 1).arg(chunkCIDs.size()).arg(e.what()));
                return false;
            }

            QByteArray plainChunk = decryptChunk(chunkBlob, aesKey, aesNonce, (uint32_t)i);
            if (plainChunk.isEmpty())
            {
                OPENSSL_cleanse(aesKey, 32);
                OPENSSL_cleanse(aesNonce, 12);
                QMessageBox::warning(this, tr("Authentication Failed"),
                    tr("Chunk %1/%2 failed authentication. File may be tampered.").arg(i + 1).arg(chunkCIDs.size()));
                return false;
            }

            cumulativeSize += plainChunk.size();
            if (cumulativeSize > dlMaxSize)
            {
                OPENSSL_cleanse(aesKey, 32);
                OPENSSL_cleanse(aesNonce, 12);
                OPENSSL_cleanse(plainChunk.data(), plainChunk.size());
                QMessageBox::warning(this, tr("Error"), tr("Decrypted data exceeds size limit."));
                return false;
            }
            outData.append(plainChunk);
            OPENSSL_cleanse(plainChunk.data(), plainChunk.size());
        }
    }
    else
    {
        // Single-blob format: tag(16) + ciphertext
        if (downloadedBlob.size() < 17)
        {
            OPENSSL_cleanse(aesKey, 32);
            OPENSSL_cleanse(aesNonce, 12);
            QMessageBox::warning(this, tr("Error"), tr("Downloaded file is too small or empty."));
            return false;
        }

        QByteArray plainChunk = decryptChunk(downloadedBlob, aesKey, aesNonce, 0);
        if (plainChunk.isEmpty())
        {
            OPENSSL_cleanse(aesKey, 32);
            OPENSSL_cleanse(aesNonce, 12);
            QMessageBox::warning(this, tr("Authentication Failed"),
                tr("File authentication failed. Wrong key or tampered data."));
            return false;
        }
        outData = plainChunk;
    }

    OPENSSL_cleanse(aesKey, 32);
    OPENSSL_cleanse(aesNonce, 12);
    return true;
#endif
}

void ChatWidget::onRenameConversationClicked()
{
    if (currentContact.isEmpty())
        return;

    QString currentName = mapContactNicknames.value(currentContact, "");
    bool ok;
    QString nickname = QInputDialog::getText(this, tr("Rename Conversation"),
        tr("Enter a nickname for this contact:"), QLineEdit::Normal, currentName, &ok);
    if (!ok)
        return;

    if (nickname.trimmed().isEmpty())
        mapContactNicknames.remove(currentContact);
    else
        mapContactNicknames[currentContact] = nickname.trimmed();

    // Persist to settings
    {
        QSettings settings;
        settings.beginWriteArray("chatNicknames");
        int idx = 0;
        for (auto it = mapContactNicknames.begin(); it != mapContactNicknames.end(); ++it, ++idx)
        {
            settings.setArrayIndex(idx);
            settings.setValue("address", it.key());
            settings.setValue("name", it.value());
        }
        settings.endArray();
    }

    // Update UI
    chatHeader->setText(tr("  Chat with %1").arg(displayNameFor(currentContact)));
    refreshContacts();
}

void ChatWidget::onDeleteConversationClicked()
{
    if (currentContact.isEmpty() || !msgModel)
        return;

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Delete Conversation"),
        tr("Permanently delete all messages with %1?\n\n"
           "This removes messages from YOUR wallet only. "
           "The other party still has their copy.\n\n"
           "This cannot be undone.")
        .arg(currentContact.left(16) + "..." + currentContact.right(6)),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
        return;

    // Collect row indices for this contact (reverse order to avoid index shifting)
    QList<int> rowsToDelete;
    for (int i = 0; i < msgModel->rowCount(QModelIndex()); i++)
    {
        QString from = msgModel->data(msgModel->index(i, MessageModel::FromAddress, QModelIndex()), Qt::DisplayRole).toString();
        QString to = msgModel->data(msgModel->index(i, MessageModel::ToAddress, QModelIndex()), Qt::DisplayRole).toString();
        if (from == currentContact || to == currentContact)
            rowsToDelete.prepend(i); // prepend so we delete from highest index first
    }

    // Delete from model (which deletes from smessage DB)
    for (int row : rowsToDelete)
        msgModel->removeRows(row, 1);

    // Clear UI
    currentContact.clear();
    showEmptyConversation();
    chatHeader->setText(tr("  Select a conversation"));
    chatHeader->setToolTip(QString());
    sendButton->setEnabled(false);
    deleteConversationButton->setEnabled(false);
    renameConversationButton->setEnabled(false);

    refreshContacts();
}

void ChatWidget::onSendTypingNotification()
{
    // Rate limit: only send if the cooldown timer is not active
    if (typingSendTimer->isActive())
        return;

    if (currentContact.isEmpty())
        return;

    // Get our sending address
    std::string addFrom;
    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_wallet);
        for (const auto& pair : pwalletMain->mapAddressBook)
        {
            if (pair.second == "receive")
            {
                addFrom = CBitcoinAddress(pair.first).ToString();
                break;
            }
        }
        if (addFrom.empty())
        {
            std::set<CKeyID> setKeyID;
            pwalletMain->GetKeys(setKeyID);
            if (!setKeyID.empty())
                addFrom = CBitcoinAddress(*setKeyID.begin()).ToString();
        }
    }

    if (!addFrom.empty())
    {
        SecureMsgSendTyping(addFrom, currentContact.toStdString());
        typingSendTimer->start(); // Start 3s cooldown
    }
}

void ChatWidget::onTypingReceived(const QString& senderAddr)
{
    // Cap to 50 entries to prevent unbounded growth
    if (!mapTypingContacts.contains(senderAddr) && mapTypingContacts.size() >= 50)
        return; // Silently drop — unknown address and map is full

    // Only accept typing from known contacts (addresses in our conversation list)
    bool known = false;
    for (int i = 0; i < contactList->count(); i++)
    {
        if (contactList->item(i)->data(Qt::UserRole).toString() == senderAddr)
        {
            known = true;
            break;
        }
    }
    if (!known)
        return;

    mapTypingContacts[senderAddr] = QDateTime::currentMSecsSinceEpoch();
    updateContactTypingDisplay();
}

void ChatWidget::onTypingTimeout()
{
    // Clear stale typing indicators (older than 5 seconds)
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    bool changed = false;
    QMutableMapIterator<QString, qint64> it(mapTypingContacts);
    while (it.hasNext())
    {
        it.next();
        if (now - it.value() > 5000)
        {
            it.remove();
            changed = true;
        }
    }
    if (changed)
        updateContactTypingDisplay();
}

void ChatWidget::updateContactTypingDisplay()
{
    refreshContacts();
}

void ChatWidget::onNewMessage()
{
    // Update last-read so current contact doesn't flash unread
    if (!currentContact.isEmpty() && isVisible())
        markRead(currentContact);

    refreshContacts();
    if (!currentContact.isEmpty())
        loadConversation(currentContact);
}
