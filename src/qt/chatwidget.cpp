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
#include "nyxsafety.h"
#include "linkpreview.h"
#include "nyxui.h"

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
#include <QBuffer>
#include <QImageReader>
#include <QUrl>
#include <QPainterPath>
#include <QEvent>
#include <QMenu>
#include <QTextBoundaryFinder>

/** Single-line label that elides its text to the available width. */
class NyxElideLabel : public QLabel
{
public:
    explicit NyxElideLabel(const QString& t) : QLabel(), full(t) { setTextFormat(Qt::PlainText); setToolTip(t); }
protected:
    void resizeEvent(QResizeEvent* e) override { QLabel::resizeEvent(e); setText(fontMetrics().elidedText(full, Qt::ElideRight, width())); }
    QSize minimumSizeHint() const override { return QSize(10, QLabel::minimumSizeHint().height()); }
private:
    QString full;
};

static bool isEmojiCp(uint c)
{
    return (c >= 0x1F000 && c <= 0x1FAFF) || (c >= 0x2600 && c <= 0x27BF) || (c >= 0x2B00 && c <= 0x2BFF) ||
           c == 0x200D || c == 0xFE0F || c == 0x20E3 || (c >= 0xE0020 && c <= 0xE007F) || c == 0x00A9 || c == 0x00AE ||
           (c >= 0x2190 && c <= 0x21FF) || (c >= 0x2300 && c <= 0x23FF);
}

/** 1-3 emoji and nothing else. */
static bool isJumboEmoji(const QString& text)
{
    const QString t = text.trimmed();
    if (t.isEmpty()) return false;
    for (uint c : t.toUcs4())
        if (!isEmojiCp(c)) return false;
    QTextBoundaryFinder f(QTextBoundaryFinder::Grapheme, t);
    int n = 0;
    while (f.toNextBoundary() > 0) ++n;
    return n <= 3;
}
#include <QClipboard>
#include <QAbstractTextDocumentLayout>
#include <QResizeEvent>

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

enum ComposerGlyph { GLYPH_ATTACH, GLYPH_EMOJI, GLYPH_LOCK };

static const char* NYX_ACCENT = "#5865F2";
static const char* NYX_IPFS_NOTICE_KEY = "fNyxIpfsNoticeDismissed";

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
        // Filled disc with a cut-out plus.
        p.setPen(Qt::NoPen);
        p.setBrush(c);
        p.drawEllipse(QRectF(1.5, 1.5, 17, 17));
        p.setCompositionMode(QPainter::CompositionMode_Clear);
        p.setPen(QPen(Qt::black, 2.0, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(QPointF(10, 6), QPointF(10, 14));
        p.drawLine(QPointF(6, 10), QPointF(14, 10));
    }
    else if (g == GLYPH_LOCK)
    {
        p.drawArc(QRectF(6.5, 3.0, 7.0, 8.0), 0, 180 * 16);
        p.drawLine(QPointF(6.5, 7.0), QPointF(6.5, 9.0));
        p.drawLine(QPointF(13.5, 7.0), QPointF(13.5, 9.0));
        p.setPen(Qt::NoPen);
        p.setBrush(c);
        p.drawRoundedRect(QRectF(4.5, 9.0, 11.0, 8.5), 2, 2);
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

static QColor mutedColor(const QPalette& pal)
{
    QColor t = pal.color(QPalette::Text);
    t.setAlpha(150);
    return t;
}

static QString cssColor(const QColor& c)
{
    return QString("rgba(%1,%2,%3,%4)").arg(c.red()).arg(c.green()).arg(c.blue()).arg(c.alpha());
}

void ChatWidget::refreshComposerIcons()
{
    const qreal dpr = devicePixelRatioF() > 0 ? devicePixelRatioF() : 1.0;
    const QColor c = mutedColor(palette());
    attachButton->setIcon(composerIcon(GLYPH_ATTACH, c, dpr));
    newChatButton->setIcon(composerIcon(GLYPH_ATTACH, c, dpr));
    emojiButton->setIcon(composerIcon(GLYPH_EMOJI, c, dpr));
    chatHeaderLock->setPixmap(composerIcon(GLYPH_LOCK, c, dpr).pixmap(QSize(16, 16)));
}

QPixmap ChatWidget::avatarFor(const QString& address, const QString& name, int px)
{
    const qreal dpr = devicePixelRatioF() > 0 ? devicePixelRatioF() : 1.0;
    const QString key = address + '\n' + name + '\n' + QString::number(px) + '\n' + QString::number(dpr);
    auto it = mapAvatarCache.constFind(key);
    if (it != mapAvatarCache.constEnd())
        return it.value();

    QPixmap pm(QSize(px, px) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor::fromHsv(NyxAvatarHue(address.toStdString()), 140, 190));
    p.drawEllipse(QRectF(0, 0, px, px));
    QFont f = GUIUtil::emojiFont(qMax(8, px * 2 / 5));
    f.setBold(true);
    p.setFont(f);
    p.setPen(Qt::white);
    p.drawText(QRectF(0, 0, px, px), Qt::AlignCenter,
               QString::fromStdString(NyxInitials(name.toStdString(), address.toStdString())));
    p.end();
    if (mapAvatarCache.size() > 512)
        mapAvatarCache.clear();
    mapAvatarCache.insert(key, pm);
    return pm;
}

/** Message row: hover highlight plus a small action toolbar at the top right. */
class NyxMsgRow : public QWidget
{
public:
    QWidget *toolbar;
    QLabel *timeHint;
    bool fHover;
    explicit NyxMsgRow(QWidget *parent = 0) : QWidget(parent), toolbar(0), timeHint(0), fHover(false)
    {
        setAttribute(Qt::WA_Hover, true);
    }
protected:
#if QT_VERSION >= 0x060000
    void enterEvent(QEnterEvent *) override { setHover(true); }
#else
    void enterEvent(QEvent *) override { setHover(true); }
#endif
    void leaveEvent(QEvent *) override { setHover(false); }
    void resizeEvent(QResizeEvent *e) override { place(); QWidget::resizeEvent(e); }
    void paintEvent(QPaintEvent *) override
    {
        if (!fHover)
            return;
        QPainter p(this);
        QColor c = palette().color(QPalette::Text);
        c.setAlpha(14);
        p.fillRect(rect(), c);
    }
private:
    void place()
    {
        if (!toolbar)
            return;
        toolbar->adjustSize();
        toolbar->move(width() - toolbar->width() - 16, 0);
        toolbar->raise();
    }
    void setHover(bool f)
    {
        fHover = f;
        if (toolbar) { place(); toolbar->setVisible(f); }
        if (timeHint) timeHint->setVisible(f);
        update();
    }
};

ChatWidget::ChatWidget(QWidget *parent) :
    QWidget(parent),
    msgModel(0),
    walletModel(0),
    pendingUploadFileSize(0),
    uploadWatcher(0),
    typingSendPending(false),
    cachedIPFSMaxSize(0),
    ipfsState(-1),
    fUploading(false),
    lastRowTime(0),
    lastRowDay(0)
{
    QHBoxLayout *mainLayout = new QHBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // === Left panel: DM list ===
    QWidget *leftPanel = new QWidget();
    leftPanel->setObjectName("nyxLeft");
    leftPanel->setAttribute(Qt::WA_StyledBackground, true);
    leftPanel->setMinimumWidth(220);
    leftPanel->setMaximumWidth(300);
    leftPanel->setStyleSheet("#nyxLeft { background-color: palette(window); border-right: 1px solid rgba(127,127,127,45); }");
    QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(0);

    QWidget *leftHeader = new QWidget();
    leftHeader->setObjectName("nyxLeftHeader");
    leftHeader->setAttribute(Qt::WA_StyledBackground, true);
    leftHeader->setFixedHeight(48);
    leftHeader->setStyleSheet("#nyxLeftHeader { border-bottom: 1px solid rgba(127,127,127,45); }");
    {
        QHBoxLayout *hl = new QHBoxLayout(leftHeader);
        hl->setContentsMargins(16, 0, 10, 0);
        QLabel *contactsTitle = new QLabel(tr("Nyx Messenger"));
        contactsTitle->setStyleSheet("font-size: 15px; font-weight: bold; color: palette(text); background: transparent;");
        hl->addWidget(contactsTitle, 1);
        newChatButton = new QToolButton();
        newChatButton->setIconSize(QSize(20, 20));
        newChatButton->setFixedSize(28, 28);
        newChatButton->setToolTip(tr("New conversation"));
        newChatButton->setAccessibleName(tr("New conversation"));
        newChatButton->setStyleSheet(
            "QToolButton { border: none; border-radius: 6px; background: transparent; padding: 0px; }"
            "QToolButton:hover { background-color: rgba(127,127,127,50); }"
            "QToolButton:disabled { color: rgba(127,127,127,120); }");
        hl->addWidget(newChatButton);
    }
    leftLayout->addWidget(leftHeader);

    contactList = new QListWidget();
    contactList->setStyleSheet(
        "QListWidget { background-color: transparent; border: none; color: palette(text); padding: 6px 8px; outline: 0; }"
        "QListWidget::item { border: none; border-radius: 6px; margin: 1px 0px; }"
        "QListWidget::item:selected { background-color: rgba(127,127,127,70); }"
        "QListWidget::item:hover:!selected { background-color: rgba(127,127,127,35); }");
    contactList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    contactList->setContextMenuPolicy(Qt::CustomContextMenu);
    contactList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    leftLayout->addWidget(contactList, 1);

    contactsEmptyLabel = new QLabel(tr("No conversations yet.\n\nPress + above and enter an Innova address to start one."));
    contactsEmptyLabel->setWordWrap(true);
    contactsEmptyLabel->setAlignment(Qt::AlignCenter);
    contactsEmptyLabel->setStyleSheet("color: palette(dark); padding: 24px 16px; font-size: 12px;");
    contactsEmptyLabel->hide();
    leftLayout->addWidget(contactsEmptyLabel, 1);

    mainLayout->addWidget(leftPanel);

    // === Right panel: conversation ===
    QWidget *rightPanel = new QWidget();
    rightPanel->setObjectName("nyxRight");
    rightPanel->setAttribute(Qt::WA_StyledBackground, true);
    rightPanel->setStyleSheet("#nyxRight { background-color: palette(base); }");
    QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(0);

    chatHeader = new QWidget();
    chatHeader->setObjectName("nyxChatHeader");
    chatHeader->setAttribute(Qt::WA_StyledBackground, true);
    chatHeader->setFixedHeight(48);
    chatHeader->setStyleSheet("#nyxChatHeader { border-bottom: 1px solid rgba(127,127,127,45); }");
    {
        QHBoxLayout *hl = new QHBoxLayout(chatHeader);
        hl->setContentsMargins(16, 0, 16, 0);
        hl->setSpacing(8);
        chatHeaderAvatar = new QLabel();
        chatHeaderAvatar->setFixedSize(24, 24);
        hl->addWidget(chatHeaderAvatar);
        chatHeaderName = new QLabel();
        chatHeaderName->setTextFormat(Qt::PlainText);
        chatHeaderName->setStyleSheet("font-size: 15px; font-weight: bold; color: palette(text); background: transparent;");
        hl->addWidget(chatHeaderName);
        chatHeaderAddr = new QToolButton();
        chatHeaderAddr->setToolTip(tr("Copy address"));
        chatHeaderAddr->setCursor(Qt::PointingHandCursor);
        chatHeaderAddr->setStyleSheet(
            "QToolButton { border: none; border-radius: 4px; padding: 2px 6px; font-size: 11px; color: palette(dark); background: transparent; }"
            "QToolButton:hover { background-color: rgba(127,127,127,45); color: palette(text); }");
        connect(chatHeaderAddr, &QToolButton::clicked, [this]() {
            if (!currentContact.isEmpty())
                QApplication::clipboard()->setText(currentContact);
        });
        hl->addWidget(chatHeaderAddr);
        hl->addStretch(1);
        chatHeaderLock = new QLabel();
        chatHeaderLock->setFixedSize(16, 16);
        chatHeaderLock->setToolTip(tr("End-to-end encrypted to the recipient's address key"));
        hl->addWidget(chatHeaderLock);
    }
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

    // One-line IPFS notice (hidden by default, dismissal remembered)
    ipfsNotice = new QWidget();
    ipfsNotice->setObjectName("nyxIpfs");
    ipfsNotice->setAttribute(Qt::WA_StyledBackground, true);
    ipfsNotice->setStyleSheet("#nyxIpfs { background-color: rgba(240,178,50,38); border-bottom: 1px solid rgba(240,178,50,90); }");
    {
        QHBoxLayout *nl = new QHBoxLayout(ipfsNotice);
        nl->setContentsMargins(16, 3, 8, 3);
        QLabel *nt = new QLabel(tr("File sharing is off: no IPFS gateway is reachable."));
        nt->setStyleSheet("font-size: 11px; color: palette(text); background: transparent;");
        nt->setToolTip(tr("Set hyperfilelocal=1 or hyperfileip=<host:port> in innova.conf and restart."));
        nt->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        nl->addWidget(nt, 1);
        QToolButton *x = new QToolButton();
        x->setText(QString::fromUtf8("\xC3\x97"));
        x->setAutoRaise(true);
        x->setToolTip(tr("Dismiss"));
        x->setStyleSheet("QToolButton { padding: 0px 4px; border: none; font-size: 13px; background: transparent; }");
        connect(x, &QToolButton::clicked, [this]() {
            ipfsNotice->hide();
            QSettings settings;
            settings.setValue(NYX_IPFS_NOTICE_KEY, true);
        });
        nl->addWidget(x);
    }
    ipfsNotice->hide();
    rightLayout->addWidget(ipfsNotice);

    chatView = new QListWidget();
    chatView->setStyleSheet(
        "QListWidget { background-color: transparent; border: none; outline: 0; }"
        "QListWidget::item { background: transparent; border: none; padding: 0px; }");
    chatView->setWordWrap(true);
    chatView->setSpacing(0);
    chatView->setSelectionMode(QAbstractItemView::NoSelection);
    chatView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    chatView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    chatView->setMouseTracking(true);
    chatView->viewport()->installEventFilter(this);
    rightLayout->addWidget(chatView, 1);

    // Composer: one rounded bar, + on the left, emoji on the right
    QWidget *inputFrame = new QWidget();
    inputFrame->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    QVBoxLayout *inputOuter = new QVBoxLayout(inputFrame);
    inputOuter->setContentsMargins(16, 4, 16, 16);
    inputOuter->setSpacing(4);
    QFrame *composerBar = new QFrame();
    composerBar->setObjectName("nyxComposer");
    composerBar->setStyleSheet("#nyxComposer { background-color: rgba(127,127,127,38); border-radius: 10px; }");
    QHBoxLayout *inputLayout = new QHBoxLayout(composerBar);
    inputLayout->setContentsMargins(10, 4, 8, 4);
    inputLayout->setSpacing(6);

    const QString toolCss =
        "QToolButton { background: transparent; border: none; border-radius: 6px; padding: 0px; }"
        "QToolButton:hover { background-color: rgba(127,127,127,50); }";
    attachButton = new QToolButton();
    attachButton->setStyleSheet(toolCss);
    attachButton->setIconSize(QSize(22, 22));
    attachButton->setFixedSize(32, 32);
    attachButton->setAccessibleName(tr("Attach file"));
    attachButton->setToolTip(tr("Attach file (encrypted, uploaded via IPFS)"));
    inputLayout->addWidget(attachButton, 0, Qt::AlignBottom);

    messageInput = new QTextEdit();
    messageInput->setAcceptRichText(false);
    messageInput->installEventFilter(this);
    messageInput->setFrameShape(QFrame::NoFrame);
    messageInput->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    messageInput->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    messageInput->setStyleSheet("QTextEdit { background: transparent; color: palette(text); border: none; padding: 0px; }");
    messageInput->setFont(GUIUtil::emojiFont(14));
    messageInput->document()->setDocumentMargin(4);
    messageInput->setContextMenuPolicy(Qt::CustomContextMenu);
    inputLayout->addWidget(messageInput, 1);

    emojiButton = new QToolButton();
    emojiButton->setStyleSheet(toolCss);
    emojiButton->setIconSize(QSize(22, 22));
    emojiButton->setFixedSize(32, 32);
    emojiButton->setAccessibleName(tr("Emoji"));
    emojiButton->setToolTip(tr("Open emoji picker"));
    inputLayout->addWidget(emojiButton, 0, Qt::AlignBottom);

    // Send has no button: Enter, Ctrl+Enter, or the composer's context menu.
    sendAction = new QAction(tr("Send message"), this);
    sendAction->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Return));
    sendAction->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    sendAction->setEnabled(false);
    messageInput->addAction(sendAction);
    connect(sendAction, &QAction::triggered, this, &ChatWidget::onSendClicked);
    connect(messageInput, &QTextEdit::customContextMenuRequested, [this](const QPoint& pos) {
        QMenu *menu = messageInput->createStandardContextMenu();
        menu->addSeparator();
        menu->addAction(sendAction);
        menu->exec(messageInput->viewport()->mapToGlobal(pos));
        delete menu;
    });
    connect(messageInput->document()->documentLayout(), &QAbstractTextDocumentLayout::documentSizeChanged,
            this, &ChatWidget::adjustComposerHeight);

    // Emoji picker popup
    emojiPicker = new EmojiPicker(this);
    emojiPicker->hide();
    connect(emojiPicker, &EmojiPicker::emojiSelected, [this](const QString& emoji) {
        messageInput->insertPlainText(emoji);
        messageInput->setFocus();
    });
    connect(emojiButton, &QToolButton::clicked, [this]() {
        QPoint pos = emojiButton->mapToGlobal(QPoint(emojiButton->width() - emojiPicker->width(), -emojiPicker->height() - 8));
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
        previewTimer->start();

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

    // Link preview chip above the composer bar
    previewChip = new QWidget();
    previewChip->setObjectName("nyxChip");
    previewChip->setAttribute(Qt::WA_StyledBackground, true);
    previewChip->setStyleSheet(QString("#nyxChip { background-color: rgba(127,127,127,30); border-left: 3px solid %1; border-radius: 4px; }").arg(NYX_ACCENT));
    {
        QHBoxLayout *pl = new QHBoxLayout(previewChip);
        pl->setContentsMargins(10, 3, 6, 3);
        previewChipText = new QLabel();
        previewChipText->setTextFormat(Qt::PlainText);
        previewChipText->setStyleSheet("color: palette(dark); font-size: 11px; background: transparent;");
        previewChipText->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        pl->addWidget(previewChipText, 1);
        QToolButton *x = new QToolButton();
        x->setText(QString::fromUtf8("\xC3\x97"));
        x->setAutoRaise(true);
        x->setToolTip(tr("Send without a link preview"));
        x->setStyleSheet("QToolButton { padding: 0px 4px; border: none; font-size: 14px; background: transparent; }");
        pl->addWidget(x);
        connect(x, &QToolButton::clicked, [this]() { clearPreview(true); });
    }
    previewChip->hide();
    inputOuter->addWidget(previewChip);
    inputOuter->addWidget(composerBar);

    previewFetcher = new LinkPreviewFetcher(this);
    connect(previewFetcher, &LinkPreviewFetcher::finished, this, &ChatWidget::onPreviewFinished);
    previewTimer = new QTimer(this);
    previewTimer->setSingleShot(true);
    previewTimer->setInterval(700);
    connect(previewTimer, &QTimer::timeout, this, &ChatWidget::schedulePreview);

    rightLayout->addWidget(inputFrame, 0);

    mainLayout->addWidget(rightPanel, 1);

    refreshComposerIcons();
    adjustComposerHeight();

    // Connections
    connect(contactList, SIGNAL(currentRowChanged(int)), this, SLOT(onContactSelected(int)));
    connect(contactList, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(onContactMenu(QPoint)));
    connect(newChatButton, SIGNAL(clicked()), this, SLOT(onNewChatClicked()));
    connect(attachButton, SIGNAL(clicked()), this, SLOT(onFileAttachClicked()));
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

    clearHeaderContact();
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

void ChatWidget::adjustComposerHeight()
{
    const int line = QFontMetrics(messageInput->font()).lineSpacing();
    const int margin = 2 * (int)messageInput->document()->documentMargin();
    const int docH = (int)messageInput->document()->size().height();
    const int h = qBound(line + margin, docH, 6 * line + margin);
    if (messageInput->height() != h)
        messageInput->setFixedHeight(h);
}

bool ChatWidget::canSend() const
{
    return fSecMsgEnabled && !fUploading && !currentContact.isEmpty()
           && !messageInput->toPlainText().trimmed().isEmpty();
}

void ChatWidget::updateAttachState()
{
    const bool fIpfsDown = ipfsState == 0;
    attachButton->setEnabled(fSecMsgEnabled && !fUploading && !fIpfsDown);
    if (fUploading)
        attachButton->setToolTip(tr("Encrypting and uploading..."));
    else if (fIpfsDown)
        attachButton->setToolTip(tr("File sharing needs an IPFS gateway. Set hyperfilelocal=1 or "
                                    "hyperfileip=<host:port> in innova.conf and restart."));
    else
        attachButton->setToolTip(tr("Attach file (encrypted, uploaded via IPFS)"));
}

void ChatWidget::setHeaderContact(const QString& address)
{
    const QString name = displayNameFor(address);
    chatHeaderName->setText(name);
    chatHeaderName->setToolTip(address);
    chatHeaderAvatar->setPixmap(avatarFor(address, name, 24));
    chatHeaderAvatar->show();
    const QString shortAddr = QString::fromStdString(NyxShortAddress(address.toStdString()));
    chatHeaderAddr->setText(shortAddr);
    chatHeaderAddr->setVisible(name != shortAddr && name != address);
    chatHeaderLock->show();
}

void ChatWidget::clearHeaderContact()
{
    chatHeaderName->setText(tr("Select a conversation"));
    chatHeaderName->setToolTip(QString());
    chatHeaderAvatar->hide();
    chatHeaderAddr->hide();
    chatHeaderLock->hide();
}

void ChatWidget::addListWidget(QListWidget *list, QWidget *w, bool fSelectable)
{
    QListWidgetItem *item = new QListWidgetItem();
    if (!fSelectable)
        item->setFlags(Qt::NoItemFlags);
    const int vw = list->viewport()->width();
    const int h = w->hasHeightForWidth() && vw > 0 ? w->heightForWidth(vw) : w->sizeHint().height();
    item->setSizeHint(QSize(0, qMax(h, 1)));
    list->addItem(item);
    list->setItemWidget(item, w);
}

void ChatWidget::relayoutChat()
{
    const int vw = chatView->viewport()->width();
    if (vw <= 0)
        return;
    for (int i = 0; i < chatView->count(); i++)
    {
        QListWidgetItem *item = chatView->item(i);
        QWidget *w = chatView->itemWidget(item);
        if (!w || !w->hasHeightForWidth())
            continue;
        const int h = w->heightForWidth(vw);
        if (h > 0 && item->sizeHint().height() != h)
            item->setSizeHint(QSize(0, h));
    }
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
        connect(msgModel, SIGNAL(embedRemovalsChanged()), this, SLOT(onNewMessage()));
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
            ipfsState = maxSize > 0 ? 1 : 0;
            QSettings settings;
            ipfsNotice->setVisible(maxSize == 0 && !settings.value(NYX_IPFS_NOTICE_KEY, false).toBool());
            updateAttachState();
        });
    });
}

QString ChatWidget::displayNameFor(const QString& address) const
{
    if (address == "anon")
        return tr("Anonymous");
    return QString::fromStdString(NyxDisplayName(address.toStdString(),
                                                 mapContactNicknames.value(address).toStdString(),
                                                 mapBookLabels.value(address).toStdString()));
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

static QWidget* makeSectionHeader(const QString& text)
{
    QLabel *l = new QLabel(text.toUpper());
    l->setTextFormat(Qt::PlainText);
    l->setStyleSheet("font-size: 10px; font-weight: bold; color: palette(dark); padding: 10px 8px 4px 8px; background: transparent;");
    return l;
}

void ChatWidget::refreshContacts()
{
    if (!msgModel)
        return;

    refreshSafetyCache();
    QString prevContact = currentContact;
    contactList->blockSignals(true);
    contactList->clear();

    struct ContactInfo { QString preview; QDateTime last; int unread; bool lastMine; ContactInfo() : unread(0), lastMine(false) {} };
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
        if (!isMine && contactState(contactAddr) == NYX_SENDER_BLOCKED)
            continue;

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

    // Requests first, then direct messages, each newest first.
    QList<QString> requests, direct;
    for (const auto& p : sorted)
        (contactState(p.second) == NYX_SENDER_REQUEST ? requests : direct).append(p.second);

    int restoreRow = -1;
    auto addRow = [&](const QString& addr) {
        const ContactInfo& ci = contacts[addr];

        QString timeStr;
        qint64 secsAgo = ci.last.secsTo(QDateTime::currentDateTime());
        if (secsAgo < 60) timeStr = tr("now");
        else if (secsAgo < 3600) timeStr = tr("%1m").arg(secsAgo / 60);
        else if (secsAgo < 86400) timeStr = tr("%1h").arg(secsAgo / 3600);
        else timeStr = ci.last.toString("MMM d");

        int unread = (addr == currentContact) ? 0 : ci.unread;
        bool typing = mapTypingContacts.contains(addr);
        const QString name = displayNameFor(addr);

        QWidget *row = new QWidget();
        row->setAttribute(Qt::WA_TranslucentBackground);
        QGridLayout *g = new QGridLayout(row);
        g->setContentsMargins(8, 6, 8, 6);
        g->setHorizontalSpacing(10);
        g->setColumnMinimumWidth(2, 36);
        g->setVerticalSpacing(1);

        QLabel *av = new QLabel();
        av->setFixedSize(32, 32);
        av->setPixmap(avatarFor(addr, name, 32));
        av->setStyleSheet("background: transparent;");
        g->addWidget(av, 0, 0, 2, 1, Qt::AlignVCenter);

        QLabel *nameLbl = new NyxElideLabel(name);
        nameLbl->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        nameLbl->setStyleSheet(QString("font-size: 13px; font-weight: %1; color: %2; background: transparent;")
                               .arg(unread ? "bold" : "600", unread ? "palette(text)" : cssColor(mutedColor(palette()))));
        QLabel *when = new QLabel(timeStr);
        when->setStyleSheet("font-size: 10px; color: palette(dark); background: transparent;");
        QString prevText = typing ? tr("typing...") : ((ci.lastMine ? tr("You: ") : QString()) + ci.preview);
        QLabel *prev = new NyxElideLabel(prevText);
        prev->setFont(GUIUtil::emojiFont(11));
        prev->setStyleSheet(QString("font-size: 11px; color: %1; background: transparent;")
                            .arg(typing ? "#23a55a" : (unread ? "palette(text)" : "palette(dark)")));
        prev->setMinimumWidth(10);
        prev->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);

        g->addWidget(nameLbl, 0, 1);
        g->addWidget(when, 0, 2, Qt::AlignRight);
        g->addWidget(prev, 1, 1);
        if (unread > 0)
        {
            QLabel *badge = new QLabel(unread > 99 ? QString("99+") : QString::number(unread));
            badge->setAlignment(Qt::AlignCenter);
            badge->setMinimumWidth(18);
            badge->setStyleSheet("background-color: #f23f43; color: white; border-radius: 8px; font-size: 10px; font-weight: bold; padding: 1px 5px;");
            g->addWidget(badge, 1, 2, Qt::AlignRight);
        }
        g->setColumnStretch(1, 1);

        QListWidgetItem *item = new QListWidgetItem();
        item->setData(Qt::UserRole, addr);
        item->setToolTip(addr);
        item->setSizeHint(QSize(0, 48));
        contactList->addItem(item);
        contactList->setItemWidget(item, row);

        if (addr == prevContact)
            restoreRow = contactList->count() - 1;
    };

    if (!requests.isEmpty())
    {
        addListWidget(contactList, makeSectionHeader(tr("Message Requests - %1").arg(requests.size())));
        for (const QString& a : requests)
            addRow(a);
        addListWidget(contactList, makeSectionHeader(tr("Direct Messages")));
    }
    for (const QString& a : direct)
        addRow(a);

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
    const QString addr = contactList->item(row)->data(Qt::UserRole).toString();
    if (addr.isEmpty())
        return;

    currentContact = addr;
    setHeaderContact(currentContact);
    updateSendButton();

    markRead(currentContact);

    loadConversation(currentContact);
    refreshContacts();
    messageInput->setFocus();
}

void ChatWidget::onContactMenu(const QPoint& pos)
{
    QListWidgetItem *item = contactList->itemAt(pos);
    if (!item)
        return;
    const QString addr = item->data(Qt::UserRole).toString();
    if (addr.isEmpty())
        return;

    QMenu menu(this);
    QAction *aRename = menu.addAction(tr("Rename..."));
    QAction *aCopy = menu.addAction(tr("Copy address"));
    QAction *aRead = menu.addAction(tr("Mark read"));
    QAction *aAccept = 0;
    if (contactState(addr) == NYX_SENDER_REQUEST && addr != "anon")
        aAccept = menu.addAction(tr("Accept request"));
    menu.addSeparator();
    QAction *aBlock = addr != "anon" ? menu.addAction(tr("Block")) : 0;
    QAction *aDelete = menu.addAction(tr("Delete conversation"));

    QAction *chosen = menu.exec(contactList->viewport()->mapToGlobal(pos));
    if (!chosen)
        return;
    if (chosen == aRename)
        renameContact(addr);
    else if (chosen == aCopy)
        QApplication::clipboard()->setText(addr);
    else if (chosen == aRead)
    {
        markRead(addr);
        refreshContacts();
    }
    else if (aAccept && chosen == aAccept)
        acceptContact(addr);
    else if (aBlock && chosen == aBlock)
        blockContact(addr);
    else if (chosen == aDelete)
        deleteConversation(addr);
}

void ChatWidget::addCenteredNote(const QString& text)
{
    QLabel *lbl = new QLabel(text);
    lbl->setTextFormat(Qt::PlainText);
    lbl->setWordWrap(true);
    lbl->setAlignment(Qt::AlignCenter);
    lbl->setStyleSheet("color: palette(dark); font-size: 12px; padding: 32px 24px; background: transparent;");
    addListWidget(chatView, lbl);
}

void ChatWidget::showEmptyConversation()
{
    chatView->clear();
    lastRowSender.clear();
    addCenteredNote(tr("Select a conversation, or press + to message an Innova address.\n\n"
                       "Messages are end-to-end encrypted with the recipient's address key and "
                       "relayed by peers that run Nyx Messenger. Nobody but the recipient can read them."));
}

void ChatWidget::addDateSeparator(const QDate& date)
{
    QString text;
    if (date == QDate::currentDate()) text = tr("Today");
    else if (date == QDate::currentDate().addDays(-1)) text = tr("Yesterday");
    else text = date.toString("MMMM d, yyyy");

    QWidget *w = new QWidget();
    w->setFixedHeight(36);
    QHBoxLayout *h = new QHBoxLayout(w);
    h->setContentsMargins(16, 8, 16, 8);
    h->setSpacing(8);
    auto line = []() {
        QFrame *f = new QFrame();
        f->setFixedHeight(1);
        f->setStyleSheet("background-color: rgba(127,127,127,60); border: none;");
        return f;
    };
    QLabel *lbl = new QLabel(text);
    lbl->setStyleSheet("color: palette(dark); font-size: 11px; font-weight: bold; background: transparent;");
    h->addWidget(line(), 1);
    h->addWidget(lbl);
    h->addWidget(line(), 1);
    addListWidget(chatView, w);
    lastRowSender.clear();
}

void ChatWidget::loadConversation(const QString& address)
{
    chatView->clear();
    lastRowSender.clear();

    if (!msgModel)
        return;

    refreshSafetyCache();
    const int state = contactState(address);
    if (state == NYX_SENDER_BLOCKED)
    {
        addCenteredNote(tr("You blocked this address. Its messages are discarded."));
        return;
    }
    if (state == NYX_SENDER_REQUEST)
        addRequestBar(address);

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

    const std::vector<std::pair<std::string, std::string> > removals = msgModel->embedRemovals();
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
        QString owner = msgModel->data(msgModel->index(row, MessageModel::FromAddress, QModelIndex()), Qt::DisplayRole).toString();

        QString cid, encKeyHex, filename;
        qint64 fileSize;
        if (parseFileMessage(msg, cid, encKeyHex, filename, fileSize))
        {
            addFileBubble(cid, encKeyHex, filename, fileSize, dt, isMine, owner, row);
            continue;
        }
        QString ext = msgModel->data(msgModel->index(row, 0, QModelIndex()), MessageModel::ExtRole).toString();
        NyxEmbed embed;
        bool fEmbed = !ext.isEmpty() && owner != "anon" && NyxDecodeEmbed(ext.toStdString(), embed)
                      && !setHiddenNow.contains(QString::fromStdString(embed.id))
                      && !NyxEmbedHidden(owner.toStdString(), embed.id, removals);
        const bool fRequest = !isMine && state != NYX_SENDER_KNOWN;
        addChatBubble(msg, dt, isMine, false, QString(),
                      fEmbed && !fRequest ? &embed : 0, owner, fRequest, row);
    }

    chatView->scrollToBottom();
}

void ChatWidget::addChatBubble(const QString& text, const QDateTime& when, bool isMine,
                               bool fFailed, const QString& failReason,
                               const NyxEmbed* embed, const QString& owner, bool fRequest, int modelRow)
{
    RowArgs a;
    a.text = text;
    a.when = when;
    a.isMine = isMine;
    a.fFailed = fFailed;
    a.failReason = failReason;
    a.embed = embed;
    a.owner = owner;
    a.fRequest = fRequest;
    a.modelRow = modelRow;
    addMessageRow(a);
}

void ChatWidget::addFileBubble(const QString& cid, const QString& encKeyHex,
                               const QString& filename, qint64 size, const QDateTime& when, bool isMine,
                               const QString& owner, int modelRow)
{
    RowArgs a;
    a.when = when;
    a.isMine = isMine;
    a.owner = owner;
    a.modelRow = modelRow;
    a.fFile = true;
    a.cid = cid;
    a.encKeyHex = encKeyHex;
    a.filename = filename;
    a.fileSize = size;
    addMessageRow(a);
}

void ChatWidget::addMessageRow(const RowArgs& a)
{
    const QString senderKey = a.isMine ? QString("\x01me") : (a.owner.isEmpty() ? currentContact : a.owner);
    const qint64 t = a.when.toSecsSinceEpoch();
    const qint64 day = a.when.date().toJulianDay();
    const bool fGrouped = !a.fFailed && NyxGroupsWith(lastRowSender.toStdString(), lastRowTime, (int)lastRowDay,
                                                      senderKey.toStdString(), t, (int)day);
    lastRowSender = a.fFailed ? QString() : senderKey;
    lastRowTime = t;
    lastRowDay = day;

    const QString addr = a.isMine ? a.owner : (a.owner.isEmpty() ? currentContact : a.owner);
    const QString name = a.isMine ? myDisplayName() : displayNameFor(addr);
    const QString timeShort = a.when.toString("hh:mm");

    NyxMsgRow *rowW = new NyxMsgRow();
    QHBoxLayout *rl = new QHBoxLayout(rowW);
    rl->setContentsMargins(16, fGrouped ? 0 : 16, 48, 1);
    rl->setSpacing(14);

    // Avatar column: avatar on a group's first row, hover time on the rest.
    QWidget *col = new QWidget();
    col->setFixedWidth(40);
    QVBoxLayout *cl = new QVBoxLayout(col);
    cl->setContentsMargins(0, fGrouped ? 2 : 0, 0, 0);
    cl->setSpacing(0);
    if (fGrouped)
    {
        QLabel *th = new QLabel(timeShort);
        th->setAlignment(Qt::AlignRight | Qt::AlignTop);
        th->setStyleSheet("font-size: 9px; color: palette(dark); background: transparent;");
        th->hide();
        cl->addWidget(th);
        rowW->timeHint = th;
    }
    else
    {
        QLabel *av = new QLabel();
        av->setFixedSize(40, 40);
        av->setPixmap(a.isMine ? avatarFor(QStringLiteral("nyx-self"), name, 40) : avatarFor(addr.isEmpty() ? name : addr, name, 40));
        av->setToolTip(addr);
        av->setStyleSheet("background: transparent;");
        cl->addWidget(av);
    }
    cl->addStretch(1);
    rl->addWidget(col, 0);

    QVBoxLayout *bl = new QVBoxLayout();
    bl->setContentsMargins(0, 0, 0, 0);
    bl->setSpacing(3);
    rl->addLayout(bl, 1);

    if (!fGrouped)
    {
        QLabel *hdr = new QLabel();
        hdr->setTextFormat(Qt::RichText);
        QString day;
        if (a.when.date() == QDate::currentDate()) day = tr("Today at %1").arg(timeShort);
        else if (a.when.date() == QDate::currentDate().addDays(-1)) day = tr("Yesterday at %1").arg(timeShort);
        else day = a.when.toString("MM/dd/yyyy hh:mm");
        hdr->setText(QString("<span style=\"font-weight: bold; font-size: 14px; color: palette(text);\">%1</span>"
                             "&nbsp;&nbsp;<span style=\"font-size: 11px; color: palette(dark);\">%2</span>")
                     .arg(name.toHtmlEscaped(), day.toHtmlEscaped()));
        hdr->setToolTip(addr);
        hdr->setFont(GUIUtil::emojiFont(14));
        hdr->setStyleSheet("background: transparent;");
        bl->addWidget(hdr);
    }

    if (!a.fFile && !a.isMine && NyxLooksLikeScam(a.text.toStdString()))
    {
        QLabel *warn = new QLabel(tr("Warning: this message asks for a recovery phrase, private key or wallet "
                                     "\"verification\". It is almost certainly a scam.") + "\n" + tr(NYX_SECRET_WARNING));
        warn->setTextFormat(Qt::PlainText);
        warn->setWordWrap(true);
        warn->setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; font-size: 11px;"
                            " border-radius: 6px; padding: 6px;");
        bl->addWidget(warn);
    }

    if (a.fFile)
    {
        QFrame *card = new QFrame();
        card->setObjectName("nyxFile");
        card->setStyleSheet(QString("QFrame#nyxFile { background-color: rgba(127,127,127,30); border: 1px solid rgba(127,127,127,60);"
                                    " border-radius: 8px; } QLabel { background: transparent; }"));
        card->setMaximumWidth(420);
        QHBoxLayout *fl = new QHBoxLayout(card);
        fl->setContentsMargins(12, 10, 12, 10);
        QString sizeStr;
        if (a.fileSize < 1024) sizeStr = QString("%1 B").arg(a.fileSize);
        else if (a.fileSize < 1024 * 1024) sizeStr = QString("%1 KB").arg(a.fileSize / 1024);
        else sizeStr = QString("%1 MB").arg(a.fileSize / (1024 * 1024));
        QLabel *fileLabel = new QLabel();
        fileLabel->setTextFormat(Qt::RichText);
        fileLabel->setText(QString("<span style=\"color: %3; font-weight: bold;\">%1</span><br>"
                                   "<span style=\"font-size: 11px; color: palette(dark);\">%2 | %4</span>")
                           .arg(a.filename.toHtmlEscaped(), sizeStr, NYX_ACCENT, tr("Encrypted")));
        fileLabel->setWordWrap(true);
        fl->addWidget(fileLabel, 1);
        QPushButton *dlButton = new QPushButton(tr("Download"));
        dlButton->setStyleSheet(QString(
            "QPushButton { background-color: %1; color: white; border: none; border-radius: 4px; padding: 5px 12px; font-weight: bold; font-size: 11px; }"
            "QPushButton:hover { background-color: #4752C4; }").arg(NYX_ACCENT));
        const QString capCid = a.cid, capKey = a.encKeyHex, capName = a.filename;
        connect(dlButton, &QPushButton::clicked, [this, capCid, capKey, capName]() {
            onFileDownloadClicked(capCid, capKey, capName);
        });
        fl->addWidget(dlButton, 0, Qt::AlignVCenter);
        QHBoxLayout *wrap = new QHBoxLayout();
        wrap->addWidget(card);
        wrap->addStretch(1);
        bl->addLayout(wrap);
    }
    else
    {
        // Untrusted text: everything is escaped; only http(s) anchors are added. Links open via a confirm.
        // A message request gets no anchors at all.
        QLabel *body = new QLabel();
        body->setTextFormat(Qt::RichText);
        const std::string html = a.fRequest ? NyxEscapeText(a.text.toStdString()) : NyxLinkify(a.text.toStdString());
        body->setText("<span style=\"white-space: pre-wrap;\">" + QString::fromStdString(html) + "</span>");
        body->setOpenExternalLinks(false);
        body->setWordWrap(true);
        body->setTextInteractionFlags(a.fRequest ? Qt::TextSelectableByMouse
                                                 : (Qt::TextSelectableByMouse | Qt::LinksAccessibleByMouse));
        connect(body, &QLabel::linkActivated, this, &ChatWidget::confirmOpenUrl);
        body->setFont(GUIUtil::emojiFont(!a.fFile && isJumboEmoji(a.text) ? 42 : 14));
        body->setStyleSheet(QString(a.fFailed ? "background: transparent; color: palette(dark);"
                                              : "background: transparent; color: palette(text);") +
                            (!a.fFile && isJumboEmoji(a.text) ? " font-size: 42px;" : ""));
        body->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        bl->addWidget(body);
        if (a.embed)
        {
            QHBoxLayout *wrap = new QHBoxLayout();
            wrap->addWidget(makeEmbedCard(*a.embed, a.isMine && !a.fFailed && !a.owner.isEmpty(), a.owner));
            wrap->addStretch(1);
            bl->addLayout(wrap);
        }
    }

    if (a.fFailed)
    {
        QLabel *st = new QLabel(tr("Not sent"));
        st->setStyleSheet("background: transparent; font-size: 11px; color: #f23f43;");
        st->setToolTip(a.failReason);
        bl->addWidget(st);
    }

    // Hover toolbar
    QWidget *tb = new QWidget(rowW);
    tb->setObjectName("nyxTools");
    tb->setAttribute(Qt::WA_StyledBackground, true);
    tb->setStyleSheet("#nyxTools { background-color: palette(window); border: 1px solid rgba(127,127,127,70); border-radius: 6px; }"
                      "QToolButton { border: none; border-radius: 4px; padding: 2px 6px; font-size: 11px; color: palette(text); background: transparent; }"
                      "QToolButton:hover { background-color: rgba(127,127,127,50); }");
    QHBoxLayout *tl = new QHBoxLayout(tb);
    tl->setContentsMargins(2, 2, 2, 2);
    tl->setSpacing(0);
    auto tool = [&](const QString& label, const QString& tip) {
        QToolButton *b = new QToolButton();
        b->setText(label);
        b->setToolTip(tip);
        b->setAccessibleName(tip);
        tl->addWidget(b);
        return b;
    };
    const QString copyText = a.fFile ? a.filename : a.text;
    connect(tool(tr("Copy"), tr("Copy text")), &QToolButton::clicked, [copyText]() {
        QApplication::clipboard()->setText(copyText);
    });
    if (!addr.isEmpty() && addr != "anon")
        connect(tool(tr("Address"), tr("Copy sender address")), &QToolButton::clicked, [addr]() {
            QApplication::clipboard()->setText(addr);
        });
    if (a.modelRow >= 0)
    {
        const int mrow = a.modelRow;
        connect(tool(tr("Delete"), tr("Delete from this wallet only")), &QToolButton::clicked,
                [this, mrow]() { QTimer::singleShot(0, this, [this, mrow]() { deleteMessageRow(mrow); }); });
    }
    tb->hide();
    rowW->toolbar = tb;

    addListWidget(chatView, rowW);
}

void ChatWidget::deleteMessageRow(int modelRow)
{
    if (!msgModel || modelRow < 0 || modelRow >= msgModel->rowCount(QModelIndex()))
        return;
    if (QMessageBox::question(this, tr("Delete message"),
            tr("Delete this message from your wallet? The other party keeps their copy."),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;
    msgModel->removeRows(modelRow, 1);
    refreshContacts();
    if (!currentContact.isEmpty())
        loadConversation(currentContact);
}

void ChatWidget::refreshMessagingEnabled()
{
    const bool fEnabled = fSecMsgEnabled;

    messagingDisabledBanner->setVisible(!fEnabled);
    enableMessagingButton->setVisible(!GetBoolArg("-nosmsg", false));

    messageInput->setReadOnly(!fEnabled);
    messageInput->setPlaceholderText(fEnabled
        ? tr("Message")
        : tr("Nyx Messenger is off. Enable it above or in Settings > Options > Messaging."));

    updateAttachState();
    newChatButton->setEnabled(fEnabled);
    updateSendButton();
}

void ChatWidget::updateSendButton()
{
    sendAction->setEnabled(canSend());
}

static const char* NYX_PREF_KEY = "fNyxMessenger";
static const char* NYX_PREVIEW_KEY = "fNyxLinkPreviews";

bool ChatWidget::linkPreviewsEnabled()
{
    QSettings settings;
    return settings.value(NYX_PREVIEW_KEY, true).toBool();
}

void ChatWidget::setLinkPreviewsEnabled(bool fEnable)
{
    QSettings settings;
    settings.setValue(NYX_PREVIEW_KEY, fEnable);
}

void ChatWidget::schedulePreview()
{
    QString text = messageInput->toPlainText();
    QString url = QString::fromStdString(NyxStripTracking(NyxFirstHttpsUrl(text.toStdString())));
    if (url.isEmpty() || !fSecMsgEnabled || !linkPreviewsEnabled() || isFileMessage(text.trimmed()))
    {
        clearPreview(false);
        return;
    }
    if (url == previewDismissedUrl || url == previewUrl || url == previewFetcher->currentUrl())
        return;
    clearPreview(false);
    if (!previewFetcher->start(url))
        return;
    previewChipText->setText(tr("Fetching link preview from %1 through Tor ...").arg(QUrl(url).host()));
    previewChip->show();
}

void ChatWidget::onPreviewFinished(const QString& url, bool ok, const QString& title, const QString& desc,
                                   const QString& site, const QByteArray& thumb)
{
    if (!ok || QString::fromStdString(NyxStripTracking(NyxFirstHttpsUrl(messageInput->toPlainText().toStdString()))) != url)
    {
        previewChip->hide();
        return;
    }
    previewUrl = url;
    previewTitle = title;
    previewDesc = desc;
    previewSite = site;
    previewThumb = thumb;
    QString shown = title.isEmpty() ? desc : title;
    previewChipText->setText(tr("Link preview: %1").arg(shown.left(80)));
    previewChip->show();
}

void ChatWidget::clearPreview(bool fDismiss)
{
    if (fDismiss)
        previewDismissedUrl = !previewUrl.isEmpty() ? previewUrl : previewFetcher->currentUrl();
    previewFetcher->cancel();
    previewUrl.clear();
    previewTitle.clear();
    previewDesc.clear();
    previewSite.clear();
    previewThumb.clear();
    previewChip->hide();
}

QWidget* ChatWidget::makeEmbedCard(const NyxEmbed& e, bool fRemovable, const QString& owner)
{
    QFrame *card = new QFrame();
    card->setObjectName("embed");
    card->setStyleSheet("QFrame#embed { background-color: rgba(127,127,127,40); border-left: 3px solid #5865F2;"
                        " border-radius: 4px; } QLabel { background: transparent; }");
    card->setMaximumWidth(400);
    QGridLayout *g = new QGridLayout(card);
    g->setContentsMargins(10, 8, 6, 8);
    g->setHorizontalSpacing(8);
    g->setVerticalSpacing(2);

    QLabel *site = new QLabel(QString::fromStdString(e.site));
    site->setTextFormat(Qt::PlainText);
    site->setStyleSheet("font-size: 10px; opacity: 0.8;");
    g->addWidget(site, 0, 0);

    const QString url = QString::fromStdString(e.url);
    if (!e.title.empty())
    {
        QLabel *title = new QLabel(QString("<a href=\"%1\">%2</a>")
            .arg(QString::fromStdString(NyxHtmlEscape(e.url)), QString::fromStdString(NyxHtmlEscape(e.title))));
        title->setTextFormat(Qt::RichText);
        title->setOpenExternalLinks(false);
        title->setWordWrap(true);
        title->setTextInteractionFlags(Qt::LinksAccessibleByMouse);
        title->setStyleSheet("font-size: 13px; font-weight: bold;");
        title->setToolTip(url);
        connect(title, &QLabel::linkActivated, this, &ChatWidget::confirmOpenUrl);
        g->addWidget(title, 1, 0);
    }
    if (!e.desc.empty())
    {
        QLabel *desc = new QLabel(QString::fromStdString(e.desc));
        desc->setTextFormat(Qt::PlainText);
        desc->setWordWrap(true);
        desc->setFont(GUIUtil::emojiFont(12));
        desc->setMaximumHeight(QFontMetrics(desc->font()).lineSpacing() * 3 + 2);
        g->addWidget(desc, 2, 0);
    }

    if (!e.thumb.empty())
    {
        QByteArray data(e.thumb.data(), (int)e.thumb.size());
        QBuffer buf(&data);
        buf.open(QIODevice::ReadOnly);
        QImageReader rd(&buf, "jpeg");
        rd.setAllocationLimit(1);
        QSize sz = rd.size();
        if (sz.isValid() && sz.width() <= 256 && sz.height() <= 256)
        {
            rd.setScaledSize(QSize(64, 64));
            QImage img = rd.read();
            if (!img.isNull())
            {
                QLabel *th = new QLabel();
                th->setPixmap(QPixmap::fromImage(img));
                th->setFixedSize(64, 64);
                g->addWidget(th, 0, 1, 3, 1, Qt::AlignTop);
            }
        }
    }

    if (fRemovable)
    {
        QToolButton *x = new QToolButton();
        x->setText(QString::fromUtf8("\xC3\x97"));
        x->setAutoRaise(true);
        x->setFixedSize(18, 18);
        x->setToolTip(tr("Remove this preview for everyone"));
        x->setStyleSheet("QToolButton { padding: 0px; border: none; font-size: 13px; }");
        const QString id = QString::fromStdString(e.id);
        connect(x, &QToolButton::clicked, [this, id, owner]() { removeEmbed(id, owner); });
        g->addWidget(x, 0, 2, Qt::AlignTop | Qt::AlignRight);
    }
    g->setColumnStretch(0, 1);
    return card;
}

void ChatWidget::removeEmbed(const QString& id, const QString& owner)
{
    if (currentContact.isEmpty() || owner.isEmpty() || owner == "anon")
        return;
    std::string from = owner.toStdString(), to = currentContact.toStdString();
    std::string plain = NyxRemovalPlain(id.toStdString()), sError;
    if (SecureMsgSend(from, to, plain, sError) != 0)
    {
        QMessageBox::warning(this, tr("Remove preview"), QString::fromStdString(sError));
        return;
    }
    setHiddenNow.insert(id);
    loadConversation(currentContact);
}

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

void ChatWidget::confirmOpenUrl(const QString& linkIn)
{
    const std::string link = NyxStripTracking(linkIn.toStdString());
    if (!NyxIsLinkableUrl(link))
        return;
    QUrl url(QString::fromStdString(link), QUrl::StrictMode);
    if (!url.isValid() || (url.scheme() != "https" && url.scheme() != "http") || url.host().isEmpty())
        return;
    const std::string host = NyxUrlHost(link);
    const QString domain = QString::fromStdString(NyxRegistrableDomain(host));
    const int flags = NyxUrlRiskFlags(link);

    QString html = tr("You are leaving Innova for:") + "<p style=\"font-size: 20px; font-weight: bold;\">"
                   + domain.toHtmlEscaped() + "</p>";
    QStringList warnings;
    if (flags & NYX_URL_LOOKALIKE)
        warnings << tr("This address uses characters from other alphabets that can imitate a familiar site (shown as %1).")
                        .arg(QUrl::fromAce(QByteArray::fromStdString(host)).toHtmlEscaped());
    else if (flags & NYX_URL_IDN)
        warnings << tr("This is an internationalised domain, shown as %1.")
                        .arg(QUrl::fromAce(QByteArray::fromStdString(host)).toHtmlEscaped());
    if (flags & NYX_URL_HIDDEN_CHARS)
        warnings << tr("The link contains invisible or text-direction characters that can disguise where it goes.");
    if (url.scheme() == "http")
        warnings << tr("The connection is not encrypted (http).");
    for (const QString& w : warnings)
        html += "<p style=\"color: #c0392b; font-weight: bold;\">" + w + "</p>";
    html += "<p style=\"font-size: 11px;\">" + QString::fromStdString(link).toHtmlEscaped() + "</p>";

    QMessageBox box(QMessageBox::Warning, tr("Open link"), html, QMessageBox::NoButton, this);
    box.setTextFormat(Qt::RichText);
    QPushButton *open = box.addButton(tr("Open"), QMessageBox::AcceptRole);
    QPushButton *cancel = box.addButton(QMessageBox::Cancel);
    box.setDefaultButton(cancel);
    box.setEscapeButton(cancel);
    box.exec();
    if (box.clickedButton() == open)
        QDesktopServices::openUrl(url);
}

int ChatWidget::contactState(const QString& address) const
{
    const std::string a = address.toStdString();
    return NyxClassifySender(a, setSentTo.contains(address), setAddressBook.contains(address),
                             NyxIsAccepted(a), NyxIsBlocked(a));
}

void ChatWidget::refreshSafetyCache()
{
    std::set<std::string> sent, book;
    SecureMsgCollectSentTo(sent);
    SecureMsgCollectAddressBook(book);
    setSentTo.clear();
    setAddressBook.clear();
    for (const std::string& a : sent)
        setSentTo.insert(QString::fromStdString(a));
    for (const std::string& a : book)
        setAddressBook.insert(QString::fromStdString(a));
    mapBookLabels.clear();
    if (pwalletMain)
    {
        LOCK(pwalletMain->cs_wallet);
        for (const auto& pair : pwalletMain->mapAddressBook)
            if (!pair.second.empty())
                mapBookLabels.insert(QString::fromStdString(CBitcoinAddress(pair.first).ToString()),
                                     QString::fromStdString(pair.second));
    }
    if (msgModel)
        for (int i = 0; i < msgModel->rowCount(QModelIndex()); i++)
            if (msgModel->data(msgModel->index(i, 0, QModelIndex()), MessageModel::TypeRole).toInt() == MessageTableEntry::Sent)
                setSentTo.insert(msgModel->data(msgModel->index(i, MessageModel::ToAddress, QModelIndex()), Qt::DisplayRole).toString());
}

void ChatWidget::addRequestBar(const QString& address)
{
    QFrame *bar = new QFrame();
    bar->setObjectName("request");
    bar->setStyleSheet("QFrame#request { background-color: palette(alternate-base); border: 1px solid palette(mid);"
                       " border-radius: 8px; } QLabel { background: transparent; color: palette(text); }");
    QVBoxLayout *v = new QVBoxLayout(bar);
    v->setContentsMargins(12, 10, 12, 10);
    QLabel *t = new QLabel(address == "anon"
        ? tr("Anonymous message. Links stay inactive and link previews are hidden.")
        : tr("Message request from %1. You have not messaged this address and it is not in your address book. "
             "Links stay inactive and link previews are hidden until you accept.").arg(address));
    t->setTextFormat(Qt::PlainText);
    t->setWordWrap(true);
    v->addWidget(t);
    if (address != "anon")
    {
        QHBoxLayout *h = new QHBoxLayout();
        QPushButton *accept = new QPushButton(tr("Accept"));
        QPushButton *block = new QPushButton(tr("Block"));
        block->setStyleSheet("QPushButton { color: #c0392b; }");
        h->addWidget(accept);
        h->addWidget(block);
        h->addStretch();
        v->addLayout(h);
        connect(accept, &QPushButton::clicked, this, [this, address]() { acceptContact(address); });
        connect(block, &QPushButton::clicked, this, [this, address]() { blockContact(address); });
    }
    QWidget *wrap = new QWidget();
    QHBoxLayout *wl = new QHBoxLayout(wrap);
    wl->setContentsMargins(16, 10, 16, 6);
    wl->addWidget(bar);
    addListWidget(chatView, wrap);
}

void ChatWidget::acceptContact(const QString& address)
{
    if (!NyxAccept(address.toStdString()))
        QMessageBox::warning(this, tr("Accept"), tr("Could not save the contact list."));
    loadConversation(currentContact);
    refreshContacts();
}

void ChatWidget::blockContact(const QString& address)
{
    if (QMessageBox::question(this, tr("Block"),
            tr("Block %1? Its messages are deleted and future messages from it are discarded.").arg(address),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;
    if (!NyxBlock(address.toStdString()))
    {
        QMessageBox::warning(this, tr("Block"), tr("Could not save the block list."));
        return;
    }
    SecureMsgDiscardFrom(address.toStdString());
    if (currentContact == address)
    {
        currentContact.clear();
        clearHeaderContact();
        showEmptyConversation();
        updateSendButton();
    }
    refreshContacts();
}

void ChatWidget::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::PaletteChange || event->type() == QEvent::StyleChange)
    {
        mapAvatarCache.clear();
        refreshComposerIcons();
    }
    QWidget::changeEvent(event);
}

bool ChatWidget::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == chatView->viewport() && event->type() == QEvent::Resize)
        QTimer::singleShot(0, this, &ChatWidget::relayoutChat);
    if (obj == messageInput && event->type() == QEvent::Resize)
        QTimer::singleShot(0, this, &ChatWidget::adjustComposerHeight);
    if (obj == messageInput && event->type() == QEvent::KeyPress)
    {
        QKeyEvent *ke = static_cast<QKeyEvent*>(event);
        if ((ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter)
            && !(ke->modifiers() & Qt::ShiftModifier)
            && !emojiAutocomplete->isVisible())
        {
            if (canSend())
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
    message = QString::fromStdString(NyxStripTrackingInText(message.toStdString()));

    NyxSecretKind secret = isFileMessage(message) ? NYX_SECRET_NONE : NyxDetectSecret(message.toStdString());
    if (secret != NYX_SECRET_NONE)
    {
        QMessageBox box(QMessageBox::Critical, tr("Do not send this"),
                        tr("This message looks like it contains a %1.")
                            .arg(QString::fromStdString(NyxSecretKindName(secret)))
                        + "\n\n" + tr(NYX_SECRET_WARNING)
                        + "\n\n" + tr("Anyone who has it can take your coins."),
                        QMessageBox::NoButton, this);
        QPushButton *cancel = box.addButton(tr("Don't send"), QMessageBox::RejectRole);
        QPushButton *force = box.addButton(tr("Send anyway"), QMessageBox::DestructiveRole);
        box.setDefaultButton(cancel);
        box.setEscapeButton(cancel);
        box.exec();
        if (box.clickedButton() != force)
            return;
    }

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
    QDateTime now = QDateTime::currentDateTime();

    std::string sendTo = currentContact.toStdString();
    std::string msgText = message.toStdString();
    NyxEmbed sentEmbed;
    bool fSentEmbed = false;
    if (!fFile && !previewUrl.isEmpty() && previewUrl != previewDismissedUrl
        && QString::fromStdString(NyxFirstHttpsUrl(msgText)) == previewUrl)
    {
        unsigned char rnd[8];
        if (RAND_bytes(rnd, sizeof(rnd)) == 1)
        {
            sentEmbed.id = QByteArray((const char*)rnd, sizeof(rnd)).toHex().toStdString();
            sentEmbed.url = previewUrl.toStdString();
            sentEmbed.title = previewTitle.toStdString();
            sentEmbed.desc = previewDesc.toStdString();
            sentEmbed.site = previewSite.toStdString();
            sentEmbed.thumb = std::string(previewThumb.constData(), previewThumb.size());
            std::string ext = NyxFitEmbed(msgText, sentEmbed, SMSG_MAX_MSG_BYTES);
            NyxEmbed check;
            if (!ext.empty() && NyxDecodeEmbed(ext, check))
            {
                msgText = NyxComposePlain(msgText, ext);
                sentEmbed = check;
                fSentEmbed = true;
            }
        }
    }
    if (SecureMsgSend(addFrom, sendTo, msgText, sError) != 0)
    {
        QString reason = QString::fromStdString(sError);
        if (reason.contains("public key", Qt::CaseInsensitive))
            reason += tr("\nThe recipient's public key is not known yet. It is learned once they send you "
                         "a message or have sent any transaction from that address.");
        // Text stays in the composer so it can be retried.
        addChatBubble(message, now, true, true, reason, 0, QString::fromStdString(addFrom));
        chatView->scrollToBottom();
        return;
    }

    messageInput->clear();
    clearPreview(false);

    // Model refresh rebuilds the view; paint now so the send feels immediate.
    if (fFile)
        addFileBubble(cid, encKeyHex, filename, fileSize, now, true, QString::fromStdString(addFrom));
    else
        addChatBubble(message, now, true, false, QString(), fSentEmbed ? &sentEmbed : 0,
                      QString::fromStdString(addFrom));
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
    fUploading = true;
    updateAttachState();
    updateSendButton();

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
    fUploading = false;
    updateAttachState();
    updateSendButton();

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

void ChatWidget::renameContact(const QString& address)
{
    if (address.isEmpty())
        return;

    QString currentName = mapContactNicknames.value(address, "");
    bool ok;
    QString nickname = QInputDialog::getText(this, tr("Rename Conversation"),
        tr("Enter a nickname for this contact:"), QLineEdit::Normal, currentName, &ok);
    if (!ok)
        return;

    if (nickname.trimmed().isEmpty())
        mapContactNicknames.remove(address);
    else
        mapContactNicknames[address] = nickname.trimmed();

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
    mapAvatarCache.clear();
    if (address == currentContact)
    {
        setHeaderContact(currentContact);
        loadConversation(currentContact);
    }
    refreshContacts();
}

void ChatWidget::deleteConversation(const QString& address)
{
    if (address.isEmpty() || !msgModel)
        return;

    QMessageBox::StandardButton reply = QMessageBox::question(this, tr("Delete Conversation"),
        tr("Permanently delete all messages with %1?\n\n"
           "This removes messages from YOUR wallet only. "
           "The other party still has their copy.\n\n"
           "This cannot be undone.")
        .arg(displayNameFor(address)),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes)
        return;

    // Collect row indices for this contact (reverse order to avoid index shifting)
    QList<int> rowsToDelete;
    for (int i = 0; i < msgModel->rowCount(QModelIndex()); i++)
    {
        QString from = msgModel->data(msgModel->index(i, MessageModel::FromAddress, QModelIndex()), Qt::DisplayRole).toString();
        QString to = msgModel->data(msgModel->index(i, MessageModel::ToAddress, QModelIndex()), Qt::DisplayRole).toString();
        if (from == address || to == address)
            rowsToDelete.prepend(i); // prepend so we delete from highest index first
    }

    // Delete from model (which deletes from smessage DB)
    for (int row : rowsToDelete)
        msgModel->removeRows(row, 1);

    if (address == currentContact)
    {
        currentContact.clear();
        showEmptyConversation();
        clearHeaderContact();
        updateSendButton();
    }

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
