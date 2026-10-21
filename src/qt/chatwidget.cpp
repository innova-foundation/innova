#include "chatwidget.h"
#include "messagemodel.h"
#include "walletmodel.h"
#include "smessage.h"
#include "guiutil.h"
#include "wallet.h"
#include "init.h"
#include "base58.h"
#include "emojipicker.h"
#include "nyxembed.h"
#include "nyxext.h"
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
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QPointer>
#include <QPlainTextEdit>
#include <QIcon>
#include <functional>

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

enum ComposerGlyph { GLYPH_ATTACH, GLYPH_EMOJI, GLYPH_LOCK, GLYPH_PLUS };

static std::string extBytes(const QString& ext)
{
    const QByteArray b = ext.toLatin1();
    return std::string(b.constData(), b.size());
}

static const QString NYX_GROUP_PREFIX = "group:";
static bool isGroupKey(const QString& a) { return a.startsWith(NYX_GROUP_PREFIX); }
static std::string gidOf(const QString& a) { return a.mid(NYX_GROUP_PREFIX.size()).toStdString(); }
static bool isGroupExt(const QString& ext) { return !ext.isEmpty() && NyxParseRecords(extBytes(ext)).fGroup; }

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
    else if (g == GLYPH_PLUS)
    {
        p.setPen(QPen(c, 2.0, Qt::SolidLine, Qt::RoundCap));
        p.drawLine(QPointF(10, 4), QPointF(10, 16));
        p.drawLine(QPointF(4, 10), QPointF(16, 10));
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
    newChatButton->setIcon(composerIcon(GLYPH_PLUS, palette().color(QPalette::Text), dpr));
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
    if (isGroupKey(address))
        p.drawRoundedRect(QRectF(0, 0, px, px), px * 0.3, px * 0.3);
    else
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
    lastRowDay(0),
    replyChip(0),
    replyChipText(0),
    reactTimer(0)
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
            if (isGroupKey(currentContact))
            {
                membersPanel->setVisible(!membersPanel->isVisible());
                refreshMembersPanel();
            }
            else if (!currentContact.isEmpty())
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
        if (!reactTargetMid.isEmpty())
        {
            const QString mid = reactTargetMid;
            reactTargetMid.clear();
            emojiPicker->hide();
            toggleReaction(mid, emoji);
            return;
        }
        messageInput->insertPlainText(emoji);
        messageInput->setFocus();
    });
    connect(emojiButton, &QToolButton::clicked, [this]() {
        reactTargetMid.clear();
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

    replyChip = new QWidget();
    replyChip->setObjectName("nyxReplyChip");
    replyChip->setAttribute(Qt::WA_StyledBackground, true);
    replyChip->setStyleSheet("#nyxReplyChip { background-color: rgba(127,127,127,30); border-radius: 4px; }");
    {
        QHBoxLayout *pl = new QHBoxLayout(replyChip);
        pl->setContentsMargins(10, 3, 6, 3);
        replyChipText = new QLabel();
        replyChipText->setTextFormat(Qt::PlainText);
        replyChipText->setFont(GUIUtil::emojiFont(11));
        replyChipText->setStyleSheet("color: palette(dark); font-size: 11px; background: transparent;");
        replyChipText->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        pl->addWidget(replyChipText, 1);
        QToolButton *x = new QToolButton();
        x->setText(QString::fromUtf8("\xC3\x97"));
        x->setAutoRaise(true);
        x->setToolTip(tr("Cancel reply"));
        x->setStyleSheet("QToolButton { padding: 0px 4px; border: none; font-size: 14px; background: transparent; }");
        pl->addWidget(x);
        connect(x, &QToolButton::clicked, this, &ChatWidget::cancelReply);
    }
    replyChip->hide();
    inputOuter->addWidget(replyChip);
    inputOuter->addWidget(previewChip);

    reactTimer = new QTimer(this);
    reactTimer->setSingleShot(true);
    reactTimer->setInterval(3000);
    connect(reactTimer, &QTimer::timeout, this, &ChatWidget::flushReactions);
    inputOuter->addWidget(composerBar);

    previewFetcher = new LinkPreviewFetcher(this);
    connect(previewFetcher, &LinkPreviewFetcher::finished, this, &ChatWidget::onPreviewFinished);
    previewTimer = new QTimer(this);
    previewTimer->setSingleShot(true);
    previewTimer->setInterval(700);
    connect(previewTimer, &QTimer::timeout, this, &ChatWidget::schedulePreview);

    rightLayout->addWidget(inputFrame, 0);

    mainLayout->addWidget(rightPanel, 1);

    membersPanel = new QWidget();
    membersPanel->setObjectName("nyxMembers");
    membersPanel->setAttribute(Qt::WA_StyledBackground, true);
    membersPanel->setFixedWidth(220);
    membersPanel->setStyleSheet("#nyxMembers { background-color: palette(window); border-left: 1px solid rgba(127,127,127,45); }");
    {
        QVBoxLayout *ml = new QVBoxLayout(membersPanel);
        ml->setContentsMargins(8, 12, 8, 12);
        ml->setSpacing(6);
        membersTitle = new QLabel();
        membersTitle->setStyleSheet("font-size: 10px; font-weight: bold; color: palette(dark); padding: 0px 8px; background: transparent;");
        ml->addWidget(membersTitle);
        membersList = new QListWidget();
        membersList->setStyleSheet(
            "QListWidget { background: transparent; border: none; outline: 0; }"
            "QListWidget::item { border-radius: 6px; padding: 2px; }"
            "QListWidget::item:hover { background-color: rgba(127,127,127,35); }");
        membersList->setIconSize(QSize(28, 28));
        membersList->setContextMenuPolicy(Qt::CustomContextMenu);
        ml->addWidget(membersList, 1);
        membersAddButton = new QPushButton(tr("Add member"));
        membersRenameButton = new QPushButton(tr("Rename group"));
        membersLeaveButton = new QPushButton(tr("Leave group"));
        membersLeaveButton->setStyleSheet("QPushButton { color: white; background-color: #c0392b; border: none; border-radius: 6px; padding: 6px; }");
        ml->addWidget(membersAddButton);
        ml->addWidget(membersRenameButton);
        ml->addWidget(membersLeaveButton);
        connect(membersAddButton, &QPushButton::clicked, this, [this]() { groupAction(currentContact, "add"); });
        connect(membersRenameButton, &QPushButton::clicked, this, [this]() { groupAction(currentContact, "rename"); });
        connect(membersLeaveButton, &QPushButton::clicked, this, [this]() { groupAction(currentContact, "leave"); });
        connect(membersList, &QListWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
            QListWidgetItem *it = membersList->itemAt(pos);
            if (!it || !isGroupKey(currentContact))
                return;
            const GroupInfo g = mapGroups.value(currentContact);
            const QString a = it->data(Qt::UserRole).toString();
            QMenu menu(this);
            QAction *aCopy = menu.addAction(tr("Copy address"));
            QAction *aMsg = setMyAddrs.contains(a) ? 0 : menu.addAction(tr("Message"));
            const bool fOwner = g.fMember && g.myAddr == g.owner && a != g.owner;
            QAction *aOwner = fOwner ? menu.addAction(tr("Make owner")) : 0;
            QAction *aRemove = fOwner ? menu.addAction(tr("Remove from group")) : 0;
            QAction *aBlock = setMyAddrs.contains(a) ? 0 : menu.addAction(tr("Block"));
            QAction *c = menu.exec(membersList->viewport()->mapToGlobal(pos));
            if (!c)
                return;
            if (c == aCopy)
                QApplication::clipboard()->setText(a);
            else if (aMsg && c == aMsg)
                openConversation(a);
            else if (aBlock && c == aBlock)
                blockContact(a);
            else
            {
                std::string sError;
                int rv = (aOwner && c == aOwner) ? SecureMsgGroupSetOwner(g.gid.toStdString(), a.toStdString(), sError)
                       : (aRemove && c == aRemove) ? SecureMsgGroupRemove(g.gid.toStdString(), a.toStdString(), sError) : 0;
                if (rv != 0 || !sError.empty())
                    QMessageBox::warning(this, tr("Group"), QString::fromStdString(sError));
                refreshContacts();
                setHeaderContact(currentContact);
            }
        });
    }
    membersPanel->hide();
    mainLayout->addWidget(membersPanel);

    refreshComposerIcons();
    adjustComposerHeight();

    // Connections
    connect(contactList, SIGNAL(currentRowChanged(int)), this, SLOT(onContactSelected(int)));
    connect(contactList, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(onContactMenu(QPoint)));
    connect(newChatButton, &QToolButton::clicked, this, &ChatWidget::onNewChatClicked);
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
    typingSendTimer->setInterval(NYX_TYPING_SEND_INTERVAL * 1000);
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
    if (isGroupKey(address))
    {
        const GroupInfo g = mapGroups.value(address);
        chatHeaderName->setText(g.name);
        chatHeaderName->setToolTip(tr("Group %1").arg(g.gid));
        chatHeaderAvatar->setPixmap(avatarFor(address, g.name, 24));
        chatHeaderAvatar->show();
        chatHeaderAddr->setText(tr("%n members", "", g.members.size()));
        chatHeaderAddr->setToolTip(tr("Show members"));
        chatHeaderAddr->show();
        chatHeaderLock->show();
        refreshMembersPanel();
        return;
    }
    chatHeaderAddr->setToolTip(tr("Copy address"));
    membersPanel->hide();
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
    membersPanel->hide();
}

QListWidgetItem* ChatWidget::addListWidget(QListWidget *list, QWidget *w, bool fSelectable)
{
    QListWidgetItem *item = new QListWidgetItem();
    if (!fSelectable)
        item->setFlags(Qt::NoItemFlags);
    const int vw = list->viewport()->width();
    const int h = w->hasHeightForWidth() && vw > 0 ? w->heightForWidth(vw) : w->sizeHint().height();
    item->setSizeHint(QSize(0, qMax(h, 1)));
    list->addItem(item);
    list->setItemWidget(item, w);
    return item;
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
        connect(msgModel, SIGNAL(controlsChanged()), this, SLOT(onNewMessage()));
        connect(msgModel, SIGNAL(rowsRemoved(QModelIndex,int,int)), this, SLOT(onNewMessage()));
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
    if (isGroupKey(address))
        return mapGroups.contains(address) ? mapGroups.value(address).name : tr("Group");
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
        if (isGroupExt(msgModel->data(mi, MessageModel::ExtRole).toString()))
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

    reloadGroups();
    for (auto it = mapGroups.constBegin(); it != mapGroups.constEnd(); ++it)
    {
        ContactInfo& ci = contacts[it.key()];
        ci.last = QDateTime::fromSecsSinceEpoch(it.value().lastTs);
        if (it.value().fRequest)
            ci.preview = tr("Group invite from %1 (%n members)", "", it.value().members.size())
                             .arg(displayNameFor(it.value().owner));
        else if (!it.value().fMember)
            ci.preview = tr("You are no longer a member");
        else
            ci.preview = tr("%n members", "", it.value().members.size());
    }

    for (const QString& d : setDraftContacts)
        if (!contacts.contains(d))
        {
            ContactInfo& ci = contacts[d];
            ci.last = QDateTime::currentDateTime();
            ci.preview = tr("New conversation");
        }

    QList<QPair<QDateTime, QString>> sorted;
    for (auto it = contacts.begin(); it != contacts.end(); ++it)
        sorted.append(qMakePair(it.value().last, it.key()));
    std::sort(sorted.begin(), sorted.end(), [](const QPair<QDateTime,QString>& a, const QPair<QDateTime,QString>& b) {
        return a.first > b.first;
    });

    // Requests first, then direct messages, each newest first.
    QList<QString> requests, direct, groups;
    for (const auto& p : sorted)
        (contactState(p.second) == NYX_SENDER_REQUEST ? requests : isGroupKey(p.second) ? groups : direct).append(p.second);

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
        const bool fGroupRow = isGroupKey(addr);
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
        QString prevText = typing ? tr("typing...") : ((ci.lastMine && !fGroupRow ? tr("You: ") : QString()) + ci.preview);
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
        item->setToolTip(fGroupRow ? tr("Group %1").arg(QString::fromStdString(gidOf(addr))) : addr);
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
    }
    if (!groups.isEmpty())
    {
        addListWidget(contactList, makeSectionHeader(tr("Groups")));
        for (const QString& a : groups)
            addRow(a);
    }
    if (!requests.isEmpty() || !groups.isEmpty())
        addListWidget(contactList, makeSectionHeader(tr("Direct Messages")));
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

    if (addr != currentContact)
        cancelReply();
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

    if (isGroupKey(addr))
    {
        const GroupInfo g = mapGroups.value(addr);
        QMenu menu(this);
        QAction *aMembers = menu.addAction(tr("Members"));
        QAction *aAccept = g.fRequest ? menu.addAction(tr("Accept invite")) : 0;
        QAction *aRename = g.fMember && g.myAddr == g.owner ? menu.addAction(tr("Rename group...")) : 0;
        QAction *aCopy = menu.addAction(tr("Copy group id"));
        menu.addSeparator();
        QAction *aLeave = g.fMember && !g.fRequest ? menu.addAction(tr("Leave group")) : 0;
        QAction *aHide = menu.addAction(tr("Hide group"));
        QAction *aBlock = g.myAddr != g.owner ? menu.addAction(tr("Block owner")) : 0;
        QAction *c = menu.exec(contactList->viewport()->mapToGlobal(pos));
        if (!c)
            return;
        if (c == aMembers)
        {
            if (currentContact != addr)
                openConversation(addr);
            membersPanel->show();
            refreshMembersPanel();
        }
        else if (c == aCopy)
            QApplication::clipboard()->setText(g.gid);
        else if (aBlock && c == aBlock)
            blockContact(g.owner);
        else
            groupAction(addr, c == aAccept ? "accept" : c == aRename ? "rename" : c == aLeave ? "leave" : "hide");
        return;
    }

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
    mapMidItems.clear();
    mapBaseReactMine.clear();

    if (!msgModel)
        return;

    refreshSafetyCache();
    const bool fGroup = isGroupKey(address);
    const GroupInfo group = mapGroups.value(address);
    const int state = contactState(address);
    if (fGroup && group.fRequest)
    {
        addGroupInviteBar(address);
        return;
    }
    if (state == NYX_SENDER_BLOCKED)
    {
        addCenteredNote(tr("You blocked this address. Its messages are discarded."));
        return;
    }
    if (state == NYX_SENDER_REQUEST)
        addRequestBar(address);

    // Rows from the model plus the control records for this conversation.
    struct Src { QDateTime dt; int modelRow; MessageTableEntry ctl; bool fMine; };
    QList<Src> src;
    std::vector<NyxThreadMsg> rows;
    setMyAddrs.clear();
    if (fGroup)
    {
        std::vector<bool> mine;
        SecureMsgCollectGroupThread(gidOf(address), rows, mine);
        if (!group.myAddr.isEmpty())
            setMyAddrs.insert(group.myAddr);
        for (size_t i = 0; i < rows.size(); i++)
        {
            Src r;
            r.dt = QDateTime::fromSecsSinceEpoch(rows[i].ts);
            r.modelRow = -1;
            r.fMine = mine[i];
            if (mine[i])
                setMyAddrs.insert(QString::fromStdString(rows[i].sender));
            src.append(r);
        }
        if (!group.fMember)
            addCenteredNote(tr("You are no longer a member of this group."));
    }
    for (int i = 0; !fGroup && i < msgModel->rowCount(QModelIndex()); i++)
    {
        QString from = msgModel->data(msgModel->index(i, MessageModel::FromAddress, QModelIndex()), Qt::DisplayRole).toString();
        QString to = msgModel->data(msgModel->index(i, MessageModel::ToAddress, QModelIndex()), Qt::DisplayRole).toString();
        const bool fMine = msgModel->data(msgModel->index(i, 0, QModelIndex()), MessageModel::TypeRole).toInt() == MessageTableEntry::Sent;
        if ((fMine ? to : from) != address)
            continue;
        if (isGroupExt(msgModel->data(msgModel->index(i, 0, QModelIndex()), MessageModel::ExtRole).toString()))
            continue;
        setMyAddrs.insert(fMine ? from : to);
        Src r;
        r.dt = msgModel->data(msgModel->index(i, MessageModel::ReceivedDateTime, QModelIndex()), Qt::DisplayRole).toDateTime();
        r.modelRow = i;
        r.fMine = fMine;
        src.append(r);
    }
    const QList<MessageTableEntry> ctls = fGroup ? QList<MessageTableEntry>() : msgModel->controlEntries();
    for (const MessageTableEntry& e : ctls)
    {
        const bool fMine = e.type == MessageTableEntry::Sent;
        if ((fMine ? e.to_address : e.from_address) != address || isGroupExt(e.ext))
            continue;
        setMyAddrs.insert(fMine ? e.from_address : e.to_address);
        Src r;
        r.dt = e.received_datetime;
        r.modelRow = -1;
        r.ctl = e;
        r.fMine = fMine;
        src.append(r);
    }
    if (!fGroup)
        std::stable_sort(src.begin(), src.end(), [](const Src& x, const Src& y) { return x.dt < y.dt; });

    for (int k = 0; !fGroup && k < src.size(); k++)
    {
        const Src& r = src[k];
        NyxThreadMsg m;
        if (r.modelRow >= 0)
        {
            m.mid = msgModel->data(msgModel->index(r.modelRow, 0, QModelIndex()), MessageModel::MidRole).toString().toStdString();
            m.sender = msgModel->data(msgModel->index(r.modelRow, MessageModel::FromAddress, QModelIndex()), Qt::DisplayRole).toString().toStdString();
            m.ts = msgModel->data(msgModel->index(r.modelRow, MessageModel::SentDateTime, QModelIndex()), Qt::DisplayRole).toDateTime().toSecsSinceEpoch();
            m.text = msgModel->data(msgModel->index(r.modelRow, MessageModel::Message, QModelIndex()), Qt::DisplayRole).toString().toStdString();
            m.ext = extBytes(msgModel->data(msgModel->index(r.modelRow, 0, QModelIndex()), MessageModel::ExtRole).toString());
        }
        else
        {
            m.mid = r.ctl.mid.toStdString();
            m.sender = r.ctl.from_address.toStdString();
            m.ts = r.ctl.sent_datetime.toSecsSinceEpoch();
            m.text = r.ctl.message.toStdString();
            m.ext = extBytes(r.ctl.ext);
        }
        rows.push_back(m);
    }
    const std::vector<NyxMsgView> views = NyxBuildThread(rows, [&](const std::string& s) {
        const QString q = QString::fromStdString(s);
        if (fGroup)
            return group.members.contains(q) && !NyxIsBlocked(s);
        return setMyAddrs.contains(q) || contactState(q) == NYX_SENDER_KNOWN;
    });

    bool fAny = false;
    for (const NyxMsgView& v : views)
        fAny = fAny || !v.fControl;
    if (!fAny)
        addCenteredNote(tr("No messages yet. Say hello."));

    const std::vector<std::pair<std::string, std::string> > removals = msgModel->embedRemovals();
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    QDate lastDate;
    for (size_t i = 0; i < rows.size(); i++)
    {
        const NyxMsgView& v = views[i];
        if (v.fControl)
            continue;
        const Src& r = src[i];
        const QDateTime dt = r.dt;
        if (dt.date() != lastDate)
        {
            addDateSeparator(dt.date());
            lastDate = dt.date();
        }

        RowArgs a;
        a.when = dt;
        a.isMine = r.fMine;
        a.owner = QString::fromStdString(rows[i].sender);
        a.modelRow = r.modelRow;
        a.mid = QString::fromStdString(rows[i].mid);
        a.fTombstone = v.fTombstone;
        a.fEdited = v.fEdited;
        a.fRequest = !a.isMine && state != NYX_SENDER_KNOWN;
        a.text = QString::fromStdString(v.text);
        const QString msg = QString::fromStdString(rows[i].text);

        if (!a.fTombstone && parseFileMessage(msg, a.cid, a.encKeyHex, a.filename, a.fileSize))
            a.fFile = true;

        NyxEmbed embed;
        if (!a.fTombstone && !a.fFile && !a.fEdited && a.owner != "anon" && !a.fRequest)
        {
            const std::string rec = NyxParseRecords(rows[i].ext).embedRec;
            if (NyxDecodeEmbed(rec, embed) && !setHiddenNow.contains(QString::fromStdString(embed.id))
                && !NyxEmbedHidden(a.owner.toStdString(), embed.id, removals))
                a.embed = &embed;
        }

        if (v.fReply)
        {
            a.fReply = true;
            a.replyMid = QString::fromStdString(v.reply.mid);
            if (v.replyIndex >= 0)
            {
                a.fReplyFound = true;
                const QString o = QString::fromStdString(rows[v.replyIndex].sender);
                a.replyName = src[v.replyIndex].fMine ? myDisplayName() : displayNameFor(o);
                a.replyText = QString::fromStdString(views[v.replyIndex].text);
            }
            else
                a.replyText = QString::fromStdString(v.reply.quote);
        }

        for (const auto& e : v.reactions)
        {
            QStringList who;
            bool fMineReact = false;
            for (const std::string& w : e.second)
            {
                who << QString::fromStdString(w);
                fMineReact = fMineReact || setMyAddrs.contains(who.last());
            }
            const QString emoji = QString::fromStdString(e.first);
            a.reactions.append(qMakePair(emoji, who));
            mapBaseReactMine[a.mid + '\n' + emoji] = fMineReact;
        }

        const bool fAnonThread = address == "anon" || a.owner == "anon";
        a.fCanControl = a.isMine && !fAnonThread && !a.fTombstone && !a.mid.isEmpty();
        a.fCanEdit = a.fCanControl && !a.fFile && now <= rows[i].ts + NYX_EDIT_WINDOW;
        addMessageRow(a);
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

    if (a.fReply)
    {
        QString snippet = a.replyText.simplified();
        if (snippet.length() > 90)
            snippet = snippet.left(90) + QString::fromUtf8("\xE2\x80\xA6");
        QLabel *q = new QLabel();
        q->setFont(GUIUtil::emojiFont(11));
        q->setTextFormat(Qt::RichText);
        q->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        q->setStyleSheet("font-size: 11px; color: palette(dark); background: transparent;");
        const QString arrow = QString::fromUtf8("\xE2\x86\xB1&nbsp;");
        if (a.fReplyFound)
        {
            q->setText(arrow + "<a href=\"jump\" style=\"color: palette(dark); text-decoration: none;\"><b>"
                       + a.replyName.toHtmlEscaped() + "</b>&nbsp;&nbsp;" + snippet.toHtmlEscaped() + "</a>");
            q->setToolTip(tr("Jump to the original message"));
            q->setCursor(Qt::PointingHandCursor);
            const QString target = a.replyMid;
            connect(q, &QLabel::linkActivated, this, [this, target]() { scrollToMid(target); });
        }
        else
        {
            q->setText(arrow + tr("Original not available. Quoted by sender: %1").arg(snippet).toHtmlEscaped());
            q->setToolTip(tr("The original is not in this wallet. The quote is the sender's copy and may differ from what was said."));
        }
        bl->addWidget(q);
    }

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

    if (!a.fFile && !a.fTombstone && !a.isMine && NyxLooksLikeScam(a.text.toStdString()))
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
        if (a.fTombstone)
            body->setText("<i>" + tr("message deleted").toHtmlEscaped() + "</i>");
        else
            body->setText("<span style=\"white-space: pre-wrap;\">" + QString::fromStdString(html) + "</span>"
                          + (a.fEdited ? QString("<span style=\"font-size: 10px; color: palette(dark);\">&nbsp;(%1)</span>")
                                             .arg(tr("edited").toHtmlEscaped()) : QString()));
        body->setContextMenuPolicy(Qt::NoContextMenu);
        body->setOpenExternalLinks(false);
        body->setWordWrap(true);
        body->setTextInteractionFlags(a.fRequest ? Qt::TextSelectableByMouse
                                                 : (Qt::TextSelectableByMouse | Qt::LinksAccessibleByMouse));
        connect(body, &QLabel::linkActivated, this, &ChatWidget::confirmOpenUrl);
        const bool fJumbo = !a.fTombstone && isJumboEmoji(a.text);
        body->setFont(GUIUtil::emojiFont(fJumbo ? 42 : 14));
        body->setStyleSheet(QString(a.fFailed || a.fTombstone ? "background: transparent; color: palette(dark);"
                                              : "background: transparent; color: palette(text);") +
                            (fJumbo ? " font-size: 42px;" : ""));
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

    if (QWidget *rb = makeReactionBar(a))
        bl->addWidget(rb);

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
    const bool fInteract = !a.fTombstone && !a.fFailed && !a.mid.isEmpty() && a.owner != "anon" && currentContact != "anon";
    const QString mid = a.mid;
    const QString snippet = a.fFile ? a.filename : a.text;
    const QString who = name;
    QMenu *menu = new QMenu(rowW);
    auto act = [&](const QString& label, const QString& tip, std::function<void()> fn, bool fBar) {
        if (fBar)
            connect(tool(label, tip), &QToolButton::clicked, this, [this, fn]() { QTimer::singleShot(0, this, fn); });
        connect(menu->addAction(tip), &QAction::triggered, this, [this, fn]() { QTimer::singleShot(0, this, fn); });
    };
    if (fInteract)
    {
        QToolButton *rb = tool(tr("React"), tr("Add reaction"));
        connect(rb, &QToolButton::clicked, this, [this, mid, rb]() { openReactPicker(mid, rb); });
        connect(menu->addAction(tr("Add reaction")), &QAction::triggered, this, [this, mid, rowW]() { openReactPicker(mid, rowW); });
        act(tr("Reply"), tr("Reply"), [this, mid, who, snippet]() { startReply(mid, who, snippet); }, true);
    }
    if (a.fCanEdit)
    {
        const QString cur = a.text;
        act(tr("Edit"), tr("Edit message"), [this, mid, cur]() { editMessage(mid, cur); }, true);
    }
    if (a.fCanControl)
        act(tr("Unsend"), tr("Delete for everyone"), [this, mid]() { unsendMessage(mid); }, true);
    menu->addSeparator();
    if (!a.fTombstone)
        act(tr("Copy"), tr("Copy text"), [copyText]() { QApplication::clipboard()->setText(copyText); }, false);
    if (!addr.isEmpty() && addr != "anon")
        act(tr("Address"), tr("Copy sender address"), [addr]() { QApplication::clipboard()->setText(addr); }, false);
    if (a.modelRow >= 0)
    {
        const int mrow = a.modelRow;
        act(tr("Delete"), tr("Delete from this wallet only"), [this, mrow]() { deleteMessageRow(mrow); }, false);
    }
    QToolButton *more = tool(QString::fromUtf8("\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2"), tr("More"));
    connect(more, &QToolButton::clicked, this, [more, menu]() { menu->popup(more->mapToGlobal(QPoint(0, more->height()))); });
    rowW->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(rowW, &QWidget::customContextMenuRequested, this, [rowW, menu](const QPoint& pos) {
        menu->popup(rowW->mapToGlobal(pos));
    });
    tb->hide();
    rowW->toolbar = tb;

    QListWidgetItem *item = addListWidget(chatView, rowW);
    if (!a.mid.isEmpty())
        mapMidItems[a.mid] = item;
}

QWidget* ChatWidget::makeReactionBar(const RowArgs& a)
{
    if (a.mid.isEmpty() || a.fTombstone)
        return 0;
    // Base state with this wallet's pending toggles applied.
    QList<QPair<QString, int> > chips;
    QSet<QString> mineSet;
    for (const auto& e : a.reactions)
    {
        bool fMine = false;
        for (const QString& w : e.second)
            fMine = fMine || setMyAddrs.contains(w);
        if (fMine)
            mineSet.insert(e.first);
        chips.append(qMakePair(e.first, (int)e.second.size()));
    }
    for (auto it = mapPendingReact.constBegin(); it != mapPendingReact.constEnd(); ++it)
    {
        const int nl = it.key().indexOf('\n');
        if (it.key().left(nl) != a.mid)
            continue;
        const QString emoji = it.key().mid(nl + 1);
        int idx = -1;
        for (int i = 0; i < chips.size(); i++)
            if (chips[i].first == emoji)
                idx = i;
        const bool fWas = mineSet.contains(emoji);
        if (it.value() == fWas)
            continue;
        if (idx < 0)
        {
            chips.append(qMakePair(emoji, 0));
            idx = chips.size() - 1;
        }
        chips[idx].second += it.value() ? 1 : -1;
        if (it.value()) mineSet.insert(emoji); else mineSet.remove(emoji);
    }
    bool fAny = false;
    for (const auto& c : chips)
        fAny = fAny || c.second > 0;
    if (!fAny)
        return 0;

    QWidget *bar = new QWidget();
    bar->setAttribute(Qt::WA_TranslucentBackground);
    QHBoxLayout *h = new QHBoxLayout(bar);
    h->setContentsMargins(0, 2, 0, 0);
    h->setSpacing(4);
    const QString mid = a.mid;
    for (const auto& c : chips)
    {
        if (c.second <= 0)
            continue;
        const bool fMine = mineSet.contains(c.first);
        QToolButton *b = new QToolButton();
        b->setText(c.first + " " + QString::number(c.second));
        b->setFont(GUIUtil::emojiFont(13));
        b->setCursor(Qt::PointingHandCursor);
        b->setToolTip(fMine ? tr("You reacted. Click to remove.") : tr("Click to react"));
        b->setStyleSheet(QString("QToolButton { border-radius: 8px; padding: 1px 7px; font-size: 12px; color: palette(text);"
                                 " background-color: %1; border: 1px solid %2; }"
                                 "QToolButton:hover { border: 1px solid rgba(127,127,127,140); }")
                         .arg(fMine ? "rgba(88,101,242,60)" : "rgba(127,127,127,35)",
                              fMine ? NYX_ACCENT : "transparent"));
        const QString emoji = c.first;
        connect(b, &QToolButton::clicked, this, [this, mid, emoji]() { toggleReaction(mid, emoji); });
        h->addWidget(b);
    }
    if (currentContact != "anon")
    {
        QToolButton *add = new QToolButton();
        add->setText("+");
        add->setToolTip(tr("Add reaction"));
        add->setCursor(Qt::PointingHandCursor);
        add->setStyleSheet("QToolButton { border-radius: 8px; padding: 1px 8px; font-size: 12px; color: palette(dark);"
                           " background-color: rgba(127,127,127,35); border: 1px solid transparent; }"
                           "QToolButton:hover { color: palette(text); }");
        connect(add, &QToolButton::clicked, this, [this, mid, add]() { openReactPicker(mid, add); });
        h->addWidget(add);
    }
    h->addStretch(1);
    return bar;
}

void ChatWidget::openReactPicker(const QString& mid, QWidget *anchor)
{
    reactTargetMid = mid;
    QPoint pos = anchor->mapToGlobal(QPoint(anchor->width() - emojiPicker->width(), anchor->height() + 4));
    emojiPicker->move(pos);
    emojiPicker->show();
    emojiPicker->raise();
}

void ChatWidget::toggleReaction(const QString& mid, const QString& emoji)
{
    if (mid.isEmpty() || !NyxIsReactionEmoji(emoji.toStdString()))
        return;
    const QString key = mid + '\n' + emoji;
    const bool fBase = mapBaseReactMine.value(key, false);
    const bool fNow = mapPendingReact.contains(key) ? mapPendingReact.value(key) : fBase;
    if (!fNow == fBase)
        mapPendingReact.remove(key);
    else
        mapPendingReact[key] = !fNow;
    // Rapid toggles collapse into the net change, sent after 3 s.
    reactTimer->start();
    if (!currentContact.isEmpty())
    {
        const int sv = chatView->verticalScrollBar()->value();
        loadConversation(currentContact);
        chatView->verticalScrollBar()->setValue(sv);
    }
}

void ChatWidget::flushReactions()
{
    QMap<QString, bool> pending = mapPendingReact;
    mapPendingReact.clear();
    QString err;
    for (auto it = pending.constBegin(); it != pending.constEnd(); ++it)
    {
        const int nl = it.key().indexOf('\n');
        std::string sError;
        if (SecureMsgSendReact(it.key().left(nl).toStdString(), it.key().mid(nl + 1).toStdString(), it.value(), sError) != 0)
            err = QString::fromStdString(sError);
    }
    if (!err.isEmpty())
        QMessageBox::warning(this, tr("Reaction"), err);
}

void ChatWidget::startReply(const QString& mid, const QString& name, const QString& snippet)
{
    replyMid = mid;
    replyChip->setProperty("quote", snippet);
    QString s = snippet.simplified();
    if (s.length() > 80)
        s = s.left(80) + QString::fromUtf8("\xE2\x80\xA6");
    replyChipText->setText(tr("Replying to %1").arg(name) + ":  " + s);
    replyChip->show();
    messageInput->setFocus();
}

void ChatWidget::cancelReply()
{
    replyMid.clear();
    if (replyChip)
        replyChip->hide();
}

void ChatWidget::scrollToMid(const QString& mid)
{
    QListWidgetItem *item = mapMidItems.value(mid);
    if (!item)
        return;
    chatView->scrollToItem(item, QAbstractItemView::PositionAtCenter);
    QWidget *w = chatView->itemWidget(item);
    if (!w)
        return;
    w->setAttribute(Qt::WA_StyledBackground, true);
    w->setStyleSheet("background-color: rgba(88,101,242,45);");
    QPointer<QWidget> pw(w);
    QTimer::singleShot(1400, this, [pw]() { if (pw) pw->setStyleSheet(QString()); });
}

void ChatWidget::editMessage(const QString& mid, const QString& current)
{
    bool ok = false;
    QString text = QInputDialog::getMultiLineText(this, tr("Edit message"),
        tr("Recipients running Nyx show the new text with an \"edited\" mark. Older clients show it as a new message."),
        current, &ok).trimmed();
    if (!ok || text.isEmpty() || text == current)
        return;
    text = EmojiPicker::replaceShortcodes(text);
    if (NyxDetectSecret(text.toStdString()) != NYX_SECRET_NONE)
    {
        QMessageBox::critical(this, tr("Do not send this"), tr(NYX_SECRET_WARNING));
        return;
    }
    std::string sError;
    if (SecureMsgSendEdit(mid.toStdString(), text.toStdString(), sError) != 0)
        QMessageBox::warning(this, tr("Edit message"), QString::fromStdString(sError));
}

void ChatWidget::unsendMessage(const QString& mid)
{
    if (QMessageBox::question(this, tr("Delete for everyone"),
            tr("Delete this message for everyone?\n\nRecipients running Nyx replace it with \"message deleted\" and erase "
               "their copy. Anyone who already read it may have kept a copy, and older clients show "
               "\"[message deleted]\" as a new message."),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;
    std::string sError;
    if (SecureMsgSendDelete(mid.toStdString(), sError) != 0)
        QMessageBox::warning(this, tr("Delete for everyone"), QString::fromStdString(sError));
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
    fNyxTyping = settings.value("fNyxTypingIndicators", false).toBool();
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
    if (isGroupKey(address))
        return mapGroups.value(address).fRequest ? NYX_SENDER_REQUEST : NYX_SENDER_KNOWN;
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
    std::string embedExt;
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
            std::string ext = NyxFitEmbed(msgText, sentEmbed, SMSG_MAX_MSG_BYTES - 160);
            NyxEmbed check;
            if (!ext.empty() && NyxDecodeEmbed(ext, check))
            {
                embedExt = ext;
                sentEmbed = check;
                fSentEmbed = true;
            }
        }
    }
    int rv;
    if (isGroupKey(currentContact))
    {
        std::vector<std::string> extra;
        if (!replyMid.isEmpty() && !fFile)
        {
            NyxReply r;
            r.mid = replyMid.toStdString();
            r.quote = replyChip->property("quote").toString().toStdString();
            extra.push_back(NyxEncodeReply(r));
        }
        if (fSentEmbed)
            extra.push_back(embedExt);
        rv = SecureMsgGroupSend(gidOf(currentContact), msgText, extra, sError);
        if (rv != 0 && fSentEmbed)
        {
            extra.pop_back();
            fSentEmbed = false;
            rv = SecureMsgGroupSend(gidOf(currentContact), msgText, extra, sError);
        }
        addFrom = mapGroups.value(currentContact).myAddr.toStdString();
    }
    else
    {
    if (!replyMid.isEmpty() && !fFile)
    {
        NyxReply r;
        r.mid = replyMid.toStdString();
        r.quote = replyChip->property("quote").toString().toStdString();
        std::string full = NyxReplyPlain(msgText, r, embedExt, SMSG_MAX_MSG_BYTES);
        if (full.empty() && !embedExt.empty())
        {
            full = NyxReplyPlain(msgText, r, std::string(), SMSG_MAX_MSG_BYTES);
            fSentEmbed = false;
        }
        if (full.empty())
        {
            QMessageBox::warning(this, tr("Reply"), tr("The reply is too long."));
            return;
        }
        msgText = full;
    }
    else if (!embedExt.empty())
        msgText = NyxComposePlain(msgText, embedExt);
    rv = SecureMsgSend(addFrom, sendTo, msgText, sError);
    }
    if (rv != 0)
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
    cancelReply();

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
    if (!fSecMsgEnabled)
    {
        QMessageBox box(QMessageBox::Information, tr("New conversation"),
                        tr("Nyx Messenger is off, so messages cannot be sent or received."), QMessageBox::NoButton, this);
        QPushButton *en = GetBoolArg("-nosmsg", false) ? 0 : box.addButton(tr("Enable messaging"), QMessageBox::AcceptRole);
        box.addButton(QMessageBox::Cancel);
        box.exec();
        if (!en || box.clickedButton() != en)
            return;
        onEnableMessagingClicked();
        if (!fSecMsgEnabled)
            return;
    }
    if (!msgModel)
    {
        QMessageBox::information(this, tr("New conversation"),
                                 tr("The message store is not loaded yet. Unlock the wallet or try again in a moment."));
        return;
    }
    QMenu menu(this);
    QAction *aDirect = menu.addAction(tr("New direct message..."));
    QAction *aGroup = menu.addAction(tr("New group..."));
    QAction *c = menu.exec(newChatButton->mapToGlobal(QPoint(0, newChatButton->height())));
    if (c == aDirect)
        startDirectDialog();
    else if (c == aGroup)
        createGroupDialog();
}

void ChatWidget::startDirectDialog()
{
    QDialog dlg(this);
    dlg.setWindowTitle(tr("New conversation"));
    dlg.setMinimumWidth(420);
    QVBoxLayout *v = new QVBoxLayout(&dlg);
    QFormLayout *form = new QFormLayout();
    QLineEdit *addrEdit = new QLineEdit();
    addrEdit->setPlaceholderText(tr("Innova address"));
    QLineEdit *nickEdit = new QLineEdit();
    nickEdit->setPlaceholderText(tr("Optional"));
    nickEdit->setMaxLength(48);
    form->addRow(tr("Address"), addrEdit);
    form->addRow(tr("Nickname"), nickEdit);
    v->addLayout(form);
    QLabel *hint = new QLabel(tr("Nothing is sent until you type a message. A first message to someone who has not "
                                 "messaged you arrives in their message requests."));
    hint->setWordWrap(true);
    hint->setStyleSheet("color: palette(dark); font-size: 11px;");
    v->addWidget(hint);
    QLabel *err = new QLabel();
    err->setStyleSheet("color: #f23f43; font-size: 11px;");
    err->hide();
    v->addWidget(err);
    QDialogButtonBox *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    bb->button(QDialogButtonBox::Ok)->setText(tr("Start conversation"));
    v->addWidget(bb);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(bb, &QDialogButtonBox::accepted, &dlg, [&]() {
        const QString addr = addrEdit->text().trimmed();
        CBitcoinAddress ba(addr.toStdString());
        if (!ba.IsValid())
        {
            err->setText(tr("That is not a valid Innova address."));
            err->show();
            return;
        }
        if (pwalletMain)
        {
            LOCK(pwalletMain->cs_wallet);
            if (IsMine(*pwalletMain, ba.Get()))
            {
                err->setText(tr("That address belongs to this wallet."));
                err->show();
                return;
            }
        }
        dlg.accept();
    });
    addrEdit->setFocus();
    if (dlg.exec() != QDialog::Accepted)
        return;

    const QString addr = addrEdit->text().trimmed();
    const QString nick = nickEdit->text().trimmed();
    if (!nick.isEmpty())
    {
        mapContactNicknames[addr] = nick;
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
        mapAvatarCache.clear();
    }
    openConversation(addr);
}

void ChatWidget::openConversation(const QString& address)
{
    if (!isGroupKey(address))
        setDraftContacts.insert(address);
    currentContact = address;
    cancelReply();
    setHeaderContact(address);
    markRead(address);
    refreshContacts();
    loadConversation(address);
    updateSendButton();
    messageInput->setFocus();
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
    // Opt-in; only to an accepted contact in the open, focused conversation. Core rate-limits to 1 per 60 s.
    if (!fNyxTyping || typingSendTimer->isActive() || currentContact.isEmpty() || currentContact == "anon"
        || isGroupKey(currentContact) || !window()->isActiveWindow() || contactState(currentContact) != NYX_SENDER_KNOWN)
        return;
    const std::string addFrom = pickSendFromAddress().toStdString();
    if (!addFrom.empty() && addFrom != "anon")
    {
        SecureMsgSendTyping(addFrom, currentContact.toStdString());
        typingSendTimer->start();
    }
}

void ChatWidget::onTypingReceived(const QString& senderAddr)
{
    if (!fNyxTyping)
        return;
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
        if (now - it.value() > NYX_TYPING_SEND_INTERVAL * 1000)
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
    mapTypingContacts.clear();
    // Update last-read so current contact doesn't flash unread
    if (!currentContact.isEmpty() && isVisible())
        markRead(currentContact);

    refreshContacts();
    if (!currentContact.isEmpty())
        loadConversation(currentContact);
}

void ChatWidget::reloadGroups()
{
    mapGroups.clear();
    if (!fSecMsgEnabled || !pwalletMain || pwalletMain->IsLocked())
        return;
    std::vector<NyxGroupView> v;
    SecureMsgCollectGroups(v);
    for (const NyxGroupView& g : v)
    {
        if (g.fHidden)
            continue;
        GroupInfo gi;
        gi.gid = QString::fromStdString(g.gid);
        gi.name = QString::fromStdString(g.name);
        gi.owner = QString::fromStdString(g.owner);
        gi.myAddr = QString::fromStdString(g.myAddr);
        for (const std::string& m : g.members)
            gi.members << QString::fromStdString(m);
        gi.fMember = g.fMember;
        gi.fRequest = g.fRequest;
        gi.lastTs = g.lastTs;
        mapGroups.insert(NYX_GROUP_PREFIX + gi.gid, gi);
    }
}

void ChatWidget::refreshMembersPanel()
{
    if (!isGroupKey(currentContact))
    {
        membersPanel->hide();
        return;
    }
    const GroupInfo g = mapGroups.value(currentContact);
    membersTitle->setText(tr("MEMBERS - %1 / %2").arg(g.members.size()).arg((int)NYX_GROUP_MAX));
    membersList->clear();
    for (const QString& m : g.members)
    {
        const bool fMe = m == g.myAddr;
        QString label = fMe ? myDisplayName() : displayNameFor(m);
        if (m == g.owner)
            label += QString::fromUtf8("  \xF0\x9F\x91\x91");   // crown
        QListWidgetItem *it = new QListWidgetItem(QIcon(avatarFor(m, fMe ? myDisplayName() : displayNameFor(m), 28)), label);
        it->setData(Qt::UserRole, m);
        it->setToolTip(m);
        membersList->addItem(it);
    }
    const bool fOwner = g.fMember && g.myAddr == g.owner;
    membersAddButton->setVisible(fOwner);
    membersAddButton->setEnabled(g.members.size() < (int)NYX_GROUP_MAX);
    membersRenameButton->setVisible(fOwner);
    membersLeaveButton->setVisible(g.fMember);
}

void ChatWidget::createGroupDialog()
{
    QDialog dlg(this);
    dlg.setWindowTitle(tr("New group"));
    dlg.setMinimumWidth(460);
    QVBoxLayout *v = new QVBoxLayout(&dlg);
    QFormLayout *form = new QFormLayout();
    QLineEdit *nameEdit = new QLineEdit();
    nameEdit->setMaxLength(NYX_GROUP_NAME_MAX);
    nameEdit->setPlaceholderText(tr("Group name"));
    QPlainTextEdit *membersEdit = new QPlainTextEdit();
    membersEdit->setPlaceholderText(tr("One Innova address per line (up to %1)").arg((int)NYX_GROUP_MAX - 1));
    membersEdit->setFixedHeight(120);
    form->addRow(tr("Name"), nameEdit);
    form->addRow(tr("Members"), membersEdit);
    v->addLayout(form);
    QLabel *hint = new QLabel(tr("Up to %1 members including you. Each message is encrypted separately to every member, "
                                 "so it costs one proof of work per member. Members see each other's addresses. "
                                 "Invitees who do not know you see the group under message requests.")
                              .arg((int)NYX_GROUP_MAX));
    hint->setWordWrap(true);
    hint->setStyleSheet("color: palette(dark); font-size: 11px;");
    v->addWidget(hint);
    QLabel *err = new QLabel();
    err->setStyleSheet("color: #f23f43; font-size: 11px;");
    err->setWordWrap(true);
    err->hide();
    v->addWidget(err);
    QDialogButtonBox *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    bb->button(QDialogButtonBox::Ok)->setText(tr("Create group"));
    v->addWidget(bb);
    std::vector<std::string> members;
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(bb, &QDialogButtonBox::accepted, &dlg, [&]() {
        members.clear();
        if (nameEdit->text().trimmed().isEmpty())
        {
            err->setText(tr("Enter a group name."));
            err->show();
            return;
        }
        for (const QString& line : membersEdit->toPlainText().split(QRegularExpression("[\\s,]+"), Qt::SkipEmptyParts))
        {
            CBitcoinAddress ba(line.toStdString());
            if (!ba.IsValid())
            {
                err->setText(tr("%1 is not a valid Innova address.").arg(line));
                err->show();
                return;
            }
            if (std::find(members.begin(), members.end(), line.toStdString()) == members.end())
                members.push_back(line.toStdString());
        }
        if (members.empty() || members.size() > NYX_GROUP_MAX - 1)
        {
            err->setText(tr("Add between 1 and %1 members.").arg((int)NYX_GROUP_MAX - 1));
            err->show();
            return;
        }
        dlg.accept();
    });
    nameEdit->setFocus();
    if (dlg.exec() != QDialog::Accepted)
        return;
    const std::string from = pickSendFromAddress().toStdString();
    std::string gid, sError;
    if (from.empty() || SecureMsgGroupCreate(from, nameEdit->text().trimmed().toStdString(), members, gid, sError) != 0)
    {
        QMessageBox::warning(this, tr("New group"), sError.empty() ? tr("No address available to send from.")
                                                                    : QString::fromStdString(sError));
        return;
    }
    if (!sError.empty())
        QMessageBox::warning(this, tr("New group"), QString::fromStdString(sError));
    refreshContacts();
    openConversation(NYX_GROUP_PREFIX + QString::fromStdString(gid));
}

void ChatWidget::addGroupInviteBar(const QString& key)
{
    const GroupInfo g = mapGroups.value(key);
    QFrame *bar = new QFrame();
    bar->setObjectName("request");
    bar->setStyleSheet("QFrame#request { background-color: palette(alternate-base); border: 1px solid palette(mid);"
                       " border-radius: 8px; } QLabel { background: transparent; color: palette(text); }");
    QVBoxLayout *v = new QVBoxLayout(bar);
    v->setContentsMargins(12, 10, 12, 10);
    QLabel *t = new QLabel(tr("Group invite from %1 (%n members): \"%2\". You have not messaged this address. "
                              "Group messages stay hidden until you accept.", "", g.members.size())
                           .arg(g.owner, g.name));
    t->setTextFormat(Qt::PlainText);
    t->setWordWrap(true);
    v->addWidget(t);
    QHBoxLayout *h = new QHBoxLayout();
    QPushButton *accept = new QPushButton(tr("Accept"));
    QPushButton *hide = new QPushButton(tr("Ignore"));
    QPushButton *block = new QPushButton(tr("Block owner"));
    block->setStyleSheet("QPushButton { color: #c0392b; }");
    h->addWidget(accept);
    h->addWidget(hide);
    h->addWidget(block);
    h->addStretch();
    v->addLayout(h);
    connect(accept, &QPushButton::clicked, this, [this, key]() { groupAction(key, "accept"); });
    connect(hide, &QPushButton::clicked, this, [this, key]() { groupAction(key, "hide"); });
    connect(block, &QPushButton::clicked, this, [this, g]() { blockContact(g.owner); });
    QWidget *wrap = new QWidget();
    QHBoxLayout *wl = new QHBoxLayout(wrap);
    wl->setContentsMargins(16, 10, 16, 6);
    wl->addWidget(bar);
    addListWidget(chatView, wrap);
}

void ChatWidget::groupAction(const QString& key, const QString& what)
{
    if (!mapGroups.contains(key))
        return;
    const GroupInfo g = mapGroups.value(key);
    const std::string gid = g.gid.toStdString();
    std::string sError;
    int rv = 0;
    if (what == "accept")
        rv = SecureMsgGroupAccept(gid) ? 0 : (sError = "Could not save the contact list.", 1);
    else if (what == "hide")
    {
        if (QMessageBox::question(this, tr("Hide group"), tr("Hide \"%1\"? Its messages are no longer shown.").arg(g.name),
                                  QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
            return;
        rv = SecureMsgGroupHide(gid) ? 0 : (sError = "Could not save the contact list.", 1);
    }
    else if (what == "leave")
    {
        if (QMessageBox::question(this, tr("Leave group"), tr("Leave \"%1\"? Members are told you left.").arg(g.name),
                                  QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
            return;
        rv = SecureMsgGroupLeave(gid, sError);
    }
    else if (what == "rename")
    {
        bool ok = false;
        const QString n = QInputDialog::getText(this, tr("Rename group"), tr("Group name"), QLineEdit::Normal, g.name, &ok).trimmed();
        if (!ok || n.isEmpty() || n == g.name)
            return;
        rv = SecureMsgGroupRename(gid, n.left(NYX_GROUP_NAME_MAX).toStdString(), sError);
    }
    else if (what == "add")
    {
        bool ok = false;
        const QString a = QInputDialog::getText(this, tr("Add member"), tr("Innova address"), QLineEdit::Normal, QString(), &ok).trimmed();
        if (!ok || a.isEmpty())
            return;
        rv = SecureMsgGroupAdd(gid, a.toStdString(), sError);
    }
    if (rv != 0 || !sError.empty())
        QMessageBox::warning(this, tr("Group"), QString::fromStdString(sError));
    refreshContacts();
    if (what == "hide" && currentContact == key)
    {
        currentContact.clear();
        clearHeaderContact();
        showEmptyConversation();
        updateSendButton();
        return;
    }
    if (currentContact == key)
    {
        setHeaderContact(key);
        loadConversation(key);
    }
}

static const char* NYX_TYPING_KEY = "fNyxTypingIndicators";

bool ChatWidget::typingIndicatorsEnabled()
{
    QSettings settings;
    return settings.value(NYX_TYPING_KEY, false).toBool();
}

void ChatWidget::setTypingIndicatorsEnabled(bool fEnable)
{
    QSettings settings;
    settings.setValue(NYX_TYPING_KEY, fEnable);
    fNyxTyping = fEnable;
}
