#include "emojipicker.h"
#include <QScrollArea>
#include <QVBoxLayout>
#include <QToolButton>
#include <QFont>
#include <QPushButton>
#include <QStringList>

QList<EmojiEntry>& EmojiPicker::getAllEmojis()
{
    static QList<EmojiEntry> emojis;
    if (emojis.isEmpty())
    {
        // Helper: create emoji from Unicode code point using QChar::fromUcs4
        auto E = [](const char* sc, unsigned int cp, const char* cat) -> EmojiEntry {
            uint ucs4[] = { cp, 0 };
            QString s = QString::fromUcs4(ucs4, 1);
            return EmojiEntry{sc, s, cat};
        };
        auto ES = E;

        // Smileys & People
        emojis << ES("smile", 0x1F604, "smileys");
        emojis << ES("grin", 0x1F601, "smileys");
        emojis << ES("laugh", 0x1F602, "smileys");
        emojis << ES("joy", 0x1F602, "smileys");
        emojis << ES("rofl", 0x1F923, "smileys");
        emojis << ES("sweat_smile", 0x1F605, "smileys");
        emojis << ES("wink", 0x1F609, "smileys");
        emojis << ES("blush", 0x1F60A, "smileys");
        emojis << ES("innocent", 0x1F607, "smileys");
        emojis << ES("heart_eyes", 0x1F60D, "smileys");
        emojis << ES("kissing", 0x1F618, "smileys");
        emojis << ES("yum", 0x1F60B, "smileys");
        emojis << ES("tongue", 0x1F61B, "smileys");
        emojis << ES("zany", 0x1F92A, "smileys");
        emojis << ES("thinking", 0x1F914, "smileys");
        emojis << ES("shush", 0x1F92B, "smileys");
        emojis << ES("neutral", 0x1F610, "smileys");
        emojis << ES("smirk", 0x1F60F, "smileys");
        emojis << ES("unamused", 0x1F612, "smileys");
        emojis << ES("rolling_eyes", 0x1F644, "smileys");
        emojis << ES("grimace", 0x1F62C, "smileys");
        emojis << ES("flushed", 0x1F633, "smileys");
        emojis << ES("pleading", 0x1F97A, "smileys");
        emojis << ES("disappointed", 0x1F61E, "smileys");
        emojis << ES("worried", 0x1F61F, "smileys");
        emojis << ES("angry", 0x1F620, "smileys");
        emojis << ES("rage", 0x1F621, "smileys");
        emojis << ES("cry", 0x1F622, "smileys");
        emojis << ES("sob", 0x1F62D, "smileys");
        emojis << ES("scream", 0x1F631, "smileys");
        emojis << ES("cold_sweat", 0x1F630, "smileys");
        emojis << ES("exploding_head", 0x1F92F, "smileys");
        emojis << ES("cool", 0x1F60E, "smileys");
        emojis << ES("nerd", 0x1F913, "smileys");
        emojis << ES("monocle", 0x1F9D0, "smileys");
        emojis << ES("clown", 0x1F921, "smileys");
        emojis << ES("skull", 0x1F480, "smileys");
        emojis << ES("ghost", 0x1F47B, "smileys");
        emojis << ES("alien", 0x1F47D, "smileys");
        emojis << ES("robot", 0x1F916, "smileys");
        emojis << ES("poop", 0x1F4A9, "smileys");
        emojis << ES("party", 0x1F973, "smileys");
        emojis << ES("mask", 0x1F637, "smileys");
        emojis << ES("sleeping", 0x1F634, "smileys");
        emojis << ES("drool", 0x1F924, "smileys");
        emojis << ES("vomit", 0x1F92E, "smileys");
        emojis << ES("devil", 0x1F608, "smileys");
        emojis << ES("imp", 0x1F47F, "smileys");

        // Gestures
        emojis << ES("thumbsup", 0x1F44D, "gestures");
        emojis << ES("thumbsdown", 0x1F44E, "gestures");
        emojis << ES("clap", 0x1F44F, "gestures");
        emojis << ES("wave", 0x1F44B, "gestures");
        emojis << ES("raised_hands", 0x1F64C, "gestures");
        emojis << ES("pray", 0x1F64F, "gestures");
        emojis << ES("handshake", 0x1F91D, "gestures");
        emojis << ES("muscle", 0x1F4AA, "gestures");
        emojis << ES("ok_hand", 0x1F44C, "gestures");
        emojis << ES("pinch", 0x1F90F, "gestures");
        emojis << E("point_up", 0x261D, "gestures");
        emojis << E("v", 0x270C, "gestures");
        emojis << ES("crossed_fingers", 0x1F91E, "gestures");
        emojis << ES("love_you", 0x1F91F, "gestures");
        emojis << ES("fist", 0x1F44A, "gestures");
        emojis << ES("eyes", 0x1F440, "gestures");

        // Hearts & Symbols
        emojis << E("heart", 0x2764, "symbols");
        emojis << ES("orange_heart", 0x1F9E1, "symbols");
        emojis << ES("yellow_heart", 0x1F49B, "symbols");
        emojis << ES("green_heart", 0x1F49A, "symbols");
        emojis << ES("blue_heart", 0x1F499, "symbols");
        emojis << ES("purple_heart", 0x1F49C, "symbols");
        emojis << ES("broken_heart", 0x1F494, "symbols");
        emojis << ES("fire", 0x1F525, "symbols");
        emojis << E("star", 0x2B50, "symbols");
        emojis << E("sparkles", 0x2728, "symbols");
        emojis << ES("100", 0x1F4AF, "symbols");
        emojis << E("check", 0x2705, "symbols");
        emojis << E("x", 0x274C, "symbols");
        emojis << E("warning", 0x26A0, "symbols");
        emojis << ES("lock", 0x1F512, "symbols");
        emojis << ES("unlock", 0x1F513, "symbols");
        emojis << ES("key", 0x1F511, "symbols");
        emojis << ES("shield", 0x1F6E1, "symbols");
        emojis << ES("link", 0x1F517, "symbols");
        emojis << ES("bell", 0x1F514, "symbols");
        emojis << ES("megaphone", 0x1F4E3, "symbols");
        emojis << ES("pin", 0x1F4CC, "symbols");

        // Crypto-specific
        emojis << ES("money_bag", 0x1F4B0, "crypto");
        emojis << ES("money_wings", 0x1F4B8, "crypto");
        emojis << ES("dollar", 0x1F4B5, "crypto");
        emojis << ES("chart_up", 0x1F4C8, "crypto");
        emojis << ES("chart_down", 0x1F4C9, "crypto");
        emojis << ES("rocket", 0x1F680, "crypto");
        emojis << ES("moon", 0x1F319, "crypto");
        emojis << ES("full_moon", 0x1F315, "crypto");
        emojis << ES("diamond", 0x1F48E, "crypto");
        emojis << ES("whale", 0x1F433, "crypto");
        emojis << ES("bear", 0x1F43B, "crypto");
        emojis << ES("bull", 0x1F402, "crypto");
        emojis << ES("wolf", 0x1F43A, "crypto");
        emojis << ES("globe", 0x1F30D, "crypto");
        emojis << ES("gear", 0x2699, "crypto");
        emojis << ES("hammer", 0x1F528, "crypto");
        emojis << ES("chains", 0x26D3, "crypto");
        emojis << ES("hourglass", 0x23F3, "crypto");

        // Nature
        emojis << ES("sun", 0x2600, "nature");
        emojis << ES("cloud", 0x2601, "nature");
        emojis << ES("rainbow", 0x1F308, "nature");
        emojis << ES("lightning", 0x26A1, "nature");
        emojis << ES("snowflake", 0x2744, "nature");
        emojis << ES("tree", 0x1F333, "nature");
        emojis << ES("flower", 0x1F33B, "nature");
        emojis << ES("mushroom", 0x1F344, "nature");

        // Objects
        emojis << ES("laptop", 0x1F4BB, "objects");
        emojis << ES("phone", 0x1F4F1, "objects");
        emojis << ES("camera", 0x1F4F7, "objects");
        emojis << ES("book", 0x1F4D6, "objects");
        emojis << ES("pencil", 0x270F, "objects");
        emojis << ES("bulb", 0x1F4A1, "objects");
        emojis << ES("wrench", 0x1F527, "objects");
        emojis << ES("trophy", 0x1F3C6, "objects");
        emojis << ES("medal", 0x1F3C5, "objects");
        emojis << ES("crown", 0x1F451, "objects");
        emojis << ES("gift", 0x1F381, "objects");
        emojis << ES("balloon", 0x1F388, "objects");
        emojis << ES("confetti", 0x1F389, "objects");
    }
    return emojis;
}

EmojiPicker::EmojiPicker(QWidget *parent) : QWidget(parent)
{
    setWindowFlags(Qt::Popup);
    setFixedSize(340, 400);
    setStyleSheet("background-color: #1a1a2e; border: 1px solid #2a2a4e; border-radius: 8px;");

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(8, 8, 8, 8);
    mainLayout->setSpacing(4);

    // Category tabs
    QHBoxLayout *catRow = new QHBoxLayout();
    catRow->setSpacing(2);
    QStringList cats; cats << "smileys" << "gestures" << "symbols" << "crypto" << "nature" << "objects";
    QStringList catIcons; catIcons << QString(QChar(0x1F600)).replace(QChar(0x1F600), ":-)")
                                   << "Gest" << "Sym" << "Crypto" << "Nat" << "Obj";
    // Use simple text labels for categories
    QString catLabels[] = {":-)", "OK", "Heart", "$", "Sun", "PC"};
    for (int i = 0; i < cats.size(); i++)
    {
        QPushButton *catBtn = new QPushButton(catLabels[i]);
        catBtn->setFixedSize(48, 28);
        catBtn->setStyleSheet("QPushButton { background: #16213e; color: #aaa; border: none; border-radius: 4px; font-size: 11px; }"
                             "QPushButton:hover { background: #2a2a5e; color: white; }");
        QString cat = cats[i];
        connect(catBtn, &QPushButton::clicked, [this, cat]() { populateGrid(cat); searchEdit->clear(); });
        catRow->addWidget(catBtn);
    }
    QPushButton *allBtn = new QPushButton("All");
    allBtn->setFixedSize(36, 28);
    allBtn->setStyleSheet("QPushButton { background: #2a2a5e; color: white; border: none; border-radius: 4px; font-size: 11px; }");
    connect(allBtn, &QPushButton::clicked, [this]() { populateGrid(); searchEdit->clear(); });
    catRow->addWidget(allBtn);
    mainLayout->addLayout(catRow);

    // Search bar
    searchEdit = new QLineEdit();
    searchEdit->setPlaceholderText(tr("Search emoji..."));
    searchEdit->setStyleSheet("background-color: #16213e; color: #eee; border: 1px solid #2a2a4e; border-radius: 4px; padding: 4px; font-size: 12px;");
    mainLayout->addWidget(searchEdit);

    // Scrollable emoji grid
    QScrollArea *scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background: transparent;");

    gridWidget = new QWidget();
    emojiGrid = new QGridLayout(gridWidget);
    emojiGrid->setSpacing(2);
    emojiGrid->setContentsMargins(0, 0, 0, 0);

    scroll->setWidget(gridWidget);
    mainLayout->addWidget(scroll);

    connect(searchEdit, SIGNAL(textChanged(QString)), this, SLOT(onSearchChanged(QString)));

    populateGrid();
}

void EmojiPicker::populateGrid(const QString& filter)
{
    // Clear existing
    QLayoutItem *child;
    while ((child = emojiGrid->takeAt(0)) != 0)
    {
        if (child->widget()) child->widget()->deleteLater();
        delete child;
    }

    const QList<EmojiEntry>& emojis = getAllEmojis();
    int col = 0, row = 0;
    int cols = 8;

    for (const EmojiEntry& e : emojis)
    {
        // Filter by category name OR shortcode search
        if (!filter.isEmpty())
        {
            // Check if filter is a category name
            if (filter == "smileys" || filter == "gestures" || filter == "symbols" ||
                filter == "crypto" || filter == "nature" || filter == "objects")
            {
                if (e.category != filter) continue;
            }
            else
            {
                if (!e.shortcode.contains(filter, Qt::CaseInsensitive)) continue;
            }
        }

        // Use QToolButton with proper Unicode text
        QToolButton *btn = new QToolButton();
        btn->setFixedSize(36, 36);
        btn->setToolTip(":" + e.shortcode + ":");
        btn->setText(e.unicode);
        btn->setStyleSheet(
            "QToolButton { font-size: 22px; border: none; border-radius: 4px; }"
            "QToolButton:hover { background-color: #2a2a5e; }");

        // On macOS, force the Apple Color Emoji font via QFont
        QFont emojiFont("Apple Color Emoji");
        emojiFont.setPointSize(18);
        btn->setFont(emojiFont);

        QString emoji = e.unicode;
        connect(btn, &QToolButton::clicked, [this, emoji]() {
            emit emojiSelected(emoji);
            hide();
        });

        emojiGrid->addWidget(btn, row, col);
        col++;
        if (col >= cols) { col = 0; row++; }
    }
}

void EmojiPicker::onSearchChanged(const QString& text)
{
    populateGrid(text);
}

QList<EmojiEntry> EmojiPicker::searchEmojis(const QString& partial)
{
    QList<EmojiEntry> results;
    for (const EmojiEntry& e : getAllEmojis())
    {
        if (e.shortcode.startsWith(partial, Qt::CaseInsensitive))
            results.append(e);
        if (results.size() >= 8)
            break;
    }
    return results;
}

QString EmojiPicker::replaceShortcodes(const QString& text)
{
    QString result = text;
    for (const EmojiEntry& e : getAllEmojis())
    {
        result.replace(":" + e.shortcode + ":", e.unicode);
    }
    return result;
}

// === EmojiAutocomplete ===

EmojiAutocomplete::EmojiAutocomplete(QWidget *parent) : QListWidget(parent)
{
    setWindowFlags(Qt::Popup | Qt::FramelessWindowHint);
    setFixedWidth(280);
    setMaximumHeight(200);
    setStyleSheet(
        "QListWidget { background-color: #16213e; color: #eee; border: 1px solid #2a2a4e; font-size: 14px;"
        " font-family: 'Apple Color Emoji', 'Segoe UI Emoji', 'Noto Color Emoji', sans-serif; }"
        "QListWidget::item { padding: 4px 8px; }"
        "QListWidget::item:selected { background-color: #2a2a5e; }");

    connect(this, SIGNAL(itemClicked(QListWidgetItem*)), this, SLOT(onItemClicked(QListWidgetItem*)));
}

void EmojiAutocomplete::updateSuggestions(const QString& partial)
{
    clear();
    if (partial.isEmpty())
    {
        hide();
        return;
    }

    QList<EmojiEntry> matches = EmojiPicker::searchEmojis(partial);
    if (matches.isEmpty())
    {
        hide();
        return;
    }

    for (const EmojiEntry& e : matches)
    {
        QListWidgetItem *item = new QListWidgetItem(e.unicode + "  :" + e.shortcode + ":");
        item->setData(Qt::UserRole, e.unicode);
        addItem(item);
    }

    setFixedHeight(qMin(count() * 28 + 4, 200));
    show();
}

void EmojiAutocomplete::onItemClicked(QListWidgetItem *item)
{
    if (item)
    {
        emit emojiChosen(item->data(Qt::UserRole).toString());
        hide();
    }
}
