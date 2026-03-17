#ifndef EMOJIPICKER_H
#define EMOJIPICKER_H

#include <QWidget>
#include <QGridLayout>
#include <QPushButton>
#include <QScrollArea>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QListWidget>

/** Emoji data: shortcode → unicode mapping */
struct EmojiEntry {
    QString shortcode; // e.g., "smile"
    QString unicode;   // e.g., "\xF0\x9F\x98\x84"
    QString category;
};

/** Popup emoji picker widget */
class EmojiPicker : public QWidget
{
    Q_OBJECT

public:
    explicit EmojiPicker(QWidget *parent = 0);

    /** Get all emojis matching a partial shortcode (for autocomplete) */
    static QList<EmojiEntry> searchEmojis(const QString& partial);

    /** Convert :shortcode: patterns in text to unicode */
    static QString replaceShortcodes(const QString& text);

signals:
    void emojiSelected(const QString& emoji);

private slots:
    void onSearchChanged(const QString& text);

private:
    QLineEdit *searchEdit;
    QGridLayout *emojiGrid;
    QWidget *gridWidget;

    void populateGrid(const QString& filter = "");

    static QList<EmojiEntry>& getAllEmojis();
};

/** Inline autocomplete popup for :shortcode: typing */
class EmojiAutocomplete : public QListWidget
{
    Q_OBJECT

public:
    explicit EmojiAutocomplete(QWidget *parent = 0);
    void updateSuggestions(const QString& partial);

signals:
    void emojiChosen(const QString& emoji);

private slots:
    void onItemClicked(QListWidgetItem *item);
};

#endif // EMOJIPICKER_H
