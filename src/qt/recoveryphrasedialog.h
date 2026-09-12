#ifndef RECOVERYPHRASEDIALOG_H
#define RECOVERYPHRASEDIALOG_H

#include <QDialog>

class WalletModel;

QT_BEGIN_NAMESPACE
class QLabel;
class QPlainTextEdit;
class QPushButton;
QT_END_NAMESPACE

/** Show this wallet's 24-word recovery phrase (the shielded seed), or restore from one.
 *  Fetched only after unlock, never written to disk, buffer overwritten on close. */
class RecoveryPhraseDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode { ShowPhrase, RestoreFromPhrase };

    explicit RecoveryPhraseDialog(Mode mode, QWidget* parent = 0);
    ~RecoveryPhraseDialog();

    void setModel(WalletModel* model);

private slots:
    void reveal();
    void restore();
    void copyToClipboard();

private:
    void wipe();
    bool requireUnlocked(QString& errorOut);

    Mode m_mode;
    WalletModel* m_model;
    QLabel* m_warning;
    QLabel* m_status;
    QPlainTextEdit* m_words;
    QPushButton* m_action;
    QPushButton* m_copy;
    bool m_revealed;
};

#endif // RECOVERYPHRASEDIALOG_H
