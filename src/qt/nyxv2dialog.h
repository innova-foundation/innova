#ifndef NYXV2DIALOG_H
#define NYXV2DIALOG_H

#include <QDialog>
#include <QStringList>

#include "json/json_spirit_value.h"

class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QTextBrowser;
class QTextEdit;
class QCheckBox;
class QWidget;

/** Nyx v2 identity, devices, contact verification and session threads. */
class NyxV2Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit NyxV2Dialog(QWidget *parent = 0);

    /** Runs "nyx <params...>" in process; false with a message on refusal. */
    static bool Call(const QStringList& params, json_spirit::Value& out, QString& err);

private slots:
    void refreshIdentity();
    void onInit();
    void onReset();
    void onConfirm();
    void onPair();
    void onApprove();
    void onInstall();
    void onRevoke();
    void onVerifyContact();
    void onAcceptReset();
    void refreshThreads();
    void onThreadSelected();
    void onSend();
    void onGroupCreate();
    void onGroupMember(const QString& op);

private:
    QString self() const;
    QString mode() const;
    bool run(const QStringList& params, json_spirit::Value& out);
    void showResult(const json_spirit::Value& v);

    QLineEdit *addrEdit;
    QComboBox *modeBox;
    QTabWidget *tabs;

    // Identity
    QLabel *idStatus;
    QWidget *alarmBanner;
    QLabel *alarmText;
    QLabel *ownSafety;
    QTableWidget *deviceTable;
    QTextEdit *pairText;

    // Contact
    QLineEdit *contactEdit;
    QLabel *contactStatus;
    QLabel *contactSafety;
    QWidget *frozenBanner;
    QWidget *resetBanner;
    QLabel *resetText;
    QCheckBox *downgradeBox;
    QString shownContact;

    // Threads
    QListWidget *threadList;
    QTextBrowser *threadView;
    QLineEdit *composer;
    QLabel *threadInfo;

    QTextBrowser *resultView;
};

#endif // NYXV2DIALOG_H
