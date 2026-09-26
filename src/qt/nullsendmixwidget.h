#ifndef NULLSENDMIXWIDGET_H
#define NULLSENDMIXWIDGET_H

#include "walletmodel.h"

#include <QPointer>
#include <QWidget>

#include <memory>

class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;
class QTimer;

/** NullSend v2008 seat: prepare a tier note, join a round, follow it.
 *
 *  Drives mixprepare, mixjoin, mixstatus, z_listiv5holds and z_holdiv5note. Running a
 *  round (mixcoordinate) is an operator task and stays on RPC.
 */
class NullSendMixWidget : public QWidget
{
    Q_OBJECT

public:
    explicit NullSendMixWidget(QWidget *parent = 0);
    ~NullSendMixWidget();
    void setModel(WalletModel *model);

private slots:
    void onPrepare();
    void onRefreshNotes();
    void onReleaseNote();
    void onJoin();
    void onRefreshStatus();

private:
    void report(const QString& heading, const QString& body);
    void dropUnlockHold();

    QPointer<WalletModel> model;
    // A seat derives keys from the IV5 seed for the whole round, and a lock clears it.
    std::unique_ptr<WalletModel::UnlockContext> unlockHold;

    QLabel *serviceLabel;
    QComboBox *tierCombo;
    QPushButton *prepareButton;
    QListWidget *notesList;
    QPushButton *refreshNotesButton;
    QPushButton *releaseNoteButton;

    QLineEdit *coordinatorEdit;
    QLineEdit *recordSlotEdit;
    QPushButton *joinButton;

    QTableWidget *jobsTable;
    QLabel *outcomeLabel;
    QTimer *statusTimer;

    QPlainTextEdit *outputView;
};

#endif // NULLSENDMIXWIDGET_H
