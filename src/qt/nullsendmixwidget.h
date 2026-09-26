#ifndef NULLSENDMIXWIDGET_H
#define NULLSENDMIXWIDGET_H

#include "iv5rpcbridge.h"
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

/** NullSend v2008 seat: configure, prepare a tier note, find, join, follow and cancel a
 *  round via the mix* RPCs. Coordinating a round (mixcoordinate) stays on RPC.
 */
class NullSendMixWidget : public QWidget
{
    Q_OBJECT

public:
    explicit NullSendMixWidget(QWidget *parent = 0);
    ~NullSendMixWidget();
    void setModel(WalletModel *model);

private slots:
    void onApplyDirectories();
    void onApplyProxy();
    void onCheckProxy();
    void onPrepare();
    void onRefreshNotes();
    void onReleaseNote();
    void onFindRounds();
    void onRoundSelected();
    void onJoin();
    void onCancelSeat();
    void onClearFinished();
    void onRefreshStatus();

private:
    void report(const QString& heading, const QString& body);
    void dropUnlockHold();
    void refreshSettings();
    bool applySetting(const QString& name, const QString& value);
    // The listed round whose coordinator and slot are in the join fields, or -1.
    int listedRoundIndex() const;
    // Empty when a note can take the seat; otherwise why not, for the user.
    QString whyNoNote(const QString& strRound) const;

    QPointer<WalletModel> model;
    // A seat derives keys from the IV5 seed for the whole round, and a lock clears it.
    std::unique_ptr<WalletModel::UnlockContext> unlockHold;

    QLabel *serviceLabel;
    QLineEdit *directoriesEdit;
    QPushButton *applyDirectoriesButton;
    QLineEdit *proxyEdit;
    QPushButton *applyProxyButton;
    QPushButton *checkProxyButton;
    QLabel *proxyLabel;
    bool fSettingsLoaded;

    QComboBox *tierCombo;
    QPushButton *prepareButton;
    QListWidget *notesList;
    QPushButton *refreshNotesButton;
    QPushButton *releaseNoteButton;

    QPushButton *findRoundsButton;
    QTableWidget *roundsTable;
    QList<Iv5Rpc::MixRoundRow> vListedRounds;
    QLineEdit *coordinatorEdit;
    QLineEdit *recordSlotEdit;
    QPushButton *joinButton;
    QLabel *eligibilityLabel;

    QTableWidget *jobsTable;
    QPushButton *cancelSeatButton;
    QPushButton *clearFinishedButton;
    QLabel *outcomeLabel;
    QTimer *statusTimer;

    QPlainTextEdit *outputView;
};

#endif // NULLSENDMIXWIDGET_H
