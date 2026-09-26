#ifndef PRIVATECOLLATERALWIDGET_H
#define PRIVATECOLLATERALWIDGET_H

#include <QStringList>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTimer;
class WalletModel;

/** Private collateralnode registration: a v2008 attestation publishing a key image (a
 *  permanent per-node pseudonym), forced to disclosure mask 7 by consensus. */
class PrivateCollateralWidget : public QWidget
{
    Q_OBJECT

public:
    explicit PrivateCollateralWidget(QWidget *parent = 0);
    void setModel(WalletModel *model);

private slots:
    void onCarveNote();
    void onRefreshProgress();
    void onListNotes();
    void onNodePreview();
    void onNodeRegister();
    void onAnnounce();
    void onStatusPrivate();
    void onRelease();

private:
    // Runs 'collateralnode <args>' and prints the reply. Unlocks first when the
    // subcommand needs a key; a preview never does.
    void run(const QStringList& args, bool fNeedsUnlock);
    bool nodeArgs(bool fConfirm, QStringList& argsOut);
    void report(const QString& heading, const QString& body);

    WalletModel *model;

    QLabel *guidedStatusLabel;
    QPushButton *carveNoteButton;
    QTimer *progressTimer;
    int nLastAttestableNotes;

    QLineEdit *nodeEndpointEdit;
    QLineEdit *nodePayoutEdit;
    QLineEdit *nodeNoteEdit;
    QPushButton *nodePreviewButton;
    QPushButton *nodeRegisterButton;

    QLineEdit *releaseKeyImageEdit;

    QPushButton *listNotesButton;
    QPushButton *announceButton;
    QPushButton *statusButton;
    QPushButton *releaseButton;

    QPlainTextEdit *outputView;
};

#endif // PRIVATECOLLATERALWIDGET_H
