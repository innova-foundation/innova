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

/** The private collateralnode and finality-member registration path.
 *
 *  Both registrations are v2008 attestations: they publish a key image, which is
 *  a permanent per-node pseudonym, and consensus forces them to disclosure mask 7.
 */
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
    void onMemberPreview();
    void onMemberRegister();
    void onAnnounce();
    void onStatusPrivate();
    void onFinalityStatus();
    void onFinalityRegistry();
    void onRelease();

private:
    // Runs 'collateralnode <args>' and prints the reply. Unlocks first when the
    // subcommand needs a key; a preview never does.
    void run(const QStringList& args, bool fNeedsUnlock);
    bool nodeArgs(bool fConfirm, QStringList& argsOut);
    bool memberArgs(bool fConfirm, QStringList& argsOut);
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

    QLineEdit *memberKeyEdit;
    QLineEdit *memberNoteEdit;
    QPushButton *memberPreviewButton;
    QPushButton *memberRegisterButton;

    QLineEdit *registryHeightEdit;
    QLineEdit *releaseKeyImageEdit;

    QPushButton *listNotesButton;
    QPushButton *announceButton;
    QPushButton *statusButton;
    QPushButton *finalityStatusButton;
    QPushButton *finalityRegistryButton;
    QPushButton *releaseButton;

    QPlainTextEdit *outputView;
};

#endif // PRIVATECOLLATERALWIDGET_H
