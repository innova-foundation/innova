#ifndef FINALITYSTATUSWIDGET_H
#define FINALITYSTATUSWIDGET_H

#include <QWidget>

class QLabel;
class QPushButton;
class QTimer;

/** Reports finality state: epoch, finalized height, tier, whether a committee is
 *  seated, and which lane produced the certificate.
 */
class FinalityStatusWidget : public QWidget
{
    Q_OBJECT

public:
    explicit FinalityStatusWidget(QWidget *parent = 0);

public slots:
    void refresh();

protected:
    void showEvent(QShowEvent *event);
    void hideEvent(QHideEvent *event);

private:
    QLabel *labelError;
    QLabel *labelHeight;
    QLabel *labelEpoch;
    QLabel *labelFinalized;
    QLabel *labelTier;
    QLabel *labelVotes;
    QLabel *labelBoundaries;
    QLabel *labelEpochHealth;

    QLabel *labelCommitteeSeated;
    QLabel *labelCommitteeTerm;
    QLabel *labelCommitteeSetHash;
    QLabel *labelCommitteeSeatKeys;
    QLabel *labelNextDraw;

    QLabel *labelLane;
    QLabel *labelCertSource;
    QLabel *labelPromotion;

    QPushButton *refreshButton;
    QTimer *pollTimer;
};

#endif // FINALITYSTATUSWIDGET_H
