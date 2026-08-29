#include "finalitystatuswidget.h"
#include "iv5rpcbridge.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

namespace
{
// Each poll makes the node run a committee draw and several database reads under
// cs_main, so it stays slow: nothing here changes faster than an epoch boundary.
const int kPollIntervalMs = 15000;

QLabel* MakeValueLabel()
{
    QLabel *label = new QLabel(QObject::tr("unknown"));
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return label;
}
}

FinalityStatusWidget::FinalityStatusWidget(QWidget *parent) :
    QWidget(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *intro = new QLabel(tr(
        "After IDAG activates, stake does not produce blocks. Blocks are proof of "
        "work; stake votes for finality. What follows is the state of that vote."));
    intro->setWordWrap(true);
    intro->setStyleSheet("color: #888;");
    layout->addWidget(intro);

    labelError = new QLabel();
    labelError->setWordWrap(true);
    labelError->setStyleSheet("color: #c62828; font-weight: bold;");
    labelError->setVisible(false);
    layout->addWidget(labelError);

    QGroupBox *chainGroup = new QGroupBox(tr("Chain"));
    QFormLayout *chainForm = new QFormLayout(chainGroup);
    labelHeight = MakeValueLabel();
    labelEpoch = MakeValueLabel();
    labelFinalized = MakeValueLabel();
    labelTier = MakeValueLabel();
    labelVotes = MakeValueLabel();
    labelBoundaries = MakeValueLabel();
    labelEpochHealth = MakeValueLabel();
    chainForm->addRow(tr("Tip height:"), labelHeight);
    chainForm->addRow(tr("Epoch:"), labelEpoch);
    chainForm->addRow(tr("Finalized:"), labelFinalized);
    chainForm->addRow(tr("Finality tier:"), labelTier);
    chainForm->addRow(tr("Votes this epoch:"), labelVotes);
    chainForm->addRow(tr("Activation:"), labelBoundaries);
    chainForm->addRow(tr("Epoch state:"), labelEpochHealth);
    layout->addWidget(chainGroup);

    QGroupBox *committeeGroup = new QGroupBox(tr("Finality committee"));
    QFormLayout *committeeForm = new QFormLayout(committeeGroup);
    labelCommitteeSeated = MakeValueLabel();
    labelCommitteeTerm = MakeValueLabel();
    labelCommitteeSetHash = MakeValueLabel();
    labelCommitteeSetHash->setStyleSheet("font-family: monospace; font-size: 11px;");
    labelNextDraw = MakeValueLabel();
    labelNextDraw->setWordWrap(true);
    committeeForm->addRow(tr("Seated:"), labelCommitteeSeated);
    committeeForm->addRow(tr("Term:"), labelCommitteeTerm);
    labelCommitteeSeatKeys = MakeValueLabel();
    labelCommitteeSeatKeys->setWordWrap(true);
    labelCommitteeSeatKeys->setStyleSheet("font-family: monospace; font-size: 11px;");
    committeeForm->addRow(tr("Committee set hash:"), labelCommitteeSetHash);
    committeeForm->addRow(tr("Seats:"), labelCommitteeSeatKeys);
    committeeForm->addRow(tr("Next term draw:"), labelNextDraw);
    layout->addWidget(committeeGroup);

    QGroupBox *certGroup = new QGroupBox(tr("Certificate"));
    QFormLayout *certForm = new QFormLayout(certGroup);
    labelLane = MakeValueLabel();
    labelLane->setWordWrap(true);
    labelCertSource = MakeValueLabel();
    labelPromotion = MakeValueLabel();
    certForm->addRow(tr("Producing lane:"), labelLane);
    certForm->addRow(tr("Source:"), labelCertSource);
    certForm->addRow(tr("Private promotion:"), labelPromotion);
    layout->addWidget(certGroup);

    QHBoxLayout *buttons = new QHBoxLayout();
    refreshButton = new QPushButton(tr("Refresh"));
    buttons->addWidget(refreshButton);
    buttons->addStretch();
    layout->addLayout(buttons);
    layout->addStretch();

    pollTimer = new QTimer(this);
    pollTimer->setInterval(kPollIntervalMs);

    connect(refreshButton, SIGNAL(clicked()), this, SLOT(refresh()));
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(refresh()));
}

void FinalityStatusWidget::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);
    refresh();
    pollTimer->start();
}

void FinalityStatusWidget::hideEvent(QHideEvent *event)
{
    pollTimer->stop();
    QWidget::hideEvent(event);
}

void FinalityStatusWidget::refresh()
{
    Iv5Rpc::FinalitySnapshot snap;
    QString error;
    if (!Iv5Rpc::FetchFinality(snap, error))
    {
        labelError->setText(tr("getfinalityinfo failed: %1").arg(error));
        labelError->setVisible(true);
        return;
    }
    labelError->setVisible(false);

    labelHeight->setText(QString::number(snap.nHeight));
    labelEpoch->setText(tr("%1 (interval %2 blocks)")
                            .arg(snap.nEpoch)
                            .arg(snap.nEpochInterval));
    labelFinalized->setText(tr("height %1, epoch %2")
                                .arg(snap.nFinalizedHeight)
                                .arg(snap.nFinalizedEpoch));
    labelTier->setText(tr("%1 (%2 consecutive hard epochs)")
                           .arg(snap.strTier)
                           .arg(snap.nConsecutiveHardEpochs));
    labelVotes->setText(tr("%1 transparent, %2 private, %3 distinct voters")
                            .arg(snap.nTransparentVotes)
                            .arg(snap.nPrivateVotes)
                            .arg(snap.nVoters));
    labelBoundaries->setText(tr("Boundary A %1, Boundary B %2")
                                 .arg(snap.fBoundaryAActive ? tr("active") : tr("inactive"))
                                 .arg(snap.fBoundaryBActive ? tr("active") : tr("inactive")));
    labelEpochHealth->setText(snap.strEpochStateHealth);

    if (snap.fCommitteeSeated)
    {
        labelCommitteeSeated->setText(tr("yes, %1 of %2 threshold")
                                          .arg(snap.nCommitteeThresholdM)
                                          .arg(snap.nCommitteeSeats));
        labelCommitteeSeated->setStyleSheet("color: #2e7d32; font-weight: bold;");
    }
    else
    {
        labelCommitteeSeated->setText(tr("no committee is seated for this epoch"));
        labelCommitteeSeated->setStyleSheet("color: #d98c00; font-weight: bold;");
    }
    labelCommitteeTerm->setText(tr("term epoch %1, %2 epochs per term")
                                    .arg(snap.nCommitteeTermEpoch)
                                    .arg(snap.nCommitteeTermEpochs));
    labelCommitteeSetHash->setText(snap.strCommitteeSetHash.isEmpty()
                                       ? tr("none")
                                       : snap.strCommitteeSetHash);
    // Seat order is drawn, not configured, so an operator has to read the keys back
    // to know whether a seat went to one this wallet can sign for.
    labelCommitteeSeatKeys->setText(snap.vSeatKeys.isEmpty()
                                        ? tr("none")
                                        : snap.vSeatKeys.join("\n"));

    // A thin registry is the usual reason nothing seats, so the shortfall is stated
    // as a count rather than left for the operator to work out at the boundary.
    if (!snap.fHaveNextDraw)
        labelNextDraw->setText(tr("the draw for the next term could not be computed"));
    else if (snap.fNextSeated)
        labelNextDraw->setText(tr("term %1 will seat, anchor height %2, %3 registry rows")
                                   .arg(snap.nNextTermEpoch)
                                   .arg(snap.nNextAnchorHeight)
                                   .arg(snap.nNextRegistryRows));
    else
        labelNextDraw->setText(tr("term %1 will NOT seat: %2 registry rows, %3 required "
                                  "(anchor height %4)")
                                   .arg(snap.nNextTermEpoch)
                                   .arg(snap.nNextRegistryRows)
                                   .arg(snap.nNextRowsRequired)
                                   .arg(snap.nNextAnchorHeight));

    labelLane->setText(snap.LaneDescription());
    labelLane->setStyleSheet(snap.fPrivateCertificatePresent
                                 ? "color: #2e7d32; font-weight: bold;"
                                 : "");
    labelCertSource->setText(tr("%1 (%2 certificate(s) this epoch, %3 with private weight)")
                                 .arg(snap.strCertificateSource)
                                 .arg(snap.nCertificates)
                                 .arg(snap.nPrivateCertificates));
    labelPromotion->setText(snap.strPrivatePromotionStatus);
}
