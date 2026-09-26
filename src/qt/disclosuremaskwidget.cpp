#include "disclosuremaskwidget.h"
#include "iv5rpcbridge.h"

#include "privacy_vnext/iv5_protocol.h"

#include <QComboBox>
#include <QFormLayout>
#include <QLabel>
#include <QVBoxLayout>

DisclosureMaskWidget::DisclosureMaskWidget(QWidget *parent) :
    QWidget(parent),
    maskCombo(0),
    detailLabel(0),
    publicMaskLabel(0),
    receiverWarningLabel(0),
    rarityWarningLabel(0)
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    QFormLayout *form = new QFormLayout();
    maskCombo = new QComboBox();
    // Listed from the default downwards, so the safe choice is the one already
    // selected and every step down the list publishes strictly more.
    for (int nMask = (int)iv5::DISCLOSURE_MASK; nMask >= 0; nMask--)
    {
        QString label = Iv5Rpc::MaskTitle(nMask);
        if (nMask == (int)iv5::WALLET_DEFAULT_DISCLOSURE_MASK)
            label += tr("  [default]");
        maskCombo->addItem(label, nMask);
    }
    form->addRow(tr("Disclosure:"), maskCombo);
    layout->addLayout(form);

    detailLabel = new QLabel();
    detailLabel->setWordWrap(true);
    detailLabel->setStyleSheet("font-family: monospace;");
    layout->addWidget(detailLabel);

    publicMaskLabel = new QLabel(tr(
        "The mask itself is public. It is stored in the clear in the transaction "
        "payload, so anyone reading the chain sees which mask you chose."));
    publicMaskLabel->setWordWrap(true);
    publicMaskLabel->setStyleSheet("color: #d98c00;");
    layout->addWidget(publicMaskLabel);

    rarityWarningLabel = new QLabel();
    rarityWarningLabel->setWordWrap(true);
    rarityWarningLabel->setStyleSheet("color: #d98c00; font-weight: bold;");
    layout->addWidget(rarityWarningLabel);

    receiverWarningLabel = new QLabel();
    receiverWarningLabel->setWordWrap(true);
    receiverWarningLabel->setStyleSheet("color: #c62828; font-weight: bold;");
    layout->addWidget(receiverWarningLabel);

    connect(maskCombo, SIGNAL(currentIndexChanged(int)),
            this, SLOT(onSelectionChanged(int)));

    setMask((int)iv5::WALLET_DEFAULT_DISCLOSURE_MASK);
    refreshExplanation();
}

int DisclosureMaskWidget::mask() const
{
    const QVariant data = maskCombo->currentData();
    bool ok = false;
    const int nMask = data.toInt(&ok);
    if (!ok || nMask < 0 || nMask > (int)iv5::DISCLOSURE_MASK)
        return (int)iv5::WALLET_DEFAULT_DISCLOSURE_MASK;
    return nMask;
}

void DisclosureMaskWidget::setMask(int nMask)
{
    const int index = maskCombo->findData(nMask);
    if (index >= 0)
        maskCombo->setCurrentIndex(index);
}

bool DisclosureMaskWidget::isDefaultMask() const
{
    return mask() == (int)iv5::WALLET_DEFAULT_DISCLOSURE_MASK;
}

void DisclosureMaskWidget::onSelectionChanged(int)
{
    refreshExplanation();
    emit maskChanged(mask());
}

void DisclosureMaskWidget::refreshExplanation()
{
    const int nMask = mask();
    detailLabel->setText(Iv5Rpc::MaskDetail(nMask));

    if (isDefaultMask())
        rarityWarningLabel->setText(QString());
    else
        rarityWarningLabel->setText(tr(
            "Mask %1 is not the wallet default. Most transactions carry mask %2, so a "
            "rarer mask narrows the set of wallets a transaction could have come from "
            "and can identify you on its own.")
            .arg(nMask)
            .arg((int)iv5::WALLET_DEFAULT_DISCLOSURE_MASK));

    if (Iv5Rpc::MaskDisclosesReceiver(nMask))
        receiverWarningLabel->setText(tr(
            "Recipient disclosure is permanent and retroactive. The recipient's spend "
            "and view keys are written into the transaction in the clear and proved to "
            "belong to that output, so anyone reading the chain now or in ten years "
            "learns which address received it. It cannot be withdrawn, and it "
            "forecloses ever disclosing the sender of a spend of that output without "
            "exposing the same link. Spending that output through a NullSend round "
            "breaks the link going forward: the round's inputs stay public, but which "
            "of its outputs is yours does not."));
    else
        receiverWarningLabel->setText(QString());
}

QString DisclosureMaskWidget::confirmationText() const
{
    const int nMask = mask();
    QString text = tr("Disclosure mask %1.\n%2\n\nThe mask is public on chain.")
                       .arg(nMask)
                       .arg(Iv5Rpc::MaskDetail(nMask));
    if (Iv5Rpc::MaskDisclosesReceiver(nMask))
        text += tr("\n\nThis publishes the recipient's address permanently. That cannot "
                   "be undone later, and whoever spends that output later can be identified "
                   "from chain data. Spending it through NullSend breaks the link going "
                   "forward.");
    if (!isDefaultMask())
        text += tr("\n\nThis is not the wallet default (mask %1); a rare mask is itself "
                   "identifying.")
                    .arg((int)iv5::WALLET_DEFAULT_DISCLOSURE_MASK);
    return text;
}
