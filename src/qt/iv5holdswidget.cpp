#include "iv5holdswidget.h"

#include "iv5rpcbridge.h"

#include <QAbstractItemView>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QVBoxLayout>

Iv5HoldsWidget::Iv5HoldsWidget(QWidget* parent)
    : QWidget(parent), m_summary(0), m_table(0), m_noteEdit(0), m_hold(0), m_release(0),
      m_status(0)
{
    QVBoxLayout* layout = new QVBoxLayout(this);

    QLabel* help = new QLabel(tr(
        "A held note is skipped by every spend and every note vote; a collateral "
        "registration that names it still takes it. Held value is not counted in the "
        "spendable or pending balance. Holds survive restarts, and a hold can be placed on "
        "an output before the wallet has scanned it."));
    help->setWordWrap(true);
    layout->addWidget(help);

    m_summary = new QLabel(tr("unknown"));
    m_summary->setStyleSheet("font-weight: bold;");
    layout->addWidget(m_summary);

    m_table = new QTableWidget(0, 3);
    m_table->setHorizontalHeaderLabels(QStringList() << tr("Note (txid:index)") << tr("Amount")
                                                     << tr("State"));
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setMinimumHeight(160);
    layout->addWidget(m_table);

    QHBoxLayout* listRow = new QHBoxLayout();
    QPushButton* refreshButton = new QPushButton(tr("Refresh"));
    m_release = new QPushButton(tr("Release selected"));
    m_release->setEnabled(false);
    listRow->addWidget(refreshButton);
    listRow->addWidget(m_release);
    listRow->addStretch();
    layout->addLayout(listRow);

    QHBoxLayout* holdRow = new QHBoxLayout();
    m_noteEdit = new QLineEdit();
    m_noteEdit->setPlaceholderText(tr("txid:index of an IV5 output of this wallet"));
    m_hold = new QPushButton(tr("Hold"));
    holdRow->addWidget(m_noteEdit, 1);
    holdRow->addWidget(m_hold);
    layout->addLayout(holdRow);

    m_status = new QLabel();
    m_status->setWordWrap(true);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(m_status);
    layout->addStretch();

    connect(refreshButton, SIGNAL(clicked()), this, SLOT(refresh()));
    connect(m_hold, SIGNAL(clicked()), this, SLOT(onHold()));
    connect(m_release, SIGNAL(clicked()), this, SLOT(onRelease()));
    connect(m_table, SIGNAL(itemSelectionChanged()), this, SLOT(onSelectionChanged()));
}

void Iv5HoldsWidget::refresh()
{
    QList<Iv5Rpc::HeldNote> notes;
    QString strError;
    m_table->setRowCount(0);
    if (!Iv5Rpc::FetchHolds(notes, strError))
    {
        m_summary->setText(tr("Could not list holds: %1").arg(strError));
        onSelectionChanged();
        return;
    }

    double dHeld = 0;
    int nUnscanned = 0;
    for (int i = 0; i < notes.size(); i++)
    {
        const Iv5Rpc::HeldNote& n = notes.at(i);
        m_table->insertRow(i);
        QTableWidgetItem* noteItem = new QTableWidgetItem(n.strNote);
        noteItem->setData(Qt::UserRole, n.strNote);
        m_table->setItem(i, 0, noteItem);
        m_table->setItem(i, 1, new QTableWidgetItem(
            n.fHaveAmount ? QString::number(n.dAmount, 'f', 8) : tr("not scanned")));
        QString strState;
        if (!n.fHaveAmount)
        {
            strState = tr("not scanned yet");
            nUnscanned++;
        }
        else if (n.fSpent)
        {
            strState = tr("spent");
        }
        else
        {
            strState = tr("held");
            dHeld += n.dAmount;
        }
        m_table->setItem(i, 2, new QTableWidgetItem(strState));
    }
    m_table->resizeColumnToContents(1);

    QString strSummary = tr("%1 hold(s); %2 INN unspent and held")
                             .arg(notes.size())
                             .arg(QString::number(dHeld, 'f', 8));
    if (nUnscanned > 0)
        strSummary += tr("; %1 not scanned yet").arg(nUnscanned);
    m_summary->setText(strSummary);
    onSelectionChanged();
}

void Iv5HoldsWidget::onSelectionChanged()
{
    m_release->setEnabled(m_table->currentRow() >= 0 && !m_table->selectedItems().isEmpty());
}

void Iv5HoldsWidget::onHold()
{
    const QString strNote = m_noteEdit->text().trimmed();
    if (!QRegularExpression("^[0-9a-fA-F]{64}:[0-9]+$").match(strNote).hasMatch())
    {
        m_status->setText(tr("A note is named as <txid>:<index>."));
        return;
    }
    if (QMessageBox::question(this, tr("Hold note"),
            tr("Hold %1?\n\nNo spend and no note vote will select it until it is released.")
                .arg(strNote),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    QString strReply, strError;
    if (!Iv5Rpc::Call("z_holdiv5note", QStringList() << strNote << "true", strReply, strError))
    {
        m_status->setText(tr("z_holdiv5note refused: %1").arg(strError));
        return;
    }
    m_noteEdit->clear();
    m_status->setText(tr("Held %1.").arg(strNote));
    refresh();
}

void Iv5HoldsWidget::onRelease()
{
    const int nRow = m_table->currentRow();
    QTableWidgetItem* item = nRow >= 0 ? m_table->item(nRow, 0) : 0;
    const QString strNote = item ? item->data(Qt::UserRole).toString() : QString();
    if (strNote.isEmpty())
    {
        m_status->setText(tr("Select a held note first."));
        return;
    }
    if (QMessageBox::question(this, tr("Release note"),
            tr("Release %1 back to ordinary spending?\n\n"
               "This also takes it out of NullSend. If this note's final share in a round "
               "has already left, that round's coordinator may still publish a transaction "
               "spending it, and any other spend of the note races it.")
                .arg(strNote),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    QString strReply, strError;
    if (!Iv5Rpc::Call("z_holdiv5note", QStringList() << strNote << "false", strReply, strError))
    {
        m_status->setText(tr("z_holdiv5note refused: %1").arg(strError));
        return;
    }
    QString strWarning;
    if (Iv5Rpc::ReadField(strReply, "warning", strWarning) && !strWarning.isEmpty())
    {
        m_status->setText(tr("Released %1. Warning: %2").arg(strNote, strWarning));
        QMessageBox::warning(this, tr("Release note"), strWarning);
    }
    else
    {
        m_status->setText(tr("Released %1.").arg(strNote));
    }
    refresh();
}
