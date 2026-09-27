#include "iv5seeddialog.h"

#include "iv5rpcbridge.h"
#include "walletmodel.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSpinBox>
#include <QVBoxLayout>

namespace
{

// Busy cursor for the synchronous calls (a rescan can take a while).
class BusyCursor
{
public:
    BusyCursor() { QApplication::setOverrideCursor(Qt::WaitCursor); }
    ~BusyCursor() { QApplication::restoreOverrideCursor(); }
};

} // namespace

Iv5SeedDialog::Iv5SeedDialog(QWidget* parent)
    : QDialog(parent), m_model(0), m_state(0), m_phraseCoverage(0), m_status(0),
      m_create(0), m_adopt(0), m_export(0), m_copy(0), m_exported(0), m_importHex(0),
      m_importCount(0), m_importRescan(0), m_import(0)
{
    setWindowTitle(tr("IV5 seed"));
    setMinimumWidth(560);
    QVBoxLayout* layout = new QVBoxLayout(this);

    QGroupBox* statusGroup = new QGroupBox(tr("Status"));
    QFormLayout* statusForm = new QFormLayout(statusGroup);
    m_state = new QLabel(tr("unknown"));
    m_state->setWordWrap(true);
    m_phraseCoverage = new QLabel(tr("unknown"));
    m_phraseCoverage->setWordWrap(true);
    statusForm->addRow(tr("Seed:"), m_state);
    statusForm->addRow(tr("Recovery phrase covers:"), m_phraseCoverage);
    layout->addWidget(statusGroup);

    QGroupBox* manageGroup = new QGroupBox(tr("Create / extend"));
    QVBoxLayout* manageLayout = new QVBoxLayout(manageGroup);
    QLabel* manageHelp = new QLabel(tr(
        "Create makes the wallet's IV5 seed; back it up afterwards (Settings > Show Recovery "
        "Phrase).\n"
        "Cover transparent addresses makes new transparent addresses derive from the same "
        "seed, so the recovery phrase restores them too. Existing transparent addresses are "
        "not covered and still need a wallet.dat backup, and older builds will refuse to "
        "open the wallet afterwards."));
    manageHelp->setWordWrap(true);
    manageLayout->addWidget(manageHelp);
    QHBoxLayout* manageRow = new QHBoxLayout();
    m_create = new QPushButton(tr("Create seed"));
    m_adopt = new QPushButton(tr("Cover transparent addresses"));
    manageRow->addWidget(m_create);
    manageRow->addWidget(m_adopt);
    manageRow->addStretch();
    manageLayout->addLayout(manageRow);
    layout->addWidget(manageGroup);

    QGroupBox* exportGroup = new QGroupBox(tr("Export seed (hex)"));
    QVBoxLayout* exportLayout = new QVBoxLayout(exportGroup);
    QLabel* exportHelp = new QLabel(tr(
        "The hex seed is the same secret as the 24-word recovery phrase. Anyone who has "
        "it can spend every note this wallet holds or will hold."));
    exportHelp->setWordWrap(true);
    exportLayout->addWidget(exportHelp);
    m_exported = new QPlainTextEdit();
    m_exported->setReadOnly(true);
    QFont mono("Monospace");
    mono.setStyleHint(QFont::TypeWriter);
    m_exported->setFont(mono);
    m_exported->setMaximumHeight(60);
    m_exported->setPlaceholderText(tr("Hidden until exported."));
    exportLayout->addWidget(m_exported);
    QHBoxLayout* exportRow = new QHBoxLayout();
    m_export = new QPushButton(tr("Export"));
    m_copy = new QPushButton(tr("Copy"));
    m_copy->setEnabled(false);
    exportRow->addWidget(m_export);
    exportRow->addWidget(m_copy);
    exportRow->addStretch();
    exportLayout->addLayout(exportRow);
    layout->addWidget(exportGroup);

    QGroupBox* importGroup = new QGroupBox(tr("Import seed (hex)"));
    QFormLayout* importForm = new QFormLayout(importGroup);
    QLabel* importHelp = new QLabel(tr(
        "Only into a wallet with no seed. Notes are found by the rescan, not by the import."));
    importHelp->setWordWrap(true);
    importForm->addRow(importHelp);
    m_importHex = new QLineEdit();
    m_importHex->setFont(mono);
    m_importHex->setEchoMode(QLineEdit::Password);
    m_importHex->setPlaceholderText(tr("64 hex characters"));
    importForm->addRow(tr("Seed:"), m_importHex);
    m_importCount = new QSpinBox();
    m_importCount->setRange(0, 1000000);
    m_importCount->setToolTip(tr("Addresses the original wallet had issued, if known "
                                 "(address_index_count from the export)."));
    importForm->addRow(tr("Address index count:"), m_importCount);
    m_importRescan = new QCheckBox(tr("Rescan the chain after import"));
    m_importRescan->setChecked(true);
    importForm->addRow(QString(), m_importRescan);
    m_import = new QPushButton(tr("Import"));
    importForm->addRow(QString(), m_import);
    layout->addWidget(importGroup);

    m_status = new QLabel();
    m_status->setWordWrap(true);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(m_status);

    QDialogButtonBox* buttons = new QDialogButtonBox(this);
    QPushButton* refresh = buttons->addButton(tr("Refresh"), QDialogButtonBox::ActionRole);
    buttons->addButton(QDialogButtonBox::Close);
    layout->addWidget(buttons);

    connect(buttons, SIGNAL(rejected()), this, SLOT(reject()));
    connect(refresh, SIGNAL(clicked()), this, SLOT(refreshStatus()));
    connect(m_create, SIGNAL(clicked()), this, SLOT(createSeed()));
    connect(m_adopt, SIGNAL(clicked()), this, SLOT(adoptPhrase()));
    connect(m_export, SIGNAL(clicked()), this, SLOT(exportSeed()));
    connect(m_copy, SIGNAL(clicked()), this, SLOT(copySeed()));
    connect(m_import, SIGNAL(clicked()), this, SLOT(importSeed()));
}

Iv5SeedDialog::~Iv5SeedDialog()
{
    wipe();
}

void Iv5SeedDialog::setModel(WalletModel* model)
{
    m_model = model;
    refreshStatus();
}

void Iv5SeedDialog::wipe()
{
    if (m_exported != 0)
    {
        const int n = m_exported->toPlainText().size();
        if (n > 0)
            m_exported->setPlainText(QString(n, QChar('x')));
        m_exported->clear();
    }
    if (m_importHex != 0)
    {
        const int n = m_importHex->text().size();
        if (n > 0)
            m_importHex->setText(QString(n, QChar('x')));
        m_importHex->clear();
    }
}

void Iv5SeedDialog::refreshStatus()
{
    Iv5Rpc::PoolSnapshot pool;
    QString strError;
    if (!Iv5Rpc::FetchPool(pool, strError))
    {
        m_state->setText(tr("unknown: %1").arg(strError));
        m_phraseCoverage->setText(tr("unknown"));
        m_create->setEnabled(false);
        m_adopt->setEnabled(false);
        m_export->setEnabled(false);
        m_import->setEnabled(false);
        return;
    }

    if (!pool.fSeedPresent)
        m_state->setText(tr("none. Create one, or restore from a phrase or an exported hex "
                            "seed."));
    else if (pool.strKeyState == "locked")
        m_state->setText(tr("present, locked"));
    else
        m_state->setText(tr("present, unlocked"));

    if (!pool.fSeedPresent)
        m_phraseCoverage->setText(tr("nothing yet"));
    else if (pool.fTransparentHd)
        m_phraseCoverage->setText(
            tr("shielded notes, and transparent addresses created since they were covered; "
               "%1 older transparent key(s) still need a wallet.dat backup")
                .arg(pool.nTransparentKeysNotCovered));
    else
        m_phraseCoverage->setText(
            tr("shielded notes only; %1 transparent key(s) need a wallet.dat backup")
                .arg(pool.nTransparentKeysNotCovered));

    m_create->setEnabled(!pool.fSeedPresent);
    m_adopt->setEnabled(pool.fSeedPresent && !pool.fTransparentHd);
    m_export->setEnabled(pool.fSeedPresent);
    m_import->setEnabled(!pool.fSeedPresent);
    m_importHex->setEnabled(!pool.fSeedPresent);
    m_importCount->setEnabled(!pool.fSeedPresent);
    m_importRescan->setEnabled(!pool.fSeedPresent);
}

bool Iv5SeedDialog::requireEncrypted(const QString& strAction)
{
    if (m_model == 0)
    {
        m_status->setText(tr("%1: no wallet is loaded.").arg(strAction));
        return false;
    }
    if (m_model->getEncryptionStatus() == WalletModel::Unencrypted)
    {
        m_status->setText(tr("%1: encrypt this wallet first; the IV5 seed only exists in an "
                             "encrypted wallet.").arg(strAction));
        return false;
    }
    return true;
}

void Iv5SeedDialog::createSeed()
{
    if (!requireEncrypted(tr("Create seed")))
        return;
    if (QMessageBox::question(this, tr("Create IV5 seed"),
            tr("Create this wallet's IV5 seed?\n\nBack it up afterwards: the recovery "
               "phrase is the only way to restore the notes it will hold."),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(m_model->requestUnlock());
    if (!ctx.isValid())
    {
        m_status->setText(tr("The wallet stayed locked; no seed was created."));
        return;
    }
    QString strReply, strError;
    if (!Iv5Rpc::Call("z_createiv5seed", QStringList(), strReply, strError))
        m_status->setText(tr("z_createiv5seed refused: %1").arg(strError));
    else
        m_status->setText(tr("Seed created. Write down the recovery phrase now "
                             "(Settings > Show Recovery Phrase)."));
    refreshStatus();
}

void Iv5SeedDialog::adoptPhrase()
{
    if (!requireEncrypted(tr("Cover transparent addresses")))
        return;
    if (QMessageBox::question(this, tr("Cover transparent addresses"),
            tr("New transparent addresses will derive from this wallet's seed, so the "
               "recovery phrase restores them.\n\n"
               "Existing transparent addresses are NOT covered and still need a wallet.dat "
               "backup.\n\n"
               "The wallet records a minimum version: older builds will refuse to open it.\n\n"
               "Continue?"),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(m_model->requestUnlock());
    if (!ctx.isValid())
    {
        m_status->setText(tr("The wallet stayed locked; nothing changed."));
        return;
    }
    QString strReply, strError;
    if (!Iv5Rpc::Call("z_adoptphrase", QStringList(), strReply, strError))
    {
        m_status->setText(tr("z_adoptphrase refused: %1").arg(strError));
    }
    else
    {
        QString strNotCovered;
        Iv5Rpc::ReadField(strReply, "transparent_keys_not_covered", strNotCovered);
        m_status->setText(tr("New transparent addresses now derive from the seed. %1 existing "
                             "transparent key(s) are not covered by the phrase.")
                              .arg(strNotCovered.isEmpty() ? tr("unknown") : strNotCovered));
    }
    refreshStatus();
}

void Iv5SeedDialog::exportSeed()
{
    if (!requireEncrypted(tr("Export")))
        return;
    if (QMessageBox::warning(this, tr("Export IV5 seed"),
            tr("The seed will be shown on screen. Anyone who sees it can spend every note "
               "this wallet holds.\n\nShow it?"),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(m_model->requestUnlock());
    if (!ctx.isValid())
    {
        m_status->setText(tr("The wallet stayed locked; the seed was not read."));
        return;
    }
    QString strReply, strError;
    if (!Iv5Rpc::Call("z_exportiv5seed", QStringList(), strReply, strError))
    {
        m_status->setText(tr("z_exportiv5seed refused: %1").arg(strError));
        return;
    }
    QString strSeed, strCount;
    if (!Iv5Rpc::ReadField(strReply, "seed", strSeed) || strSeed.isEmpty())
    {
        m_status->setText(tr("The node returned no seed."));
        return;
    }
    Iv5Rpc::ReadField(strReply, "address_index_count", strCount);
    m_exported->setPlainText(strSeed);
    m_copy->setEnabled(true);
    m_status->setText(tr("Address index count: %1. Keep it with the seed; an import uses it "
                         "as the starting point of the scan.").arg(strCount));
}

void Iv5SeedDialog::copySeed()
{
    if (m_exported->toPlainText().isEmpty())
        return;
    QApplication::clipboard()->setText(m_exported->toPlainText());
    m_status->setText(tr("Copied. Clear your clipboard when you are done; other "
                         "applications can read it."));
}

void Iv5SeedDialog::importSeed()
{
    if (!requireEncrypted(tr("Import")))
        return;
    const QString strHex = m_importHex->text().trimmed();
    if (!QRegularExpression("^[0-9a-fA-F]{64}$").match(strHex).hasMatch())
    {
        m_status->setText(tr("An IV5 seed is 64 hex characters."));
        return;
    }
    const bool fRescan = m_importRescan->isChecked();
    if (QMessageBox::question(this, tr("Import IV5 seed"),
            fRescan ? tr("Import this seed and rescan the chain? The rescan can take a while "
                         "and the window will not respond until it finishes.")
                    : tr("Import this seed without a rescan? No notes appear until "
                         "z_rescaniv5 runs."),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(m_model->requestUnlock());
    if (!ctx.isValid())
    {
        m_status->setText(tr("The wallet stayed locked; nothing was imported."));
        return;
    }
    QString strReply, strError;
    bool fOk = false;
    {
        BusyCursor busy;
        fOk = Iv5Rpc::Call("z_importiv5seed",
                           QStringList() << strHex << QString::number(m_importCount->value())
                                         << (fRescan ? "true" : "false"),
                           strReply, strError);
    }
    if (!fOk)
    {
        m_status->setText(tr("z_importiv5seed refused: %1").arg(strError));
        return;
    }
    wipe();
    QString strNotes;
    Iv5Rpc::ReadField(strReply, "notes", strNotes);
    m_status->setText(fRescan
        ? tr("Imported and rescanned; the wallet now records %1 note(s).").arg(strNotes)
        : tr("Imported. Run a rescan (z_rescaniv5) before trusting the balance."));
    refreshStatus();
}
