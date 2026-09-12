#include "recoveryphrasedialog.h"

#include "guiutil.h"
#include "iv5rpcbridge.h"
#include "walletmodel.h"

#include <QApplication>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QFont>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

RecoveryPhraseDialog::RecoveryPhraseDialog(Mode mode, QWidget* parent)
    : QDialog(parent), m_mode(mode), m_model(0), m_warning(0), m_status(0),
      m_words(0), m_action(0), m_copy(0), m_revealed(false)
{
    setWindowTitle(m_mode == ShowPhrase ? tr("Recovery phrase")
                                        : tr("Restore from a recovery phrase"));
    QVBoxLayout* layout = new QVBoxLayout(this);

    m_warning = new QLabel(this);
    m_warning->setWordWrap(true);
    if (m_mode == ShowPhrase)
        m_warning->setText(tr(
            "These 24 words ARE this wallet's shielded seed. Anyone who has them can spend "
            "every note this wallet holds or will ever hold.\n\n"
            "Write them on paper. Do not photograph them, and do not put them anywhere that "
            "syncs to another machine.\n\n"
            "Transparent addresses created before the phrase was adopted were drawn at "
            "random and are NOT covered by it: those still need a wallet.dat backup."));
    else
        m_warning->setText(tr(
            "Type the 24 words, separated by spaces, in the order they were given.\n\n"
            "This only works on a wallet that holds no seed of its own. A wallet that "
            "already has one refuses the restore, because the notes it has recorded belong "
            "to that seed and would become unspendable under another."));
    layout->addWidget(m_warning);

    m_words = new QPlainTextEdit(this);
    QFont mono("Monospace");
    mono.setStyleHint(QFont::TypeWriter);
    m_words->setFont(mono);
    m_words->setMinimumHeight(90);
    if (m_mode == ShowPhrase)
    {
        m_words->setReadOnly(true);
        m_words->setPlaceholderText(tr("Hidden until you choose to reveal them."));
    }
    else
    {
        m_words->setPlaceholderText(tr("word1 word2 word3 ... word24"));
    }
    layout->addWidget(m_words);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    layout->addWidget(m_status);

    QDialogButtonBox* buttons = new QDialogButtonBox(this);
    m_action = buttons->addButton(
        m_mode == ShowPhrase ? tr("Reveal") : tr("Restore"), QDialogButtonBox::ActionRole);
    if (m_mode == ShowPhrase)
    {
        m_copy = buttons->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
        m_copy->setEnabled(false);
        connect(m_copy, SIGNAL(clicked()), this, SLOT(copyToClipboard()));
    }
    buttons->addButton(QDialogButtonBox::Close);
    connect(buttons, SIGNAL(rejected()), this, SLOT(reject()));
    connect(m_action, SIGNAL(clicked()), this,
            m_mode == ShowPhrase ? SLOT(reveal()) : SLOT(restore()));
    layout->addWidget(buttons);
}

RecoveryPhraseDialog::~RecoveryPhraseDialog()
{
    wipe();
}

void RecoveryPhraseDialog::setModel(WalletModel* model)
{
    m_model = model;
}

// Overwrite before releasing. Qt would otherwise leave the words in whatever heap page the
// document happened to own, for as long as that page goes unreused.
void RecoveryPhraseDialog::wipe()
{
    if (m_words == 0)
        return;
    const int nChars = m_words->toPlainText().size();
    if (nChars > 0)
        m_words->setPlainText(QString(nChars, QChar('x')));
    m_words->clear();
}

bool RecoveryPhraseDialog::requireUnlocked(QString& errorOut)
{
    if (m_model == 0)
    {
        errorOut = tr("no wallet is loaded");
        return false;
    }
    // The seed only exists in an encrypted wallet, so an unencrypted one has no phrase to
    // show and nowhere to put a restored one.
    if (m_model->getEncryptionStatus() == WalletModel::Unencrypted)
    {
        errorOut = tr("encrypt this wallet first: the shielded seed only exists in an "
                      "encrypted wallet");
        return false;
    }
    return true;
}

void RecoveryPhraseDialog::reveal()
{
    QString strError;
    if (!requireUnlocked(strError))
    {
        m_status->setText(tr("Cannot show the phrase: %1").arg(strError));
        return;
    }

    WalletModel::UnlockContext ctx(m_model->requestUnlock());
    if (!ctx.isValid())
    {
        m_status->setText(tr("The wallet stayed locked, so the phrase was not read."));
        return;
    }

    QString strReply;
    if (!Iv5Rpc::Call("z_exportphrase", QStringList(), strReply, strError))
    {
        m_status->setText(tr("Could not read the phrase: %1").arg(strError));
        return;
    }

    QString strPhrase;
    if (!Iv5Rpc::ReadField(strReply, "phrase", strPhrase) || strPhrase.isEmpty())
    {
        m_status->setText(tr("The node returned no phrase."));
        return;
    }

    QString strNotCovered;
    Iv5Rpc::ReadField(strReply, "transparent_keys_not_covered", strNotCovered);

    m_words->setPlainText(strPhrase);
    m_revealed = true;
    if (m_copy != 0)
        m_copy->setEnabled(true);
    m_action->setEnabled(false);
    // The count, not a description: someone deciding whether they still need a file backup
    // should be told the number.
    m_status->setText(strNotCovered.isEmpty() || strNotCovered == "0"
        ? tr("Written down, these words restore every shielded note this wallet can hold.")
        : tr("Note: %1 transparent key(s) in this wallet are NOT covered by these words and "
             "still need a wallet.dat backup.").arg(strNotCovered));
}

void RecoveryPhraseDialog::copyToClipboard()
{
    if (!m_revealed)
        return;
    QApplication::clipboard()->setText(m_words->toPlainText());
    m_status->setText(tr("Copied. Clear your clipboard when you are done -- other "
                         "applications can read it."));
}

void RecoveryPhraseDialog::restore()
{
    QString strError;
    if (!requireUnlocked(strError))
    {
        m_status->setText(tr("Cannot restore: %1").arg(strError));
        return;
    }

    const QString strPhrase = m_words->toPlainText().simplified();
    const int nWords = strPhrase.isEmpty() ? 0 : strPhrase.split(' ').size();
    if (nWords != 24)
    {
        m_status->setText(tr("A recovery phrase is 24 words; this is %1.").arg(nWords));
        return;
    }

    if (QMessageBox::question(this, tr("Restore from a phrase"),
            tr("This rebuilds the wallet's shielded identity from those words and then "
               "rescans the chain, which can take a while.\n\nContinue?"),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
        return;

    WalletModel::UnlockContext ctx(m_model->requestUnlock());
    if (!ctx.isValid())
    {
        m_status->setText(tr("The wallet stayed locked, so nothing was restored."));
        return;
    }

    QString strReply;
    QStringList params;
    params << strPhrase;
    if (!Iv5Rpc::Call("z_importphrase", params, strReply, strError))
    {
        m_status->setText(tr("The restore was refused: %1").arg(strError));
        return;
    }

    // The import records the seed; the notes only appear once the chain has been read
    // against it, so the rescan is part of the same action rather than a second thing to
    // remember.
    QString strScan;
    if (!Iv5Rpc::Call("z_rescaniv5", QStringList(), strScan, strError))
    {
        m_status->setText(tr("The seed was restored, but the rescan failed to start: %1\n"
                             "Run z_rescaniv5 before trusting the balance.").arg(strError));
        return;
    }

    wipe();
    m_action->setEnabled(false);
    m_status->setText(tr("Restored. The chain is being read against this seed; the balance "
                         "is not complete until that finishes."));
}
