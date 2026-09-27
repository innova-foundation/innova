#ifndef IV5SEEDDIALOG_H
#define IV5SEEDDIALOG_H

#include <QDialog>

class WalletModel;

QT_BEGIN_NAMESPACE
class QCheckBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
QT_END_NAMESPACE

/** The wallet's IV5 seed and viewing keys: status, create, export/import, and extending
 *  the recovery phrase to transparent addresses. Exported text is held only in the
 *  dialog and overwritten on close. */
class Iv5SeedDialog : public QDialog
{
    Q_OBJECT

public:
    explicit Iv5SeedDialog(QWidget* parent = 0);
    ~Iv5SeedDialog();

    void setModel(WalletModel* model);

private slots:
    void refreshStatus();
    void createSeed();
    void adoptPhrase();
    void exportSeed();
    void copySeed();
    void importSeed();
    void exportViewingKey();
    void copyViewingKey();
    void importViewingKey();
    void refreshViewingKeys();

private:
    bool requireEncrypted(const QString& strAction);
    void wipe();

    WalletModel* m_model;
    QLabel* m_state;
    QLabel* m_phraseCoverage;
    QLabel* m_status;
    QPushButton* m_create;
    QPushButton* m_adopt;
    QPushButton* m_export;
    QPushButton* m_copy;
    QPlainTextEdit* m_exported;
    QLineEdit* m_importHex;
    QSpinBox* m_importCount;
    QCheckBox* m_importRescan;
    QPushButton* m_import;

    QLineEdit* m_vkAddress;
    QPushButton* m_vkExport;
    QPushButton* m_vkCopy;
    QPlainTextEdit* m_vkExported;
    QLineEdit* m_vkImport;
    QCheckBox* m_vkRescan;
    QSpinBox* m_vkStartHeight;
    QPushButton* m_vkImportButton;
    QLabel* m_vkSummary;
};

#endif // IV5SEEDDIALOG_H
