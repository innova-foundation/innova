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

/** The wallet's IV5 seed: status, create, export/import as hex, and extending the
 *  recovery phrase to transparent addresses. Drives z_getshieldedinfo,
 *  z_createiv5seed, z_exportiv5seed, z_importiv5seed, z_adoptphrase and z_rescaniv5.
 *  Exported hex is held only in the dialog and overwritten on close. */
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
};

#endif // IV5SEEDDIALOG_H
