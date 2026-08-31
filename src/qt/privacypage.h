#ifndef PRIVACYPAGE_H
#define PRIVACYPAGE_H

#include <QWidget>

class QLabel;
class QLineEdit;
class QListWidget;
class QRadioButton;
class QPushButton;
class QTabWidget;
class DisclosureMaskWidget;
class FinalityStatusWidget;
class PrivateCollateralWidget;
class WalletModel;

/** The v2008 privacy surface: what a transaction discloses, migration into the
 *  pool, private collateralnode registration, and finality status.
 */
class PrivacyPage : public QWidget
{
    Q_OBJECT

public:
    explicit PrivacyPage(QWidget *parent = 0);
    void setModel(WalletModel *model);

private slots:
    void onSendClicked();
    void onMigrateClicked();
    void onMigrateAllClicked();
    void onMigrateModeChanged();
    void onNewAddressClicked();
    void onCopyAddressClicked();
    void onRefreshClicked();

private:
    void setupUI();
    void refreshBalances();
    QWidget* buildSendTab();
    QWidget* buildMigrateTab();
    QWidget* buildAddressTab();

    WalletModel *model;

    QLabel *availabilityLabel;
    QLabel *labelPoolBalance;
    QLabel *labelPoolUnconfirmed;
    QLabel *labelNoteCount;
    QLabel *labelTransparentBalance;
    QLabel *labelSeedState;
    QLabel *labelScanGap;

    QLineEdit *sendToEdit;
    QLineEdit *sendAmountEdit;
    DisclosureMaskWidget *maskWidget;
    QPushButton *sendButton;

    QLabel *migrateNoticeLabel;
    QRadioButton *migrateSimpleRadio;
    QRadioButton *migrateAdvancedRadio;
    QWidget *migrateAdvancedBox;
    QPushButton *migrateAllButton;
    QLabel *migrateAllSummary;
    QLineEdit *migrateFromEdit;
    QLineEdit *migrateMaxInputsEdit;
    QPushButton *migrateButton;

    QListWidget *addressList;
    QPushButton *newAddressButton;
    QPushButton *copyAddressButton;

    PrivateCollateralWidget *collateralWidget;
    FinalityStatusWidget *finalityWidget;

    QLabel *statusLabel;
};

#endif // PRIVACYPAGE_H
