#ifndef PRIVACYPAGE_H
#define PRIVACYPAGE_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QTextEdit>
#include <QGroupBox>
#include <QListWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QTabWidget>

class WalletModel;

class PrivacyPage : public QWidget
{
    Q_OBJECT

public:
    explicit PrivacyPage(QWidget *parent = 0);
    void setModel(WalletModel *model);

private slots:
    void onShieldClicked();
    void onUnshieldClicked();
    void onSendShieldedClicked();
    void onNewZAddressClicked();
    void onRefreshClicked();
    void onCopyAddressClicked();
    void onNewSPAddressClicked();
    void onCopySPAddressClicked();

private:
    WalletModel *model;

    // Balance display
    QLabel *labelTransparentBalance;
    QLabel *labelShieldedBalance;
    QLabel *labelTotalPrivateBalance;

    // Shield/Unshield tab
    QLineEdit *shieldAmountEdit;
    QComboBox *shieldTargetCombo;
    QPushButton *shieldButton;
    QLineEdit *unshieldAmountEdit;
    QLineEdit *unshieldToEdit;
    QPushButton *unshieldButton;

    // Send Shielded tab
    QLineEdit *sendFromEdit;
    QLineEdit *sendToEdit;
    QLineEdit *sendAmountEdit;
    QLineEdit *sendMemoEdit;
    QPushButton *sendShieldedButton;

    // Address Management tab (z-addresses)
    QListWidget *zAddressList;
    QPushButton *newZAddressButton;
    QPushButton *copyAddressButton;
    QPushButton *refreshButton;

    // Silent Payment Addresses tab
    QListWidget *spAddressList;
    QPushButton *newSPAddressButton;
    QPushButton *copySPAddressButton;

    // Status
    QLabel *statusLabel;

    void setupUI();
    void refreshBalances();
    void refreshAddresses();
    void refreshSPAddresses();
};

#endif // PRIVACYPAGE_H
