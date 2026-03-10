#ifndef STAKINGPAGE_H
#define STAKINGPAGE_H

#include <QWidget>

class QLabel;
class QComboBox;
class QPushButton;
class QLineEdit;
class QStackedWidget;
class QVBoxLayout;
class QTableWidget;
class WalletModel;
class OptionsModel;

/** Staking page widget - provides staking mode control, cold staking delegation, and status */
class StakingPage : public QWidget
{
    Q_OBJECT

public:
    explicit StakingPage(QWidget *parent = 0);
    ~StakingPage();
    void setModel(WalletModel *model);

public slots:
    void updateStakingStatus();
    void updateBalances();

private slots:
    void onStakingModeChanged(int index);
    void onShieldCoinsClicked();
    void onDelegateClicked();
    void onRevokeDelegation();
    void onRefreshDelegations();

private:
    void setupTransparentPanel();
    void setupNullStakePanel();
    void setupColdStakingPanel();
    void updateModeDescription(int mode);

    WalletModel *model;

    QLabel *labelStakingMode;
    QLabel *labelStakingStatus;
    QLabel *labelStakingBalance;
    QLabel *labelEstimatedTime;
    QComboBox *comboStakingMode;

    QStackedWidget *stackedPanels;

    QWidget *transparentPanel;
    QLabel *labelTransparentUTXOs;
    QLabel *labelTransparentWeight;

    QWidget *nullstakePanel;
    QLabel *labelShieldedBalance;
    QLabel *labelShieldedStatus;
    QPushButton *btnShieldCoins;

    QWidget *coldStakingPanel;
    QLabel *labelColdStakingInfo;
    QLabel *labelColdBalance;
    QLabel *labelColdInstructions;
    QLineEdit *editStakerAddress;
    QLineEdit *editDelegateAmount;
    QPushButton *btnDelegate;
    QPushButton *btnRefreshDelegations;
    QTableWidget *tableDelegations;

    QTimer *updateTimer;
};

#endif // STAKINGPAGE_H
