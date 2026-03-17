#ifndef NULLSENDPAGE_H
#define NULLSENDPAGE_H

#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QComboBox>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QToolButton>

class WalletModel;

class NullSendPage : public QWidget
{
    Q_OBJECT

public:
    explicit NullSendPage(QWidget *parent = 0);
    void setModel(WalletModel *model);

private slots:
    void onStartMixClicked();
    void onStopMixClicked();
    void onRefreshStatusClicked();

private:
    WalletModel *model;

    // Mix controls
    QLineEdit *fromAddressEdit;
    QLineEdit *amountEdit;
    QSpinBox *poolSizeSpin;
    QSpinBox *timeoutSpin;
    QPushButton *startMixButton;
    QPushButton *stopMixButton;

    // Status
    QLabel *statusLabel;
    QLabel *mixingStatusLabel;
    QPushButton *refreshStatusButton;

    void setupUI();
};

#endif // NULLSENDPAGE_H
