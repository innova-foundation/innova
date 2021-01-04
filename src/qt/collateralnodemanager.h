#ifndef COLLATERALSTAKEMANAGER_H
#define COLLATERALSTAKEMANAGER_H

#include "util.h"
#include "sync.h"

#include <QWidget>
#include <QTimer>

namespace Ui {
    class CollateralnodeManager;
}
class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Collateralnode Manager page widget */
class CollateralnodeManager : public QWidget
{
    Q_OBJECT

public:
    explicit CollateralnodeManager(QWidget *parent = 0);
    ~CollateralnodeManager();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);


public slots:
    void updateNodeList();
    void updateAdrenalineNode(QString alias, QString addr, QString privkey);

signals:

private:
    QTimer *timer;
    Ui::CollateralnodeManager *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    CCriticalSection cs_adrenaline;
    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

private slots:
    void on_copyAddressButton_clicked();
    void on_createButton_clicked();
    void on_editButton_clicked();
    void on_getConfigButton_clicked();
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void on_startAllButton_clicked();
    void on_stopAllButton_clicked();
    void on_removeButton_clicked();
    void on_tableWidget_2_itemSelectionChanged();
};

#endif // COLLATERALSTAKEMANAGER_H
