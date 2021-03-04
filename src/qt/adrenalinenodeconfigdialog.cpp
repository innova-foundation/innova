#include "adrenalinenodeconfigdialog.h"
#include "ui_adrenalinenodeconfigdialog.h"

#include <QModelIndex>

AdrenalineNodeConfigDialog::AdrenalineNodeConfigDialog(QWidget *parent, QString nodeAddress, QString privkey) :
    QDialog(parent),
    ui(new Ui::AdrenalineNodeConfigDialog)
{
    ui->setupUi(this);
    QString desc = "rpcallowip=127.0.0.1<br>rpcuser=REPLACEME<br>rpcpassword=REPLACEME<br>server=1<br>listen=1<br>port=REPLACEMEWITHYOURPORT<br>collateralnode=1<br>collateralnodeaddr=" + nodeAddress + "<br>collateralnodeprivkey=" + privkey + "<br>";
    ui->detailText->setHtml(desc);
}

AdrenalineNodeConfigDialog::~AdrenalineNodeConfigDialog()
{
    delete ui;
}
