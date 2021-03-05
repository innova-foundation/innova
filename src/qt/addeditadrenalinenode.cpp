#include "addeditadrenalinenode.h"
#include "ui_addeditadrenalinenode.h"
#include "collateralnodeconfig.h"
#include "collateralnodemanager.h"
#include "ui_collateralnodemanager.h"

#include "walletdb.h"
#include "wallet.h"
#include "ui_interface.h"
#include "util.h"
#include "key.h"
#include "script.h"
#include "init.h"
#include "base58.h"
#include <QMessageBox>
#include <QClipboard>

AddEditAdrenalineNode::AddEditAdrenalineNode(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AddEditAdrenalineNode)
{
    ui->setupUi(this);

}

AddEditAdrenalineNode::~AddEditAdrenalineNode()
{
    delete ui;
}

void AddEditAdrenalineNode::on_okButton_clicked()
{
    if(ui->aliasLineEdit->text() == "")
    {
        QMessageBox msg;
        msg.setText("Please enter an alias.");
        msg.exec();
        return;
    }
    else if(ui->addressLineEdit->text() == "")
    {
        QMessageBox msg;
        msg.setText("Please enter an ip address and port. (123.45.68.69:14539)");
        msg.exec();
        return;
    }
    else if(ui->privkeyLineEdit->text() == "")
    {
        QMessageBox msg;
        msg.setText("Please enter a collateralnode private key. This can be found using the \"collateralnode genkey\" command in the console.");
        msg.exec();
        return;
    }
    else if(ui->txhashLineEdit->text() == "")
    {
        QMessageBox msg;
        msg.setText("Please enter the transaction hash for the transaction that has 25000 INN");
        msg.exec();
        return;
    }
    else if(ui->outputindexLineEdit->text() == "")
    {
        QMessageBox msg;
        msg.setText("Please enter a transaction output index. This can be found using the \"collateralnode outputs\" command in the console.");
        msg.exec();
        return;
    }
    else
    {

        CAdrenalineNodeConfig c;

        c.sAlias = ui->aliasLineEdit->text().toStdString();
        c.sAddress = ui->addressLineEdit->text().toStdString();
        c.sCollateralnodePrivKey = ui->privkeyLineEdit->text().toStdString();
        c.sTxHash = ui->txhashLineEdit->text().toStdString();
        c.sOutputIndex = ui->outputindexLineEdit->text().toStdString();

        CWalletDB walletdb(pwalletMain->strWalletFile);

        boost::filesystem::path pathConfigFile = GetCollateralnodeConfigFile();
        boost::filesystem::ofstream stream(pathConfigFile.string(), std::ios::out | std::ios::app);
        if (stream.is_open())
        {
            stream << c.sAlias << " " << c.sAddress << " " << c.sCollateralnodePrivKey << " " << c.sTxHash << " " << c.sOutputIndex << std::endl;
            stream.close();
        }
        collateralnodeConfig.add(c.sAlias, c.sAddress, c.sCollateralnodePrivKey, c.sTxHash, c.sOutputIndex);

        pwalletMain->mapMyAdrenalineNodes.insert(make_pair(c.sAddress, c));
        walletdb.WriteAdrenalineNodeConfig(c.sAddress, c);
        uiInterface.NotifyAdrenalineNodeChanged(c);

        accept();
    }
}

void AddEditAdrenalineNode::on_cancelButton_clicked()
{
    reject();
}

void AddEditAdrenalineNode::on_AddEditAddressPasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->addressLineEdit->setText(QApplication::clipboard()->text());
}

void AddEditAdrenalineNode::on_AddEditPrivkeyPasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->privkeyLineEdit->setText(QApplication::clipboard()->text());
}

void AddEditAdrenalineNode::on_AddEditTxhashPasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->txhashLineEdit->setText(QApplication::clipboard()->text());
}
