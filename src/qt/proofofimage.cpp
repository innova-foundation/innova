#include "proofofimage.h"
#include "ui_proofofimage.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "guiconstants.h"

#include "hash.h"
#include "base58.h"
#include "key.h"
#include "util.h"
#include "init.h"
#include "wallet.h"
#include "walletdb.h"
#include "pod.h"

#include <QApplication>
#include <QClipboard>
#include <QScrollArea>
#include <QUrl>
#include <QFileDialog>
#include <QDesktopServices>

#include <fstream>

ProofOfImage::ProofOfImage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ProofOfImage)
{
    ui->setupUi(this);
    fileName = "";

}

ProofOfImage::~ProofOfImage()
{
    delete ui;
}

void ProofOfImage::on_filePushButton_clicked()
{
	fileName = QFileDialog::getOpenFileName(this,
    tr("Open File"), "./", tr("All Files (*.*)"));

    ui->labelFile->setText(fileName);

}

void ProofOfImage::on_createPushButton_clicked()
{
    if(fileName == "")
    {
        noImageSelected();
        return;
    }

    if (!pwalletMain)
    {
        QMessageBox errbox;
        errbox.setText("Error, Wallet is not available!");
        errbox.exec();
        ui->txLineEdit->setText("ERROR: Wallet is not available!");
        return;
    }

    ui->lineEdit->clear();
    ui->saltLineEdit->clear();
    ui->txLineEdit->clear();

    std::vector<unsigned char> vFileDigest;
    std::string strError;
    if (!PodHashFile(fileName.toStdString(), vFileDigest, strError))
    {
        QMessageBox errbox;
        errbox.setText(QString::fromStdString(strError));
        errbox.exec();
        ui->txLineEdit->setText(QString::fromStdString("ERROR: " + strError));
        return;
    }

    const bool fBlinded = ui->blindCheckBox->isChecked();
    int nType = fBlinded ? POD_TYPE_BLINDED : POD_TYPE_PLAIN;
    std::vector<unsigned char> vSalt;
    std::vector<unsigned char> vStampDigest = vFileDigest;
    if (fBlinded)
    {
        vSalt = PodNewSalt();
        vStampDigest = PodBlindDigest(vFileDigest, vSalt);
    }

    CWalletTx wtx;
    wtx.mapValue["comment"] = ui->edit->text().toStdString();
    wtx.mapValue["to"] = "Proof of Data";
    wtx.mapValue["podsha256"] = HexStr(vFileDigest.begin(), vFileDigest.end());
    if (fBlinded)
        wtx.mapValue["podsalt"] = HexStr(vSalt.begin(), vSalt.end());

    strError = PodCreateStamp(pwalletMain, nType, vStampDigest,
                              std::vector<unsigned char>(), wtx);
    if (strError != "")
    {
        QMessageBox errbox;
        errbox.setText(QString::fromStdString(strError));
        errbox.exec();
        ui->txLineEdit->setText(QString::fromStdString("ERROR: " + strError));
        return;
    }

    ui->lineEdit->setText(QString::fromStdString(HexStr(vStampDigest.begin(), vStampDigest.end())));
    if (fBlinded)
        ui->saltLineEdit->setText(QString::fromStdString(HexStr(vSalt.begin(), vSalt.end())));
    ui->txLineEdit->setText(QString::fromStdString(wtx.GetHash().GetHex()));

    QMessageBox successbox;
    successbox.setText(fBlinded
        ? "Proof of Data timestamped. Save the salt: without it this stamp proves nothing about the file."
        : "Proof of Data timestamped. The published digest is the file's plain SHA-256.");
    successbox.exec();
}

void ProofOfImage::on_checkButton_clicked()
{
    if (ui->lineEdit->text().isEmpty())
    {
        QMessageBox errorbox;
        errorbox.setText("No digest to copy. Create a timestamp first.");
        errorbox.exec();
        return;
    }
    QApplication::clipboard()->setText(ui->lineEdit->text());
}

void ProofOfImage::on_checkTxButton_clicked()
{
  //go to block explorer
    std::string bexp = "https://chainz.cryptoid.info/inn/tx.dws?";
    //open url
    QString link = QString::fromStdString(bexp + ui->txLineEdit->text().toStdString());
    QDesktopServices::openUrl(QUrl(link));
}

void ProofOfImage::noImageSelected()
{
  //err message
  QMessageBox errorbox;
  errorbox.setText("No file selected!");
  errorbox.exec();
}
