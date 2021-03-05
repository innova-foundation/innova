#include "hyperfile.h"
#include "ui_hyperfile.h"

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

#include <boost/filesystem.hpp>

#ifdef USE_IPFS
#include <ipfs/client.h>
#include <ipfs/http/transport.h>
#endif

#include <QScrollArea>
#include <QUrl>
#include <QFileDialog>
#include <QDesktopServices>

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

Hyperfile::Hyperfile(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Hyperfile)
{
    ui->setupUi(this);
    fileName = "";
    fileCont = "";
    ui->checkButton->setHidden(true);
    //ui->checkLabel->setHidden(true);
    ui->lineEdit->setHidden(true);
    ui->hashLabel->setHidden(true);

    ui->lineEdit_2->setHidden(true);
    ui->hashLabel_2->setHidden(true);
    ui->lineEdit_3->setHidden(true);
    ui->hashLabel_3->setHidden(true);
    ui->checkHashButton->setHidden(true);
    ui->checkButtonCloudflare->setHidden(true);
}

Hyperfile::~Hyperfile()
{
    delete ui;
}

void Hyperfile::on_filePushButton_clicked()
{
  //Upload a file
	fileName = QFileDialog::getOpenFileName(this,
    tr("Upload File to IPFS"), "./", tr("All Files (*.*)"));

    //fileCont = QFileDialog::getOpenFileContent("All Files (*.*)",  fileContentReady);

  ui->labelFile->setText(fileName);
}

void Hyperfile::on_createPodButton_clicked()
{

#ifdef USE_IPFS
fHyperfileLocal = GetBoolArg("-hyperfilelocal");

if (QMessageBox::Yes == QMessageBox(QMessageBox::Information, "Innova Hyperfile POD", "Warning: This costs 0.001 INN to timestamp your IPFS file hash on the Innova blockchain.", QMessageBox::Yes|QMessageBox::No).exec())
{
    //qDebug() << "Yes was clicked";

    //Ensure IPFS connected
    if (fHyperfileLocal) {
      try {
        std::stringstream contents;
        ipfs::Json add_result;

        std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

        ipfs::Client client(ipfsip);

        if(fileName == "")
        {
          noImageSelected();
          return;
        }

        //read whole file
        std::ifstream ipfsFile;
        std::string filename = fileName.toStdString().c_str();

        boost::filesystem::path p(filename);
        std::string basename = p.filename().string();

        ipfsFile.open(fileName.toStdString().c_str(), std::ios::binary);
        std::vector<char> ipfsContents((std::istreambuf_iterator<char>(ipfsFile)), std::istreambuf_iterator<char>());

        std::string ipfsC(ipfsContents.begin(), ipfsContents.end());

        std::string fileContents = ipfsC.c_str();

        printf("Hyperfile Upload File Start: %s\n", basename.c_str());
        //printf("Hyperfile File Contents: %s\n", ipfsC.c_str());

        client.FilesAdd(
        {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, fileName.toStdString().c_str()}},
        &add_result);

        const std::string& hash = add_result[0]["hash"];

        ui->lineEdit->setText(QString::fromStdString(hash));



        std::string r = add_result.dump();
        printf("Hyperfile POD Successfully Added IPFS File(s): %s\n", r.c_str());

        //Hyperfile POD
        if (hash != "") {
          //Hash the file for Innova Hyperfile POD
          //uint256 imagehash = SerializeHash(ipfsContents);
          CKeyID keyid(Hash160(hash.begin(), hash.end()));
          CBitcoinAddress baddr = CBitcoinAddress(keyid);
          std::string addr = baddr.ToString();

          ui->lineEdit_2->setText(QString::fromStdString(addr));

          CAmount nAmount = 0.001 * COIN; // 0.001 INN Fee

          // Wallet comments
          CWalletTx wtx;
          wtx.mapValue["comment"] = hash;
          std::string sNarr = "Hyperfile POD";
          wtx.mapValue["to"]      = "Hyperfile POD";

          if (pwalletMain->IsLocked())
          {
            QMessageBox unlockbox;
            unlockbox.setText("Error, Your wallet is locked! Please unlock your wallet!");
            unlockbox.exec();
            //ui->txLineEdit->setText("ERROR: Your wallet is locked! Cannot send Hyperfile POD. Unlock your wallet!");
          } else if (pwalletMain->GetBalance() < 0.001) {
            QMessageBox error2box;
            error2box.setText("Error, You need at least 0.001 INN to send Hyperfile POD!");
            error2box.exec();
            //ui->txLineEdit->setText("ERROR: You need at least a 0.001 INN balance to send Hyperfile POD.");
          } else {
            //std::string sNarr;
            std::string strError = pwalletMain->SendMoneyToDestination(baddr.Get(), nAmount, sNarr, wtx);

            if(strError != "")
            {
                QMessageBox infobox;
                infobox.setText(QString::fromStdString(strError));
                infobox.exec();
            }
            QMessageBox successbox;
            successbox.setText("Hyperfile POD Timestamp Successful!");
            successbox.exec();
            ui->lineEdit_3->setText(QString::fromStdString(wtx.GetHash().GetHex()));
          }
        }

        if (hash != "") {
          ui->checkButton->setHidden(false);
         //ui->checkLabel->setHidden(false);
          ui->lineEdit->setHidden(false);
          ui->hashLabel->setHidden(false);
          ui->lineEdit_3->setHidden(false);
          ui->hashLabel_3->setHidden(false);
          ui->lineEdit_2->setHidden(false);
          ui->hashLabel_2->setHidden(false);
          ui->checkHashButton->setHidden(false);
          ui->checkButtonCloudflare->setHidden(false);
        }

      } catch (const std::exception& e) {
          std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
          QMessageBox errbox;
          errbox.setText(QString::fromStdString(e.what()));
          errbox.exec();
      }

    } else {
      try {
        std::stringstream contents;
        ipfs::Json add_result;
        ipfs::Client client("https://ipfs.infura.io:5001");

        if(fileName == "")
        {
          noImageSelected();
          return;
        }

        //read whole file
        std::ifstream ipfsFile;
        std::string filename = fileName.toStdString().c_str();

        boost::filesystem::path p(filename);
        std::string basename = p.filename().string();

        ipfsFile.open(fileName.toStdString().c_str(), std::ios::binary);
        std::vector<char> ipfsContents((std::istreambuf_iterator<char>(ipfsFile)), std::istreambuf_iterator<char>());

        std::string ipfsC(ipfsContents.begin(), ipfsContents.end());

        std::string fileContents = ipfsC.c_str();

        printf("Hyperfile Upload File Start: %s\n", basename.c_str());
        //printf("Hyperfile File Contents: %s\n", ipfsC.c_str());

        client.FilesAdd(
        {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, fileName.toStdString().c_str()}},
        &add_result);

        const std::string& hash = add_result[0]["hash"];

        ui->lineEdit->setText(QString::fromStdString(hash));

        std::string r = add_result.dump();
        printf("Hyperfile POD Successfully Added IPFS File(s): %s\n", r.c_str());

        //Hyperfile POD
        if (hash != "") {
          //Hash the file for Innova Hyperfile POD
          //uint256 imagehash = SerializeHash(ipfsContents);
          CKeyID keyid(Hash160(hash.begin(), hash.end()));
          CBitcoinAddress baddr = CBitcoinAddress(keyid);
          std::string addr = baddr.ToString();

          ui->lineEdit_2->setText(QString::fromStdString(addr));

          CAmount nAmount = 0.001 * COIN; // 0.001 INN Fee

          // Wallet comments
          CWalletTx wtx;
          wtx.mapValue["comment"] = hash;
          std::string sNarr = "Hyperfile POD";
          wtx.mapValue["to"]      = "Hyperfile POD";

          if (pwalletMain->IsLocked())
          {
            QMessageBox unlockbox;
            unlockbox.setText("Error, Your wallet is locked! Please unlock your wallet!");
            unlockbox.exec();
            //ui->txLineEdit->setText("ERROR: Your wallet is locked! Cannot send Hyperfile POD. Unlock your wallet!");
          } else if (pwalletMain->GetBalance() < 0.001) {
            QMessageBox error2box;
            error2box.setText("Error, You need at least 0.001 INN to send Hyperfile POD!");
            error2box.exec();
            //ui->txLineEdit->setText("ERROR: You need at least a 0.001 INN balance to send Hyperfile POD.");
          } else {
            //std::string sNarr;
            std::string strError = pwalletMain->SendMoneyToDestination(baddr.Get(), nAmount, sNarr, wtx);

            if(strError != "")
            {
                QMessageBox infobox;
                infobox.setText(QString::fromStdString(strError));
                infobox.exec();
            }
            QMessageBox successbox;
            successbox.setText("Hyperfile POD Timestamp Successful!");
            successbox.exec();
            ui->lineEdit_3->setText(QString::fromStdString(wtx.GetHash().GetHex()));
          }
        }

        if (hash != "") {
          ui->checkButton->setHidden(false);
          //ui->checkLabel->setHidden(false);
          ui->lineEdit->setHidden(false);
          ui->hashLabel->setHidden(false);
          ui->lineEdit_2->setHidden(false);
          ui->lineEdit_3->setHidden(false);
          ui->hashLabel_3->setHidden(false);
          ui->hashLabel_2->setHidden(false);
          ui->checkHashButton->setHidden(false);
          ui->checkButtonCloudflare->setHidden(false);
        }

      } catch (const std::exception& e) {
          std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
          QMessageBox errbox;
          errbox.setText(QString::fromStdString(e.what()));
          errbox.exec();
      }

    }

  } else {
    //qDebug() << "Cancelled";
  }
#endif

}

void Hyperfile::on_createPushButton_clicked()
{

#ifdef USE_IPFS
fHyperfileLocal = GetBoolArg("-hyperfilelocal");

//Ensure IPFS connected
if (fHyperfileLocal) {
try {
std::stringstream contents;
ipfs::Json add_result;

std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

ipfs::Client client(ipfsip);

if(fileName == "")
{
  noImageSelected();
  return;
}

//read whole file
std::ifstream ipfsFile;
std::string filename = fileName.toStdString().c_str();

boost::filesystem::path p(filename);
std::string basename = p.filename().string();

ipfsFile.open(fileName.toStdString().c_str(), std::ios::binary);
std::vector<char> ipfsContents((std::istreambuf_iterator<char>(ipfsFile)), std::istreambuf_iterator<char>());

std::string ipfsC(ipfsContents.begin(), ipfsContents.end());

std::string fileContents = ipfsC.c_str();

printf("Hyperfile Upload File Start: %s\n", basename.c_str());
//printf("Hyperfile File Contents: %s\n", ipfsC.c_str());

client.FilesAdd(
{{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, fileName.toStdString().c_str()}},
&add_result);

const std::string& hash = add_result[0]["hash"];

ui->lineEdit->setText(QString::fromStdString(hash));

std::string r = add_result.dump();
printf("Hyperfile Successfully Added IPFS File(s): %s\n", r.c_str());

if (hash != "") {
  ui->checkButton->setHidden(false);
  //ui->checkLabel->setHidden(false);
  ui->lineEdit->setHidden(false);
  ui->hashLabel->setHidden(false);
  ui->checkButtonCloudflare->setHidden(false);
}

} catch (const std::exception& e) {
  std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
  QMessageBox errbox;
  errbox.setText(QString::fromStdString(e.what()));
  errbox.exec();
}

} else {
try {
std::stringstream contents;
ipfs::Json add_result;
ipfs::Client client("https://ipfs.infura.io:5001");

if(fileName == "")
{
  noImageSelected();
  return;
}

//read whole file
std::ifstream ipfsFile;
std::string filename = fileName.toStdString().c_str();

boost::filesystem::path p(filename);
std::string basename = p.filename().string();

    ipfsFile.open(fileName.toStdString().c_str(), std::ios::binary);
    std::vector<char> ipfsContents((std::istreambuf_iterator<char>(ipfsFile)), std::istreambuf_iterator<char>());

    std::string ipfsC(ipfsContents.begin(), ipfsContents.end());

    std::string fileContents = ipfsC.c_str();

    printf("Hyperfile Upload File Start: %s\n", basename.c_str());
    //printf("Hyperfile File Contents: %s\n", ipfsC.c_str());

    client.FilesAdd(
    {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, fileName.toStdString().c_str()}},
    &add_result);

    const std::string& hash = add_result[0]["hash"];

    ui->lineEdit->setText(QString::fromStdString(hash));

    std::string r = add_result.dump();
    printf("Hyperfile Successfully Added IPFS File(s): %s\n", r.c_str());

    if (hash != "") {
      ui->checkButton->setHidden(false);
      //ui->checkLabel->setHidden(false);
      ui->lineEdit->setHidden(false);
      ui->hashLabel->setHidden(false);
      ui->checkButtonCloudflare->setHidden(false);
    }

  } catch (const std::exception& e) {
      std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
      QMessageBox errbox;
      errbox.setText(QString::fromStdString(e.what()));
      errbox.exec();
  }

}
#endif

}

void Hyperfile::on_checkButton_clicked()
{
    if(fileName == "")
    {
      noImageSelected();
      return;
    }

    //go to public IPFS gateway
    std::string linkurl = "https://ipfs.infura.io/ipfs/";
    //open url
    QString link = QString::fromStdString(linkurl + ui->lineEdit->text().toStdString());
    QDesktopServices::openUrl(QUrl(link));

}

void Hyperfile::on_checkButtonCloudflare_clicked()
{
  if(fileName == "")
      {
        noImageSelected();
        return;
      }
      //go to public IPFS gateway
   std::string linkurl2 = "https://cloudflare-ipfs.com/ipfs/";
   //open url
   QString link2 = QString::fromStdString(linkurl2 + ui->lineEdit->text().toStdString());
   QDesktopServices::openUrl(QUrl(link2));
}

void Hyperfile::on_checkHashButton_clicked()
{
   if(fileName == "")
   {
     noImageSelected();
     return;
   }

   //go to public IPFS gateway
   std::string linkurl3 = "https://chainz.cryptoid.info/d/tx.dws?";
   //open url
   QString link3 = QString::fromStdString(linkurl3 + ui->lineEdit_3->text().toStdString());
   QDesktopServices::openUrl(QUrl(link3));
}

void Hyperfile::noImageSelected()
{
  //err message
  QMessageBox errorbox;
  errorbox.setText("No file selected or uploaded!");
  errorbox.exec();
}
