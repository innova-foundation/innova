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
#include "pod.h"

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

#ifdef USE_IPFS
// No fallback endpoint: a disabled or unset endpoint is an error.
static bool HyperfileEndpointOrBox(std::string& strEndpointOut)
{
    fHyperfileLocal = GetBoolArg("-hyperfilelocal");
    if (!fHyperfileLocal)
    {
        QMessageBox errbox;
        errbox.setText("Hyperfile is off. Add hyperfilelocal=1 and "
                       "hyperfileip=ipfs.innova-foundation.com:5001 to innova.conf and restart. "
                       "There is no public fallback endpoint.");
        errbox.exec();
        return false;
    }

    strEndpointOut = GetArg("-hyperfileip", "");
    if (strEndpointOut.empty())
    {
        QMessageBox errbox;
        errbox.setText("hyperfilelocal=1 but no hyperfileip is set, and there is no default "
                       "IPFS API endpoint. Set hyperfileip=<host:port> in innova.conf.");
        errbox.exec();
        return false;
    }
    return true;
}

// Returns "" and shows the reason on any failure. A partial upload is never
// reported as a CID.
static std::string HyperfileAddOrBox(const std::string& strEndpoint, const QString& qsFile)
{
    try
    {
        ipfs::Client client(strEndpoint);

        std::string filename = qsFile.toStdString();
        boost::filesystem::path p(filename);
        std::string basename = p.filename().string();

        printf("Hyperfile Upload File Start: %s\n", basename.c_str());

        ipfs::Json add_result;
        client.FilesAdd(
            {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, filename.c_str()}},
            &add_result);

        if (add_result.empty() || add_result[0]["hash"].is_null())
        {
            QMessageBox errbox;
            errbox.setText("IPFS upload returned no CID. Nothing was stored.");
            errbox.exec();
            return "";
        }

        const std::string strCid = add_result[0]["hash"];
        if (strCid.empty())
        {
            QMessageBox errbox;
            errbox.setText("IPFS upload returned an empty CID. Nothing was stored.");
            errbox.exec();
            return "";
        }

        printf("Hyperfile Successfully Added IPFS File(s): %s\n", add_result.dump().c_str());
        return strCid;
    }
    catch (const std::exception& e)
    {
        // A 302 here usually means a large file or an endpoint that is not an
        // IPFS API. Either way nothing was stored.
        std::cerr << e.what() << std::endl;
        QMessageBox errbox;
        errbox.setText(QString("IPFS upload failed: ") + QString::fromStdString(e.what()));
        errbox.exec();
        return "";
    }
}
#endif

void Hyperfile::on_createPodButton_clicked()
{
#ifdef USE_IPFS
    if (fileName == "")
    {
        noImageSelected();
        return;
    }

    if (QMessageBox::Yes != QMessageBox(QMessageBox::Information, "Innova Hyperfile POD",
            "This uploads the file to IPFS, where it becomes public and effectively permanent, "
            "and then anchors its SHA-256 digest on chain for a normal transaction fee.\n\n"
            "Use Proof of Data instead if you want the timestamp without publishing the file.\n\n"
            "Continue?",
            QMessageBox::Yes | QMessageBox::No).exec())
        return;

    if (!pwalletMain)
    {
        QMessageBox errbox;
        errbox.setText("Error, Wallet is not available!");
        errbox.exec();
        return;
    }

    std::string strEndpoint;
    if (!HyperfileEndpointOrBox(strEndpoint))
        return;

    // Hash before uploading: a stamp is worthless if the bytes that were hashed
    // are not the bytes that were stored.
    std::vector<unsigned char> vDigest;
    std::string strError;
    if (!PodHashFile(fileName.toStdString(), vDigest, strError))
    {
        QMessageBox errbox;
        errbox.setText(QString::fromStdString(strError));
        errbox.exec();
        return;
    }

    std::string strCid = HyperfileAddOrBox(strEndpoint, fileName);
    if (strCid.empty())
        return;

    ui->lineEdit->setText(QString::fromStdString(strCid));
    ui->lineEdit_2->setText(QString::fromStdString(HexStr(vDigest.begin(), vDigest.end())));
    ui->checkButton->setHidden(false);
    ui->lineEdit->setHidden(false);
    ui->hashLabel->setHidden(false);
    ui->lineEdit_2->setHidden(false);
    ui->hashLabel_2->setHidden(false);
    ui->checkButtonCloudflare->setHidden(false);

    std::vector<unsigned char> vLocator;
    PodCidToLocator(strCid, vLocator);

    CWalletTx wtx;
    wtx.mapValue["comment"] = strCid;
    wtx.mapValue["to"] = "Hyperfile POD";
    wtx.mapValue["podsha256"] = HexStr(vDigest.begin(), vDigest.end());

    strError = PodCreateStamp(pwalletMain, POD_TYPE_HYPERFILE, vDigest, vLocator, wtx);
    if (strError != "")
    {
        // The upload cannot be undone, so the CID above stands; the stamp does not.
        QMessageBox errbox;
        errbox.setText(QString::fromStdString(
            "The file was uploaded to IPFS, but it was NOT timestamped: " + strError));
        errbox.exec();
        return;
    }

    ui->lineEdit_3->setText(QString::fromStdString(wtx.GetHash().GetHex()));
    ui->lineEdit_3->setHidden(false);
    ui->hashLabel_3->setHidden(false);
    ui->checkHashButton->setHidden(false);

    QMessageBox successbox;
    successbox.setText("Hyperfile POD timestamp successful. Verify it later with "
                       "podverify <file> <txid> in the debug console.");
    successbox.exec();
#endif
}

void Hyperfile::on_createPushButton_clicked()
{
#ifdef USE_IPFS
    if (fileName == "")
    {
        noImageSelected();
        return;
    }

    if (QMessageBox::Yes != QMessageBox(QMessageBox::Information, "Innova Hyperfile",
            "IPFS content is public and, once pinned or cached by any peer, effectively "
            "permanent - it cannot be recalled. The configured endpoint's operator sees the "
            "file contents and this node's IP address.\n\nUpload?",
            QMessageBox::Yes | QMessageBox::No).exec())
        return;

    std::string strEndpoint;
    if (!HyperfileEndpointOrBox(strEndpoint))
        return;

    std::string strCid = HyperfileAddOrBox(strEndpoint, fileName);
    if (strCid.empty())
        return;

    ui->lineEdit->setText(QString::fromStdString(strCid));
    ui->checkButton->setHidden(false);
    ui->lineEdit->setHidden(false);
    ui->hashLabel->setHidden(false);
    ui->checkButtonCloudflare->setHidden(false);
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
    std::string linkurl = "https://ipfs.io/ipfs/";
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
   std::string linkurl2 = "https://dweb.link/ipfs/";
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
   std::string linkurl3 = "https://chainz.cryptoid.info/inn/tx.dws?";
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
