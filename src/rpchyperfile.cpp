// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2017-2020 The Denarius developers
// Copyright (c) 2019-2020 The Innova Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Original OG - credits to carsenk for original IPFS code & Denarius HyperFile Commands

#include "main.h"
#include "innovarpc.h"
#include "init.h"
#include "txdb.h"
#include <errno.h>

#include <boost/filesystem.hpp>
#include <fstream>

#ifdef USE_IPFS
#include <ipfs/client.h>
#include <ipfs/http/transport.h>
#include <ipfs/test/utils.h>
#endif

using namespace json_spirit;
using namespace std;

#ifdef USE_IPFS
Value hyperfilegetstat(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "hyperfilegetstat\n"
            "\nArguments:\n"
            "1. \"ipfshash\"          (string, required) The IPFS Hash/Block\n"
            "Returns the IPFS block stats of the inputted IPFS CID/Hash/Block");

    Object obj;
    std::string userHash = params[0].get_str();
    ipfs::Json stat_result;

    fHyperFileLocal = GetBoolArg("-hyperfilelocal");

    if (fHyperFileLocal) {
        std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

        ipfs::Client client(ipfsip);

        /* An example output:
        Stat: {"Key":"QmQpWo5TL9nivqvL18Bq8bS34eewAA6jcgdVsUu4tGeVHo","Size":15}
        */
        client.BlockStat(userHash, &stat_result);
        obj.push_back(Pair("key",        stat_result["Key"].dump().c_str()));
        obj.push_back(Pair("size",       stat_result["Size"].dump().c_str()));

        return obj;
    } else {
        ipfs::Client client("https://ipfs.infura.io:5001");

        /* An example output:
        Stat: {"Key":"QmQpWo5TL9nivqvL18Bq8bS34eewAA6jcgdVsUu4tGeVHo","Size":15}
        */
        client.BlockStat(userHash, &stat_result);
        obj.push_back(Pair("key",        stat_result["Key"].dump().c_str()));
        obj.push_back(Pair("size",       stat_result["Size"].dump().c_str()));

        return obj;
    }
}
Value hyperfilegetblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "hyperfilegetblock\n"
            "\nArguments:\n"
            "1. \"ipfshash\"          (string, required) The IPFS Hash/Block\n"
            "Returns the IPFS hash/block data hex of the inputted IPFS CID/Hash/Block");

    Object obj;
    std::string userHash = params[0].get_str();
    std::stringstream block_contents;

    fHyperFileLocal = GetBoolArg("-hyperfilelocal");

    if (fHyperFileLocal) {
        std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

        ipfs::Client client(ipfsip);

        client.BlockGet(userHash, &block_contents);
        obj.push_back(Pair("blockhex", ipfs::test::string_to_hex(block_contents.str()).c_str()));

        return obj;
    } else {
        ipfs::Client client("https://ipfs.infura.io:5001");

        /* E.g. userHash is "QmQpWo5TL9nivqvL18Bq8bS34eewAA6jcgdVsUu4tGeVHo". */
        client.BlockGet(userHash, &block_contents);
        obj.push_back(Pair("blockhex", ipfs::test::string_to_hex(block_contents.str()).c_str()));

        return obj;
        /* An example output:
        Block (hex): 426c6f636b2070757420746573742e
        */
    }
}

Value hyperfileversion(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "hyperfileversion\n"
            "Returns the version of the connected IPFS node within the Innova HyperFile");

    ipfs::Json version;
    ipfs::Json id;
    bool connected = false;
    Object obj, peerinfo;

    fHyperFileLocal = GetBoolArg("-hyperfilelocal");

    if (fHyperFileLocal) {
        std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

        ipfs::Client client(ipfsip);

        client.Version(&version);
        const std::string& vv = version["Version"].dump();
        printf("HyperFile: IPFS Peer Version: %s\n", vv.c_str());
        std::string versionj = version["Version"].dump();

        if (version["Version"].dump() != "") {
            connected = true;
        }

        client.Id(&id);

        obj.push_back(Pair("connected",          connected));
        obj.push_back(Pair("hyperfilelocal",       "true"));
        obj.push_back(Pair("ipfspeer",           ipfsip));
        obj.push_back(Pair("ipfsversion",        version["Version"].dump().c_str()));

        peerinfo.push_back(Pair("peerid",             id["ID"].dump().c_str()));
        peerinfo.push_back(Pair("addresses",          id["Addresses"].dump().c_str()));
        peerinfo.push_back(Pair("publickey",          id["PublicKey"].dump().c_str()));
        obj.push_back(Pair("peerinfo",                peerinfo));

        return obj;
    } else {
        ipfs::Client client("https://ipfs.infura.io:5001");

        client.Version(&version);
        const std::string& vv = version["Version"].dump();
        printf("HyperFile: IPFS Peer Version: %s\n", vv.c_str());
        std::string versionj = version["Version"].dump();

        if (version["Version"].dump() != "") {
            connected = true;
        }

        obj.push_back(Pair("connected",          connected));
        obj.push_back(Pair("hyperfilelocal",       "false"));
        obj.push_back(Pair("ipfspeer",           "https://ipfs.infura.io:5001"));
        obj.push_back(Pair("ipfsversion",        version["Version"].dump().c_str()));
        obj.push_back(Pair("peerinfo",           "Peer ID Info only supported with hyperfilelocal=1"));

        return obj;
    }
}

Value hyperfilepod(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
    throw runtime_error(
        "hyperfilepod\n"
        "\nArguments:\n"
        "1. \"filelocation\"          (string, required) The file location of the file to upload (e.g. /home/name/file.jpg)\n"
        "Returns the uploaded IPFS file CID/Hash of the uploaded file and public gateway link if successful, along with the HyperFile POD TX ID Timestamp.");

    Object obj;
    std::string userFile = params[0].get_str();


    //Ensure IPFS connected
    fHyperFileLocal = GetBoolArg("-hyperfilelocal");

    if (fHyperFileLocal) {
        try {
            ipfs::Json add_result;

            std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

            ipfs::Client client(ipfsip);

            if(userFile == "")
            {
              return 0;
            }

            std::string filename = userFile.c_str();

            boost::filesystem::path p(filename);
            std::string basename = p.filename().string();

            printf("HyperFile Upload File Start: %s\n", basename.c_str());
            //printf("HyperFile File Contents: %s\n", ipfsC.c_str());

            client.FilesAdd(
            {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, userFile.c_str()}},
            &add_result);

            const std::string& hash = add_result[0]["hash"];
            int size = add_result[0]["size"];

            std::string r = add_result.dump();
            printf("HyperFile POD Successfully Added IPFS File(s): %s\n", r.c_str());

            //HyperFile POD
            if (hash != "") {
                //Hash the file for Innova HyperFile POD
                //uint256 imagehash = SerializeHash(ipfsContents);
                CKeyID keyid(Hash160(hash.begin(), hash.end()));
                CBitcoinAddress baddr = CBitcoinAddress(keyid);
                std::string addr = baddr.ToString();

                //ui->lineEdit_2->setText(QString::fromStdString(addr));

                CAmount nAmount = 0.001 * COIN; // 0.001 INN Fee

                // Wallet comments
                CWalletTx wtx;
                wtx.mapValue["comment"] = hash;
                std::string sNarr = "HyperFile POD";
                wtx.mapValue["to"]      = "HyperFile POD";

                if (pwalletMain->IsLocked())
                {
                    obj.push_back(Pair("error",  "Error, Your wallet is locked! Please unlock your wallet!"));
                    //ui->txLineEdit->setText("ERROR: Your wallet is locked! Cannot send HyperFile POD. Unlock your wallet!");
                } else if (pwalletMain->GetBalance() < 0.001) {
                    obj.push_back(Pair("error",  "Error, You need at least 0.001 INN to send HyperFile POD!"));
                    //ui->txLineEdit->setText("ERROR: You need at least a 0.001 INN balance to send HyperFile POD.");
                } else {
                    //std::string sNarr;
                    std::string strError = pwalletMain->SendMoneyToDestination(baddr.Get(), nAmount, sNarr, wtx);

                    if(strError != "")
                    {
                        obj.push_back(Pair("error",  strError.c_str()));
                    }

                    //ui->lineEdit_3->setText(QString::fromStdString(wtx.GetHash().GetHex()));

                    std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
                    std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;
                    std::string ipfsoglink = "https://ipfs.io/ipfs/" + hash;

                    obj.push_back(Pair("filename",           basename.c_str()));
                    obj.push_back(Pair("sizebytes",          size));
                    obj.push_back(Pair("ipfshash",           hash));
                    obj.push_back(Pair("infuralink",         filelink));
                    obj.push_back(Pair("cflink",             cloudlink));
                    obj.push_back(Pair("ipfslink",           ipfsoglink));
                    obj.push_back(Pair("podaddress",         addr.c_str()));
                    obj.push_back(Pair("podtxid",            wtx.GetHash().GetHex()));
                }
            }

            /*
            std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
            std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;

            obj.push_back(Pair("filename",           filename.c_str()));
            obj.push_back(Pair("sizebytes",          size));
            obj.push_back(Pair("ipfshash",           hash));
            obj.push_back(Pair("infuralink",         filelink));
            obj.push_back(Pair("cflink",             cloudlink));
            */

            } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
                obj.push_back(Pair("error",          e.what()));
            }

            return obj;
        } else {
            try {
                ipfs::Json add_result;
                ipfs::Client client("https://ipfs.infura.io:5001");

                if(userFile == "")
                {
                  return 0;
                }

                std::string filename = userFile.c_str();

                boost::filesystem::path p(filename);
                std::string basename = p.filename().string();

                printf("HyperFile Upload File Start: %s\n", basename.c_str());
                //printf("HyperFile File Contents: %s\n", ipfsC.c_str());

                client.FilesAdd(
                {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, userFile.c_str()}},
                &add_result);

                const std::string& hash = add_result[0]["hash"];
                int size = add_result[0]["size"];

                std::string r = add_result.dump();
                printf("HyperFile POD Successfully Added IPFS File(s): %s\n", r.c_str());

                //HyperFile POD
                if (hash != "") {
                    //Hash the file for Innova HyperFile POD
                    //uint256 imagehash = SerializeHash(ipfsContents);
                    CKeyID keyid(Hash160(hash.begin(), hash.end()));
                    CBitcoinAddress baddr = CBitcoinAddress(keyid);
                    std::string addr = baddr.ToString();

                    //ui->lineEdit_2->setText(QString::fromStdString(addr));

                    CAmount nAmount = 0.001 * COIN; // 0.001 INN Fee

                    // Wallet comments
                    CWalletTx wtx;
                    wtx.mapValue["comment"] = hash;
                    std::string sNarr = "HyperFile POD";
                    wtx.mapValue["to"]      = "HyperFile POD";

                    if (pwalletMain->IsLocked())
                    {
                        obj.push_back(Pair("error",  "Error, Your wallet is locked! Please unlock your wallet!"));
                        //ui->txLineEdit->setText("ERROR: Your wallet is locked! Cannot send HyperFile POD. Unlock your wallet!");
                    } else if (pwalletMain->GetBalance() < 0.001) {
                        obj.push_back(Pair("error",  "Error, You need at least 0.001 INN to send HyperFile POD!"));
                        //ui->txLineEdit->setText("ERROR: You need at least a 0.001 INN balance to send HyperFile POD.");
                    } else {
                        //std::string sNarr;
                        std::string strError = pwalletMain->SendMoneyToDestination(baddr.Get(), nAmount, sNarr, wtx);

                        if(strError != "")
                        {
                            obj.push_back(Pair("error",  strError.c_str()));
                        }

                        //ui->lineEdit_3->setText(QString::fromStdString(wtx.GetHash().GetHex()));

                        std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
                        std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;
                        std::string ipfsoglink = "https://ipfs.io/ipfs/" + hash;

                        obj.push_back(Pair("filename",           basename.c_str()));
                        obj.push_back(Pair("sizebytes",          size));
                        obj.push_back(Pair("ipfshash",           hash));
                        obj.push_back(Pair("infuralink",         filelink));
                        obj.push_back(Pair("cflink",             cloudlink));
                        obj.push_back(Pair("ipfslink",           ipfsoglink));
                        obj.push_back(Pair("podaddress",         addr.c_str()));
                        obj.push_back(Pair("podtxid",            wtx.GetHash().GetHex()));
                    }
                }

                } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
                obj.push_back(Pair("error",          e.what()));
            }

            return obj;
        }
}

Value hyperfileupload(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
    throw runtime_error(
        "hyperfileupload\n"
        "\nArguments:\n"
        "1. \"filelocation\"          (string, required) The file location of the file to upload (e.g. /home/name/file.jpg)\n"
        "Returns the uploaded IPFS file CID/Hash of the uploaded file and public gateway link if successful.");

    Object obj;
    std::string userFile = params[0].get_str();


    //Ensure IPFS connected
    fHyperFileLocal = GetBoolArg("-hyperfilelocal");

    if (fHyperFileLocal) {
        try {
            ipfs::Json add_result;

            std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

            ipfs::Client client(ipfsip);

            if(userFile == "")
            {
            return;
            }

            std::string filename = userFile.c_str();

            boost::filesystem::path p(filename);
            std::string basename = p.filename().string();

            printf("HyperFile Upload File Start: %s\n", basename.c_str());
            //printf("HyperFile File Contents: %s\n", ipfsC.c_str());

            client.FilesAdd(
            {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, userFile.c_str()}},
            &add_result);

            const std::string& hash = add_result[0]["hash"];
            int size = add_result[0]["size"];

            std::string r = add_result.dump();
            printf("HyperFile Successfully Added IPFS File(s): %s\n", r.c_str());

            std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
            std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;
            std::string ipfsoglink = "https://ipfs.io/ipfs/" + hash;

            obj.push_back(Pair("filename",           basename.c_str()));
            obj.push_back(Pair("sizebytes",          size));
            obj.push_back(Pair("ipfshash",           hash));
            obj.push_back(Pair("infuralink",         filelink));
            obj.push_back(Pair("cflink",             cloudlink));
            obj.push_back(Pair("ipfslink",           ipfsoglink));

            } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
                obj.push_back(Pair("error",          e.what()));
            }

            return obj;
        } else {
            try {
                ipfs::Json add_result;
                ipfs::Client client("https://ipfs.infura.io:5001");

                if(userFile == "")
                {
                  return 0;
                }

                std::string filename = userFile.c_str();

                boost::filesystem::path p(filename);
                std::string basename = p.filename().string();

                printf("HyperFile Upload File Start: %s\n", basename.c_str());
                //printf("HyperFile File Contents: %s\n", ipfsC.c_str());

                client.FilesAdd(
                {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, userFile.c_str()}},
                &add_result);

                const std::string& hash = add_result[0]["hash"];
                int size = add_result[0]["size"];

                std::string r = add_result.dump();
                printf("HyperFile Successfully Added IPFS File(s): %s\n", r.c_str());

                std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
                std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;
                std::string ipfsoglink = "https://ipfs.io/ipfs/" + hash;

                obj.push_back(Pair("filename",           basename.c_str()));
                obj.push_back(Pair("sizebytes",          size));
                obj.push_back(Pair("ipfshash",           hash));
                obj.push_back(Pair("infuralink",         filelink));
                obj.push_back(Pair("cflink",             cloudlink));
                obj.push_back(Pair("ipfslink",           ipfsoglink));

                } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
                obj.push_back(Pair("error",          e.what()));
            }

            return obj;
        }

        /*     ￼
        hyperfileupload C:/users/NAME/Dropbox/Innova/innova-128.png
        15:45:55        ￼
        {
        "filename" : "innova-128.png",
        "results" : "[{\"hash\":\"QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT\",\"path\":\"innova-128.png\",\"size\":47555}]",
        "ipfshash" : "QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT",
        "ipfslink" : "https://ipfs.infura.io/ipfs/QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT"
        }
        */
}

Value hyperfileduo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
    throw runtime_error(
        "hyperfileduo\n"
        "\nArguments:\n"
        "1. \"filelocation\"          (string, required) The file location of the file to upload (e.g. /home/name/file.jpg)\n"
        "Returns the uploaded IPFS file CID/Hashes of the uploaded file and public gateway links if successful from submission to two IPFS API nodes.");

    Object obj, second, first;
    std::string userFile = params[0].get_str();


    //Ensure IPFS connected
    fHyperFileLocal = GetBoolArg("-hyperfilelocal");

    if (fHyperFileLocal) {
        try {
            ipfs::Json add_result;

            std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

            ipfs::Client client(ipfsip);

            if(userFile == "")
            {
              return 0;
            }

            std::string filename = userFile.c_str();

            boost::filesystem::path p(filename);
            std::string basename = p.filename().string();

            printf("HyperFile Upload File Start: %s\n", basename.c_str());
            //printf("HyperFile File Contents: %s\n", ipfsC.c_str());

            client.FilesAdd(
            {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, userFile.c_str()}},
            &add_result);

            const std::string& hash = add_result[0]["hash"];
            int size = add_result[0]["size"];

            std::string r = add_result.dump();
            printf("HyperFile Duo Successfully Added IPFS File(s): %s\n", r.c_str());

            std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
            std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;
            std::string ipfsoglink = "https://ipfs.io/ipfs/" + hash;

            obj.push_back(Pair("duoupload",          "true"));

            first.push_back(Pair("nodeip",             ipfsip));
            first.push_back(Pair("filename",           basename.c_str()));
            first.push_back(Pair("sizebytes",          size));
            first.push_back(Pair("ipfshash",           hash));
            first.push_back(Pair("infuralink",         filelink));
            first.push_back(Pair("cflink",             cloudlink));
            first.push_back(Pair("ipfslink",           ipfsoglink));
            obj.push_back(Pair("first",                first));

            } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
                obj.push_back(Pair("error",          e.what()));
            }

            try {
                ipfs::Json add_result;
                ipfs::Client client("https://ipfs.infura.io:5001");

                if(userFile == "")
                {
                  return 0;
                }

                std::string filename = userFile.c_str();

                boost::filesystem::path p(filename);
                std::string basename = p.filename().string();

                printf("HyperFile Upload File Start: %s\n", basename.c_str());
                //printf("HyperFile File Contents: %s\n", ipfsC.c_str());

                client.FilesAdd(
                {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, userFile.c_str()}},
                &add_result);

                const std::string& hash = add_result[0]["hash"];
                int size = add_result[0]["size"];

                std::string r = add_result.dump();
                printf("HyperFile Duo Successfully Added IPFS File(s): %s\n", r.c_str());

                std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
                std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;
                std::string ipfsoglink = "https://ipfs.io/ipfs/" + hash;

                second.push_back(Pair("nodeip",             "https://ipfs.infura.io:5001"));
                second.push_back(Pair("filename",           basename.c_str()));
                second.push_back(Pair("sizebytes",          size));
                second.push_back(Pair("ipfshash",           hash));
                second.push_back(Pair("infuralink",         filelink));
                second.push_back(Pair("cflink",             cloudlink));
                second.push_back(Pair("ipfslink",           ipfsoglink));
                obj.push_back(Pair("second",                second));

                } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
                obj.push_back(Pair("error",          e.what()));
            }

            return obj;


        } else {
            obj.push_back(Pair("error",          "hyperfileduo is only available with -hyperfilelocal=1"));
            return obj;
        }

        /*     ￼
        hyperfileupload C:/users/NAME/Dropbox/Innova/innova-128.png
        15:45:55        ￼
        {
        "filename" : "innova-128.png",
        "results" : "[{\"hash\":\"QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT\",\"path\":\"innova-128.png\",\"size\":47555}]",
        "ipfshash" : "QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT",
        "ipfslink" : "https://ipfs.infura.io/ipfs/QmYKi7A9PyqywRA4aBWmqgSCYrXgRzri2QF25JKzBMjCxT"
        }
        */
}

Value hyperfileduopod(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
    throw runtime_error(
        "hyperfileduopod\n"
        "\nArguments:\n"
        "1. \"filelocation\"          (string, required) The file location of the file to upload (e.g. /home/name/file.jpg)\n"
        "Returns the uploaded IPFS file CID/Hashes of the uploaded file and public gateway links if successful from submission to two IPFS API nodes and PODs with D");

    Object obj, second, first;
    std::string userFile = params[0].get_str();


    //Ensure IPFS connected
    fHyperFileLocal = GetBoolArg("-hyperfilelocal");

    if (fHyperFileLocal) {
        try {
            ipfs::Json add_result;

            std::string ipfsip = GetArg("-hyperfileip", "localhost:5001"); //Default Localhost

            ipfs::Client client(ipfsip);

            if(userFile == "")
            {
              return 0;
            }

            std::string filename = userFile.c_str();

            boost::filesystem::path p(filename);
            std::string basename = p.filename().string();

            printf("HyperFile Upload File Start: %s\n", basename.c_str());
            //printf("HyperFile File Contents: %s\n", ipfsC.c_str());

            client.FilesAdd(
            {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, userFile.c_str()}},
            &add_result);

            const std::string& hash = add_result[0]["hash"];
            int size = add_result[0]["size"];

            std::string r = add_result.dump();
            printf("HyperFile Duo Pod Successfully Added IPFS File(s): %s\n", r.c_str());

            //HyperFile POD for Duo
            if (hash != "") {
                //Hash the file for Innova HyperFile POD
                //uint256 imagehash = SerializeHash(ipfsContents);
                CKeyID keyid(Hash160(hash.begin(), hash.end()));
                CBitcoinAddress baddr = CBitcoinAddress(keyid);
                std::string addr = baddr.ToString();

                //ui->lineEdit_2->setText(QString::fromStdString(addr));

                CAmount nAmount = 0.0005 * COIN; // 0.0005 INN Fee - 0.001 INN Total for HyperFile Duo Pod

                // Wallet comments
                CWalletTx wtx;
                wtx.mapValue["comment"] = hash;
                std::string sNarr = "HyperFile Duo POD";
                wtx.mapValue["to"]      = "HyperFile Duo POD";

                if (pwalletMain->IsLocked())
                {
                    obj.push_back(Pair("error",  "Error, Your wallet is locked! Please unlock your wallet!"));
                    //ui->txLineEdit->setText("ERROR: Your wallet is locked! Cannot send HyperFile POD. Unlock your wallet!");
                } else if (pwalletMain->GetBalance() < 0.001) {
                    obj.push_back(Pair("error",  "Error, You need at least 0.001 INN to send HyperFile POD!"));
                    //ui->txLineEdit->setText("ERROR: You need at least a 0.001 INN balance to send HyperFile POD.");
                } else {
                    //std::string sNarr;
                    std::string strError = pwalletMain->SendMoneyToDestination(baddr.Get(), nAmount, sNarr, wtx);

                    if(strError != "")
                    {
                        obj.push_back(Pair("error",  strError.c_str()));
                    }

                    std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
                    std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;
                    std::string ipfsoglink = "https://ipfs.io/ipfs/" + hash;

                    obj.push_back(Pair("duoupload",          "true"));

                    first.push_back(Pair("nodeip",             ipfsip));
                    first.push_back(Pair("filename",           basename.c_str()));
                    first.push_back(Pair("sizebytes",          size));
                    first.push_back(Pair("ipfshash",           hash));
                    first.push_back(Pair("infuralink",         filelink));
                    first.push_back(Pair("cflink",             cloudlink));
                    first.push_back(Pair("ipfslink",           ipfsoglink));
                    first.push_back(Pair("podaddress",         addr.c_str()));
                    first.push_back(Pair("podtxid",            wtx.GetHash().GetHex()));
                    obj.push_back(Pair("first",                first));

                }
            }

            } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
                obj.push_back(Pair("error",          e.what()));
            }

            try {
                ipfs::Json add_result;
                ipfs::Client client("https://ipfs.infura.io:5001");

                if(userFile == "")
                {
                  return 0;
                }

                std::string filename = userFile.c_str();

                boost::filesystem::path p(filename);
                std::string basename = p.filename().string();

                printf("HyperFile Upload File Start: %s\n", basename.c_str());
                //printf("HyperFile File Contents: %s\n", ipfsC.c_str());

                client.FilesAdd(
                {{basename.c_str(), ipfs::http::FileUpload::Type::kFileName, userFile.c_str()}},
                &add_result);

                const std::string& hash = add_result[0]["hash"];
                int size = add_result[0]["size"];

                std::string r = add_result.dump();
                printf("HyperFile Duo POD Successfully Added IPFS File(s): %s\n", r.c_str());

                //HyperFile POD for Duo
                if (hash != "") {
                    //Hash the file for Innova HyperFile POD
                    //uint256 imagehash = SerializeHash(ipfsContents);
                    CKeyID keyid(Hash160(hash.begin(), hash.end()));
                    CBitcoinAddress baddr = CBitcoinAddress(keyid);
                    std::string addr = baddr.ToString();

                    //ui->lineEdit_2->setText(QString::fromStdString(addr));

                    CAmount nAmount = 0.0005 * COIN; // 0.0005 INN Fee - 0.001 INN Total for HyperFile Duo Pod

                    // Wallet comments
                    CWalletTx wtx;
                    wtx.mapValue["comment"] = hash;
                    std::string sNarr = "HyperFile Duo POD";
                    wtx.mapValue["to"]      = "HyperFile Duo POD";

                    if (pwalletMain->IsLocked())
                    {
                        obj.push_back(Pair("error",  "Error, Your wallet is locked! Please unlock your wallet!"));
                        //ui->txLineEdit->setText("ERROR: Your wallet is locked! Cannot send HyperFile POD. Unlock your wallet!");
                    } else if (pwalletMain->GetBalance() < 0.001) {
                        obj.push_back(Pair("error",  "Error, You need at least 0.001 INN to send HyperFile POD!"));
                        //ui->txLineEdit->setText("ERROR: You need at least a 0.001 INN balance to send HyperFile POD.");
                    } else {
                        //std::string sNarr;
                        std::string strError = pwalletMain->SendMoneyToDestination(baddr.Get(), nAmount, sNarr, wtx);

                        if(strError != "")
                        {
                            obj.push_back(Pair("error",  strError.c_str()));
                        }

                        std::string filelink = "https://ipfs.infura.io/ipfs/" + hash;
                        std::string cloudlink = "https://cloudflare-ipfs.com/ipfs/" + hash;
                        std::string ipfsoglink = "https://ipfs.io/ipfs/" + hash;

                        second.push_back(Pair("nodeip",             "https://ipfs.infura.io:5001"));
                        second.push_back(Pair("filename",           basename.c_str()));
                        second.push_back(Pair("sizebytes",          size));
                        second.push_back(Pair("ipfshash",           hash));
                        second.push_back(Pair("infuralink",         filelink));
                        second.push_back(Pair("cflink",             cloudlink));
                        second.push_back(Pair("ipfslink",           ipfsoglink));
                        second.push_back(Pair("podaddress",         addr.c_str()));
                        second.push_back(Pair("podtxid",            wtx.GetHash().GetHex()));
                        obj.push_back(Pair("second",                second));

                    }
                }

                } catch (const std::exception& e) {
                std::cerr << e.what() << std::endl; //302 error on large files: passing null and throwing exception
                obj.push_back(Pair("error",          e.what()));
            }

            return obj;


        } else {
            obj.push_back(Pair("error",          "hyperfileduopod is only available with -hyperfilelocal=1"));
            return obj;
        }
}
#endif
