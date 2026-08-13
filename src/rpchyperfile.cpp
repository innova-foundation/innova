// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2017-2021 The Denarius developers
// Copyright (c) 2019-2026 The Innova Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Original OG - credits to carsenk for original IPFS code & Denarius Jupiter Commands

#include "main.h"
#include "innovarpc.h"
#include "init.h"
#include "txdb.h"
#include "pod.h"
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

// No fallback endpoint: an unset or disabled endpoint is an error.
static std::string HyperfileEndpoint()
{
    fHyperfileLocal = GetBoolArg("-hyperfilelocal");
    if (!fHyperfileLocal)
        throw JSONRPCError(RPC_MISC_ERROR,
            "Hyperfile is off. Set hyperfilelocal=1 and hyperfileip=<host:port> in innova.conf "
            "(the Foundation node is ipfs.innova-foundation.com:5001) and restart. There is no "
            "public fallback endpoint.");

    std::string strEndpoint = GetArg("-hyperfileip", "");
    if (strEndpoint.empty())
        throw JSONRPCError(RPC_MISC_ERROR,
            "hyperfilelocal=1 but no hyperfileip is set, and there is no default IPFS API "
            "endpoint to fall back to. Set hyperfileip=<host:port> in innova.conf.");

    return strEndpoint;
}

static void HyperfileAddLinks(Object& obj, const std::string& strCid)
{
    obj.push_back(Pair("ipfslink",  "https://ipfs.io/ipfs/" + strCid));
    obj.push_back(Pair("dweblink",  "https://dweb.link/ipfs/" + strCid));
}

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

    ipfs::Client client(HyperfileEndpoint());

    client.BlockStat(userHash, &stat_result);
    obj.push_back(Pair("key",        stat_result["Key"].dump().c_str()));
    obj.push_back(Pair("size",       stat_result["Size"].dump().c_str()));

    return obj;
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

    ipfs::Client client(HyperfileEndpoint());

    client.BlockGet(userHash, &block_contents);
    obj.push_back(Pair("blockhex", ipfs::test::string_to_hex(block_contents.str()).c_str()));

    return obj;
}

Value hyperfileversion(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "hyperfileversion\n"
            "Returns the version of the connected IPFS node within the Innova Hyperfile");

    ipfs::Json version;
    ipfs::Json id;
    bool connected = false;
    Object obj, peerinfo;

    std::string strEndpoint = HyperfileEndpoint();
    ipfs::Client client(strEndpoint);

    client.Version(&version);
    printf("Hyperfile: IPFS Peer Version: %s\n", version["Version"].dump().c_str());

    if (version["Version"].dump() != "")
        connected = true;

    client.Id(&id);

    obj.push_back(Pair("connected",     connected));
    obj.push_back(Pair("ipfspeer",      strEndpoint));
    obj.push_back(Pair("ipfsversion",   version["Version"].dump().c_str()));

    peerinfo.push_back(Pair("peerid",       id["ID"].dump().c_str()));
    peerinfo.push_back(Pair("addresses",    id["Addresses"].dump().c_str()));
    peerinfo.push_back(Pair("publickey",    id["PublicKey"].dump().c_str()));
    obj.push_back(Pair("peerinfo",          peerinfo));

    return obj;
}

// Uploads the file and returns the CID. Throws on any failure; a partial upload
// must not be reported as a success.
static std::string HyperfileAdd(const std::string& strPath, Object& obj)
{
    ipfs::Client client(HyperfileEndpoint());

    boost::filesystem::path p(strPath);
    std::string strBase = p.filename().string();

    printf("Hyperfile Upload File Start: %s\n", strBase.c_str());

    ipfs::Json add_result;
    try
    {
        client.FilesAdd(
            {{strBase.c_str(), ipfs::http::FileUpload::Type::kFileName, strPath.c_str()}},
            &add_result);
    }
    catch (const std::exception& e)
    {
        // A 302 here is the usual symptom of a large file or an endpoint that is
        // not an IPFS API. Either way nothing was stored.
        throw JSONRPCError(RPC_MISC_ERROR, std::string("IPFS upload failed: ") + e.what());
    }

    if (add_result.empty() || add_result[0]["hash"].is_null())
        throw JSONRPCError(RPC_MISC_ERROR, "IPFS upload returned no CID.");

    const std::string strCid = add_result[0]["hash"];
    if (strCid.empty())
        throw JSONRPCError(RPC_MISC_ERROR, "IPFS upload returned an empty CID.");

    printf("Hyperfile Successfully Added IPFS File(s): %s\n", add_result.dump().c_str());

    obj.push_back(Pair("filename",  strBase));
    if (!add_result[0]["size"].is_null())
        obj.push_back(Pair("sizebytes", (int)add_result[0]["size"]));
    obj.push_back(Pair("ipfshash",  strCid));
    HyperfileAddLinks(obj, strCid);

    return strCid;
}

Value hyperfileupload(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "hyperfileupload <filelocation>\n"
            "\nUploads a file to IPFS through the configured Hyperfile endpoint.\n"
            "\nArguments:\n"
            "1. \"filelocation\"      (string, required) The file to upload (e.g. /home/name/file.jpg)\n"
            "\n" + PodHyperfileDisclosure() + "\n"
            "\nThis command reads a path on the node's filesystem and requires -enablefilerpc=1.\n");

    PodRequireFileRpc("hyperfileupload");

    std::string userFile = params[0].get_str();
    if (userFile.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "filelocation is empty.");

    Object obj;
    HyperfileAdd(userFile, obj);
    return obj;
}

Value hyperfilepod(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "hyperfilepod <filelocation>\n"
            "\nUploads a file to IPFS and anchors its SHA-256 digest on the Innova chain,\n"
            "with the file's CID carried alongside as a retrieval locator.\n"
            "\nArguments:\n"
            "1. \"filelocation\"      (string, required) The file to upload (e.g. /home/name/file.jpg)\n"
            "\nThe digest is what binds. If the CID later stops resolving, the stamp still\n"
            "proves the file. Verify with podverify.\n"
            "\n" + PodHyperfileDisclosure() + "\n"
            "\nUse proofofdata instead if you want the timestamp without publishing the file.\n"
            "\nThis command reads a path on the node's filesystem and requires -enablefilerpc=1.\n");

    PodRequireFileRpc("hyperfilepod");

    if (!pwalletMain)
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is not available.");

    std::string userFile = params[0].get_str();
    if (userFile.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "filelocation is empty.");

    // Hash before uploading: a stamp is worthless if the bytes that were hashed
    // are not the bytes that were stored.
    std::vector<unsigned char> vDigest;
    std::string strError;
    if (!PodHashFile(userFile, vDigest, strError))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strError);

    Object obj;
    std::string strCid = HyperfileAdd(userFile, obj);

    obj.push_back(Pair("filesha256", HexStr(vDigest.begin(), vDigest.end())));

    std::vector<unsigned char> vLocator;
    if (!PodCidToLocator(strCid, vLocator))
        obj.push_back(Pair("locatornote",
            "CID is not a CIDv0 sha2-256 multihash, so no locator was embedded. "
            "The digest still binds the file."));

    CWalletTx wtx;
    wtx.mapValue["comment"] = strCid;
    wtx.mapValue["to"] = "Hyperfile POD";
    wtx.mapValue["podsha256"] = HexStr(vDigest.begin(), vDigest.end());

    strError = PodCreateStamp(pwalletMain, POD_TYPE_HYPERFILE, vDigest, vLocator, wtx);
    if (strError != "")
    {
        // The upload happened and cannot be undone, so report it; the stamp did not.
        obj.push_back(Pair("error", strError));
        obj.push_back(Pair("stamped", false));
        return obj;
    }

    obj.push_back(Pair("stamped", true));
    obj.push_back(Pair("podtxid", wtx.GetHash().GetHex()));
    return obj;
}

#endif // USE_IPFS
