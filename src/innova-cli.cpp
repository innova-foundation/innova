// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "innovarpc.h"
#include "util.h"

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>

#include <cstdio>
#include <string>

static std::string CliUsage()
{
    return "Innova RPC client version " + FormatFullVersion() + "\n\n"
        "Usage:\n"
        "  innova-cli [options] <command> [params]  Send a command to a running innovad or Innova wallet\n"
        "  innova-cli [options] help                List commands\n"
        "  innova-cli [options] help <command>      Get help for a command\n\n"
        "Options:\n"
        "  -?                    This help message\n"
        "  -version              Print the version and exit\n"
        "  -conf=<file>          Configuration file (default: innova.conf)\n"
        "  -datadir=<dir>        Data directory\n"
        "  -testnet              Use the test network\n"
        "  -rpcconnect=<ip>      Node address (default: 127.0.0.1)\n"
        "  -rpcport=<port>       RPC port (default: 14531, testnet: 15531)\n"
        "  -rpcuser=<user>       RPC user name\n"
        "  -rpcpassword=<pw>     RPC password\n"
        "  -rpcssl               Use HTTPS for RPC\n"
        "  -rpcwait              Wait for the RPC server to start\n";
}

static bool RPCPortOpen()
{
    try {
        boost::asio::io_context io;
        boost::asio::ip::tcp::resolver resolver(io);
        boost::asio::ip::tcp::socket socket(io);
        boost::asio::connect(socket, resolver.resolve(
            GetArg("-rpcconnect", "127.0.0.1"),
            GetArg("-rpcport", GetBoolArg("-testnet", false) ? "15531" : "14531")));
        return true;
    } catch (...) {
        return false;
    }
}

int main(int argc, char* argv[])
{
    ParseParameters(argc, argv);

    if (mapArgs.count("-version")) {
        fprintf(stdout, "Innova RPC client version %s\n", FormatFullVersion().c_str());
        return 0;
    }

    int nCommand = 0;
    for (int i = 1; i < argc; i++)
        if (!IsSwitchChar(argv[i][0]))
            nCommand++;
    if (nCommand == 0 || mapArgs.count("-?") || mapArgs.count("-help") || mapArgs.count("--help")) {
        fprintf(stdout, "%s", CliUsage().c_str());
        return nCommand == 0 && !mapArgs.count("-?") && !mapArgs.count("-help") && !mapArgs.count("--help");
    }

    if (mapArgs.count("-datadir") && !boost::filesystem::is_directory(GetDataDir(false))) {
        fprintf(stderr, "error: data directory \"%s\" does not exist\n", mapArgs["-datadir"].c_str());
        return 1;
    }
    // Never create a config: that is the node's job.
    if (boost::filesystem::exists(GetConfigFile()))
        ReadConfigFile(mapArgs, mapMultiArgs);

    if (GetBoolArg("-rpcwait", false))
        while (!RPCPortOpen())
            MilliSleep(1000);

    int nRet = CommandLineRPC(argc, argv);
    fflush(stdout);
    fflush(stderr);
    exit(nRet);
}
