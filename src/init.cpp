// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2017-2021 The Denarius developers
// Copyright (c) 2019-2022 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "main.h"
#include "txdb.h"
#include "walletdb.h"
#include "innovarpc.h"
#include "net.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include "checkpoints.h"
#include "activecollateralnode.h"
#include "collateralnodeconfig.h"
#include "spork.h"
#include "smessage.h"
#include "ringsig.h"
#include "idns.h"

#ifdef USE_NATIVETOR
#include "tor/anonymize.h" //Tor native optional integration (Flag -nativetor=1)
#endif

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <openssl/crypto.h>

#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>

#ifndef WIN32
#include <signal.h>
#endif


using namespace std;
using namespace boost;

CWallet* pwalletMain = NULL;
IDns* idns = NULL;
CClientUIInterface uiInterface;
bool fConfChange;
bool fEnforceCanonical;
bool fMinimizeCoinAge;
unsigned int nNodeLifespan;
unsigned int nDerivationMethodIndex;
unsigned int nMinerSleep;

unsigned short const onion_port = 9089; //Tor Onion Routing Default Port

unsigned int nBlockMaxSize;
unsigned int nBlockPrioritySize;
unsigned int nBlockMinSize;
int64_t nMinTxFee = MIN_TX_FEE;

bool fUseFastIndex;
enum Checkpoints::CPMode CheckpointsMode;

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

void ExitTimeout(void* parg)
{
#ifdef WIN32
    //MilliSleep(5000);
    sleep(5);
    ExitProcess(0);
#endif
}

void StartShutdown()
{
#ifdef QT_GUI
    // ensure we leave the Qt main loop for a clean GUI exit (Shutdown() is called in bitcoin.cpp afterwards)
    uiInterface.QueueShutdown();
#else
    // Without UI, Shutdown() can simply be started in a new thread
    NewThread(Shutdown, NULL);
#endif
}

void Shutdown(void* parg)
{
    static CCriticalSection cs_Shutdown;
    static bool fTaken;
    printf("Shutdown is in progress...\n\n");

    // Make this thread recognisable as the shutdown thread
    RenameThread("innova-shutoff");

    bool fFirstThread = false;
    {
        TRY_LOCK(cs_Shutdown, lockShutdown);
        if (lockShutdown)
        {
            fFirstThread = !fTaken;
            fTaken = true;
        }
    }
    static bool fExit;
    if (fFirstThread)
    {
        fShutdown = true;

        if(idns) {
            delete idns;
        }
        Finalise();
        /*
        SecureMsgShutdown();

        mempool.AddTransactionsUpdated(1);
//        CTxDB().Close();
        bitdb.Flush(false);
        StopNode();
        bitdb.Flush(true);
        boost::filesystem::remove(GetPidFile());
        UnregisterWallet(pwalletMain);
        delete pwalletMain;
        */
        NewThread(ExitTimeout, NULL);
        MilliSleep(50);
        printf("Innova exited\n\n");
        fExit = true;
#ifndef QT_GUI
        // ensure non-UI client gets exited here, but let Bitcoin-Qt reach 'return 0;' in bitcoin.cpp
        exit(0);
#endif
    } else
    {
        while (!fExit)
            MilliSleep(500);
        MilliSleep(100);
        ExitThread(0);
    };
}

void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}





//////////////////////////////////////////////////////////////////////////////
//
// Start
//
#if !defined(QT_GUI)
bool AppInit(int argc, char* argv[])
{
    bool fRet = false;
    try
    {
        //
        // Parameters
        //
        // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
        ParseParameters(argc, argv);
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified directory does not exist\n");
            Shutdown(NULL);
        };
        ReadConfigFile(mapArgs, mapMultiArgs);

        if (mapArgs.count("-?") || mapArgs.count("--help"))
        {
            // First part of help message is specific to bitcoind / RPC client
            std::string strUsage = _("Innova version") + " " + FormatFullVersion() + "\n\n" +
                _("Usage:") + "\n" +
                  "  innovad [options]                     " + "\n" +
                  "  innovad [options] <command> [params]  " + _("Send command to -server or innovad") + "\n" +
                  "  innovad [options] help                " + _("List commands") + "\n" +
                  "  innovad [options] help <command>      " + _("Get help for a command") + "\n";

            strUsage += "\n" + HelpMessage();

            fprintf(stdout, "%s", strUsage.c_str());
            return false;
        };

        // Command-line RPC
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "innova:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            int ret = CommandLineRPC(argc, argv);
            exit(ret);
        };

#if !defined(WIN32) && !defined(QT_GUI)
    fDaemon = GetBoolArg("-daemon", false);
    if (fDaemon)
    {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0)
        {
            fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
            return false;
        }
        if (pid > 0)
        {
            CreatePidFile(GetPidFile(), pid);
            return true;
        }

        pid_t sid = setsid();
        if (sid < 0)
            fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
    }
#endif

        fRet = AppInit2();
    } catch (std::exception& e)
    {
        PrintException(&e, "AppInit()");
    } catch (...)
    {
        PrintException(NULL, "AppInit()");
    };
    //if (!fRet)
        //Shutdown(NULL);
    if (!fRet)
      Shutdown(NULL);

    return fRet;
}

extern void noui_connect();
int main(int argc, char* argv[])
{
    bool fRet = false;

    // Connect bitcoind signal handlers
    noui_connect();

    fRet = AppInit(argc, argv);

    if (fRet && fDaemon)
        return 0;

    return 1;
}
#endif

bool static InitError(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("Innova"), CClientUIInterface::OK | CClientUIInterface::MODAL);
    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("Innova"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
    return true;
}


bool static Bind(const CService &addr, bool fError = true)
{
    if (IsLimited(addr))
        return false;

    std::string strError;
    if (!BindListenPort(addr, strError))
    {
        if (fError)
            return InitError(strError);
        return false;
    };
    return true;
}

// Core-specific options shared between UI and daemon
std::string HelpMessage()
{
    string strUsage = _("Options:") + "\n" +
        "  -?                     " + _("This help message") + "\n" +
        "  -conf=<file>           " + _("Specify configuration file (default: innova.conf)") + "\n" +
        "  -pid=<file>            " + _("Specify pid file (default: innovad.pid)") + "\n" +
        "  -datadir=<dir>         " + _("Specify data directory") + "\n" +
        "  -wallet=<dir>          " + _("Specify wallet file (within data directory)") + "\n" +
        "  -dbcache=<n>           " + _("Set database cache size in megabytes (default: 25)") + "\n" +
        "  -dblogsize=<n>         " + _("Set database disk log size in megabytes (default: 100)") + "\n" +
        "  -timeout=<n>           " + _("Specify connection timeout in milliseconds (default: 5000)") + "\n" +
        "  -proxy=<ip:port>       " + _("Connect through socks proxy") + "\n" +
        "  -socks=<n>             " + _("Select the version of socks proxy to use (4-5, default: 5)") + "\n" +
        "  -tor=<ip:port>         " + _("Use proxy to reach tor hidden services (default: same as -proxy)") + "\n"
        "  -dns                   " + _("Allow DNS lookups for -addnode, -seednode and -connect") + "\n" +
        "  -port=<port>           " + _("Listen for connections on <port> (default: 14530 or testnet: 15530)") + "\n" +
        "  -maxconnections=<n>    " + _("Maintain at most <n> connections to peers (default: 125)") + "\n" +
        "  -maxuploadtarget=<n>   " + _("Set a max upload target for your INN node, 100 = 100MB (default: 0 unlimited)") + "\n" +
        "  -addnode=<ip>          " + _("Add a node to connect to and attempt to keep the connection open") + "\n" +
        "  -connect=<ip>          " + _("Connect only to the specified node(s)") + "\n" +
        "  -seednode=<ip>         " + _("Connect to a node to retrieve peer addresses, and disconnect") + "\n" +
        "  -externalip=<ip>       " + _("Specify your own public address") + "\n" +
        "  -onlynet=<net>         " + _("Only connect to nodes in network <net> (IPv4, IPv6 or Tor)") + "\n" +
        "  -discover              " + _("Discover own IP address (default: 1 when listening and no -externalip)") + "\n" +
        "  -listen                " + _("Accept connections from outside (default: 1 if no -proxy or -connect)") + "\n" +
        "  -bind=<addr>           " + _("Bind to given address. Use [host]:port notation for IPv6") + "\n" +
        "  -dnsseed               " + _("Find peers using DNS lookup (default: 1)") + "\n" +
        "  -onionseed             " + _("Find peers using .onion seeds (default: 0 unless -connect)") + "\n" +
        "  -nativetor=<n>         " + _("Enable or disable Native Tor Onion Node (default: 0)") +
        "  -staking               " + _("Stake your coins to support network and gain reward (default: 1)") + "\n" +
        "  -minstakeinterval=<n>  " + _("Minimum time in seconds between successful stakes (default: 30)") + "\n" +
        "  -minersleep=<n>        " + _("Milliseconds between stake attempts. Lowering this param will not result in more stakes. (default: 1000)") + "\n" +
        "  -synctime              " + _("Sync time with other nodes. Disable if time on your system is precise e.g. syncing with NTP (default: 1)") + "\n" +
        "  -cppolicy              " + _("Sync checkpoints policy (default: strict)") + "\n" +
        "  -banscore=<n>          " + _("Threshold for disconnecting misbehaving peers (default: 100)") + "\n" +
        "  -bantime=<n>           " + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)") + "\n" +
        "  -softbantime=<n>       " + _("Number of seconds to keep soft banned peers from reconnecting (default: 3600)") + "\n" +
        "  -maxreceivebuffer=<n>  " + _("Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)") + "\n" +
        "  -maxsendbuffer=<n>     " + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)") + "\n" +
#ifdef USE_UPNP
#if USE_UPNP
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 1 when listening)") + "\n" +
#else
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 0)") + "\n" +
#endif
#endif
        "  -detachdb              " + _("Detach block and address databases. Increases shutdown time (default: 0)") + "\n" +
        "  -paytxfee=<amt>        " + _("Fee per KB to add to transactions you send") + "\n" +
        "  -mininput=<amt>        " + _("When creating transactions, ignore inputs with value less than this (default: 0.01)") + "\n" +
#ifdef QT_GUI
        "  -server                " + _("Accept command line and JSON-RPC commands") + "\n" +
#endif
#if !defined(WIN32) && !defined(QT_GUI)
        "  -daemon                " + _("Run in the background as a daemon and accept commands") + "\n" +
#endif
        "  -testnet               " + _("Use the test network") + "\n" +
        "  -debug                 " + _("Output extra debugging information. Implies all other -debug* options") + "\n" +
        "  -debugnet              " + _("Output extra network debugging information") + "\n" +
        "  -debugchain            " + _("Output extra blockchain debugging information") + "\n" +
        "  -logtimestamps         " + _("Prepend debug output with timestamp") + "\n" +
        "  -shrinkdebugfile       " + _("Shrink debug.log file on client startup (default: 1 when no -debug)") + "\n" +
        "  -printtoconsole        " + _("Send trace/debug info to console instead of debug.log file") + "\n" +
#ifdef WIN32
        "  -printtodebugger       " + _("Send trace/debug info to debugger") + "\n" +
#endif
        "  -rpcuser=<user>        " + _("Username for JSON-RPC connections") + "\n" +
        "  -rpcpassword=<pw>      " + _("Password for JSON-RPC connections") + "\n" +
        "  -rpcport=<port>        " + _("Listen for JSON-RPC connections on <port> (default: 32339 or testnet: 32338)") + "\n" +
        "  -rpcallowip=<ip>       " + _("Allow JSON-RPC connections from specified IP address") + "\n" +
        "  -rpcconnect=<ip>       " + _("Send commands to node running on <ip> (default: 127.0.0.1)") + "\n" +
        "  -blocknotify=<cmd>     " + _("Execute command when the best block changes (%s in cmd is replaced by block hash)") + "\n" +
        "  -walletnotify=<cmd>    " + _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)") + "\n" +
        "  -confchange            " + _("Require a confirmations for change (default: 0)") + "\n" +
        "  -enforcecanonical      " + _("Enforce transaction scripts to use canonical PUSH operators (default: 1)") + "\n" +
        "  -alertnotify=<cmd>     " + _("Execute command when a relevant alert is received (%s in cmd is replaced by message)") + "\n" +
        "  -upgradewallet         " + _("Upgrade wallet to latest format") + "\n" +
        "  -keypool=<n>           " + _("Set key pool size to <n> (default: 100)") + "\n" +
        "  -rescan                " + _("Rescan the block chain for missing wallet transactions") + "\n" +
        "  -zapwallettxes         " + _("Clear list of wallet transactions (diagnostic tool; implies -rescan)") + "\n" +
        "  -salvagewallet         " + _("Attempt to recover private keys from a corrupt wallet.dat") + "\n" +
        "  -checkblocks=<n>       " + _("How many blocks to check at startup (default: 2500, 0 = all)") + "\n" +
        "  -checklevel=<n>        " + _("How thorough the block verification is (0-6, default: 1)") + "\n" +
        "  -loadblock=<file>      " + _("Imports blocks from external blk000?.dat file") + "\n" +

        "\n" + _("Block creation options:") + "\n" +
        "  -blockminsize=<n>      "   + _("Set minimum block size in bytes (default: 0)") + "\n" +
        "  -blockmaxsize=<n>      "   + _("Set maximum block size in bytes (default: 250000)") + "\n" +
        "  -blockprioritysize=<n> "   + _("Set maximum size of high-priority/low-fee transactions in bytes (default: 27000)") + "\n" +
        "  -maxorphantx=<n>       "   + strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"), DEFAULT_MAX_ORPHAN_TRANSACTIONS) + "\n" +
        "  -maxorphanblocks=<n>   "   + strprintf(_("Keep at most <n> unconnectable blocks in memory (default: %u)"), DEFAULT_MAX_ORPHAN_BLOCKS) + "\n" +

        "\n" + _("SSL options: (see the Bitcoin Wiki for SSL setup instructions)") + "\n" +
        "  -rpcssl                                  " + _("Use OpenSSL (https) for JSON-RPC connections") + "\n" +
        "  -rpcsslcertificatechainfile=<file.cert>  " + _("Server certificate file (default: server.cert)") + "\n" +
        "  -rpcsslprivatekeyfile=<file.pem>         " + _("Server private key (default: server.pem)") + "\n" +
        "  -rpcsslciphers=<ciphers>                 " + _("Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)") + "\n" +

        "\n" + _("Collateralnode options:") + "\n" +
        "  -collateralnode=<n>            " + _("Enable the client to act as a collateralnode (0-1, default: 0)") + "\n" +
        "  -mnconf=<file>             " + _("Specify collateralnode configuration file (default: collateralnode.conf)") + "\n" +
        "  -cnconflock=<n>            " + _("Lock collateralnodes from collateralnode configuration file (default: 1)") +
        "  -collateralnodeprivkey=<n>     " + _("Set the collateralnode private key") + "\n" +
        "  -collateralnodeaddr=<n>        " + _("Set external address:port to get to this collateralnode (example: address:port)") + "\n" +
        "  -collateralnodeminprotocol=<n> " + _("Ignore collateralnodes less than version (example: 70007; default : 0)") + "\n" +

        "\n" + _("Secure messaging options:") + "\n" +
        "  -nosmsg                                  " + _("Disable secure messaging.") + "\n" +
        "  -debugsmsg                               " + _("Log extra debug messages.") + "\n" +
        "  -smsgscanchain                           " + _("Scan the block chain for public key addresses on startup.") + "\n";

    return strUsage;
}

/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void)
{
    if(!ECC_InitSanityCheck())
    {
        InitError("OpenSSL appears to lack support for elliptic curve cryptography. For more "
                  "information, visit https://en.bitcoin.it/wiki/OpenSSL_and_EC_Libraries");
        return false;
    };

    // TODO: remaining sanity checks, see #4081

    return true;
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInit2()
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
// We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
// which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif
#ifndef WIN32
    umask(077);

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);
#endif

    if (!CheckDiskSpace())
        return false;

    // ********************************************************* Step 2: parameter interactions

    nNodeLifespan = GetArg("-addrlifespan", 7);
    fUseFastIndex = GetBoolArg("-fastindex", true);
    nMinStakeInterval = GetArg("-minstakeinterval", 60); // 2 blocks, don't make pos chains!
    nMinerSleep = GetArg("-minersleep", 10000); //default 10seconds, higher=more cpu usage

    // Largest block you're willing to create.
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    nBlockPrioritySize = GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-innovai-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    if (mapArgs.count("-mintxfee"))
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);

    if (fDebug)
        printf("nMinerSleep %u\n", nMinerSleep);

    CheckpointsMode = Checkpoints::STRICT;
    std::string strCpMode = GetArg("-cppolicy", "strict");

    if (strCpMode == "strict")
        CheckpointsMode = Checkpoints::STRICT;

    if (strCpMode == "advisory")
        CheckpointsMode = Checkpoints::ADVISORY;

    if (strCpMode == "permissive")
        CheckpointsMode = Checkpoints::PERMISSIVE;

    nDerivationMethodIndex = 0;

    fTestNet = GetBoolArg("-testnet");

    fCNLock = GetBoolArg("-cnconflock");
    fNativeTor = GetBoolArg("-nativetor");
    fHyperFileLocal = GetBoolArg("-hyperfilelocal");

    if (mapArgs.count("-bind"))
    {
        // when specifying an explicit binding address, you want to listen on it
        // even when -connect or -proxy is specified
        SoftSetBoolArg("-listen", true);
    }

    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0)
    {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        SoftSetBoolArg("-dnsseed", false);
        SoftSetBoolArg("-listen", false);
        SoftSetBoolArg("-onionseed", false);
    }

    if (mapArgs.count("-proxy"))
    {
        // to protect privacy, do not listen by default if a proxy server is specified
        SoftSetBoolArg("-listen", false);
    }

    if (!GetBoolArg("-listen", true))
    {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        SoftSetBoolArg("-upnp", false);
        SoftSetBoolArg("-discover", false);
    }

    if (mapArgs.count("-externalip"))
    {
        // if an explicit public IP is specified, do not try to find others
        SoftSetBoolArg("-discover", false);
    }

    if (GetBoolArg("-salvagewallet"))
    {
        // Rewrite just private keys: rescan to find transactions
        SoftSetBoolArg("-rescan", true);
    }

    // -zapwallettx implies a rescan
    if (GetBoolArg("-zapwallettxes", false)) {
        if (SoftSetBoolArg("-rescan", true))
            printf("AppInit2 : parameter interaction: -zapwallettxes=1 -> setting -rescan=1\n");
    }

    // Process Collateralnode config
    std::string err;
    collateralnodeConfig.read(err);
    if (!err.empty())
        InitError("error while parsing collateralnode.conf Error: " + err);

    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (SoftSetBoolArg("-dnsseed", false))
            InitWarning(_("AppInit2 : parameter interaction: -connect set -> setting -dnsseed=0\n"));
        if (SoftSetBoolArg("-listen", false))
            InitWarning(_("AppInit2 : parameter interaction: -connect set -> setting -listen=0\n"));
    }
    // ********************************************************* Step 3: parameter-to-internal-flags

    fDebug = GetBoolArg("-debug");

    // - debug implies fDebug*, unless otherwise specified, except net/fs/smsg since they are -really- noisy.
    if (fDebug)
    {
        SoftSetBoolArg("-debugnet", false);
        SoftSetBoolArg("-debugfs", false);
        SoftSetBoolArg("-debugsmsg", false);
        SoftSetBoolArg("-debugchain", true);
        SoftSetBoolArg("-debugringsig", true);
    };

    fDebugNet = GetBoolArg("-debugnet");
    fDebugSmsg = GetBoolArg("-debugsmsg");
    fDebugChain = GetBoolArg("-debugchain");
    fDebugCN = GetBoolArg("-debugfs");
    fDebugRingSig = GetBoolArg("-debugringsig");

    fNoSmsg = GetBoolArg("-nosmsg");
    fDisableStealth = GetBoolArg("-disablestealth"); // force-disable stealth transaction scanning

    bitdb.SetDetach(GetBoolArg("-detachdb", false));

#if !defined(WIN32) && !defined(QT_GUI)
    fDaemon = GetBoolArg("-daemon");
#else
    fDaemon = false;
#endif

    if (fDaemon)
        fServer = true;
    else
        fServer = GetBoolArg("-server");

    /* force fServer when running without GUI */
#if !defined(QT_GUI)
    fServer = true;
#endif
    fPrintToConsole = GetBoolArg("-printtoconsole");
    fPrintToDebugger = GetBoolArg("-printtodebugger");
    fLogTimestamps = GetBoolArg("-logtimestamps");

    if (mapArgs.count("-timeout"))
    {
        int nNewTimeout = GetArg("-timeout", 5000);
        if (nNewTimeout > 0 && nNewTimeout < 600000)
            nConnectTimeout = nNewTimeout;
    };

    if (mapArgs.count("-paytxfee"))
    {
        if (!ParseMoney(mapArgs["-paytxfee"], nTransactionFee))
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s'"), mapArgs["-paytxfee"].c_str()));
        if (nTransactionFee > 0.25 * COIN)
            InitWarning(_("Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
    };

    fConfChange = GetBoolArg("-confchange", false);
    fEnforceCanonical = GetBoolArg("-enforcecanonical", true);

    if (mapArgs.count("-mininput"))
    {
        if (!ParseMoney(mapArgs["-mininput"], nMinimumInputValue))
            return InitError(strprintf(_("Invalid amount for -mininput=<amount>: '%s'"), mapArgs["-mininput"].c_str()));
    };

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log
    // Sanity check
    if (!InitSanityCheck())
        return InitError(_("Initialization sanity check failed. Innova is shutting down."));

    std::string strDataDir = GetDataDir().string();
    std::string strWalletFileName = GetArg("-wallet", "wallet.dat");

    // strWalletFileName must be a plain filename without a directory
    if (strWalletFileName != boost::filesystem::basename(strWalletFileName) + boost::filesystem::extension(strWalletFileName))
        return InitError(strprintf(_("Wallet %s resides outside data directory %s."), strWalletFileName.c_str(), strDataDir.c_str()));

    // Make sure only a single Innova process is using the data directory.
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file)
        fclose(file);

    static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
    if (!lock.try_lock())
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. Innova is probably already running."), strDataDir.c_str()));

    hooks = InitHook(); //Initialized Innova Name Hooks
    if (GetBoolArg("-shrinkdebugfile", !fDebug))
        ShrinkDebugFile();
    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    printf("Innova version %s (%s)\n", FormatFullVersion().c_str(), CLIENT_DATE.c_str());
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) //WIP OpenSSL 1.0.x only, OpenSSL 1.1 not supported yet
    printf("Using OpenSSL version %s\n", SSLeay_version(SSLEAY_VERSION));
#else
    printf("Using OpenSSL version %s\n", OpenSSL_version(OPENSSL_VERSION));
#endif

    printf("Using Boost Version %d.%d.%d\n", BOOST_VERSION / 100000, BOOST_VERSION / 100 % 1000, BOOST_VERSION % 100);

    if (!fLogTimestamps)
        printf("Startup time: %s\n", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
    printf("Default data directory %s\n", GetDefaultDataDir().string().c_str());
    printf("Used data directory %s\n", strDataDir.c_str());
    std::ostringstream strErrors;

    if (mapArgs.count("-collateralnodepaymentskey")) // collateralnode payments priv key
    {
        if (!collateralnodePayments.SetPrivKey(GetArg("-collateralnodepaymentskey", "")))
            return InitError(_("Unable to sign collateralnode payment winner, wrong key?"));
        if (!sporkManager.SetPrivKey(GetArg("-collateralnodepaymentskey", "")))
            return InitError(_("Unable to sign spork message, wrong key?"));
    }

    //ignore collateralnodes below protocol version
    CCollateralNode::minProtoVersion = GetArg("-collateralnodeminprotocol", MIN_MN_PROTO_VERSION);

    // Added maxuploadtarget=MB Tries to keep outbound traffic under the given target (in MiB per 24h), 0 = no limit
    if (mapArgs.count("-maxuploadtarget")) {
        CNode::SetMaxOutboundTarget(GetArg("-maxuploadtarget", 0)*1024*1024);
    }

    if (fDaemon)
        fprintf(stdout, "Innova server starting\n");

    int64_t nStart;
    int64_t nStart2;

    // SMSG_RELAY Node Enum
    if (fNoSmsg)
        nLocalServices &= ~(SMSG_RELAY);

    // Anonymous Ring Signatures ~ I n n o v a - v3.0.0.0
    if (initialiseRingSigs() != 0)
        return InitError("initialiseRingSigs() failed.");


    // ********************************************************* Step 5: verify database integrity

    uiInterface.InitMessage(_("Verifying database integrity..."));

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }

    if (GetBoolArg("-salvagewallet"))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, strWalletFileName, true))
            return false;
    };

    if (filesystem::exists(GetDataDir() / strWalletFileName))
    {
        CDBEnv::VerifyResult r = bitdb.Verify(strWalletFileName, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK)
        {
            string msg = strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
                                     " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                     " your balance or transactions are incorrect you should"
                                     " restore from a backup."), strDataDir.c_str());
            uiInterface.ThreadSafeMessageBox(msg, _("Innova"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        };

        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(_("wallet.dat corrupt, salvage failed"));
    };

    // ********************************************************* Step 6: network initialization

    nBloomFilterElements = GetArg("-bloomfilterelements", 1536);

    int nSocksVersion = GetArg("-socks", 5);

    if (nSocksVersion != 4 && nSocksVersion != 5)
        return InitError(strprintf(_("Unknown -socks proxy version requested: %i"), nSocksVersion));

    // Native Tor Onion Relay Integration
    if(fNativeTor)
    {
        do {
            std::set<enum Network> nets;
            nets.insert(NET_TOR);

            for (int n = 0; n < NET_MAX; n++) {
                enum Network net = (enum Network)n;
                if (!nets.count(net))
                    SetLimited(net);
            }
        } while (false);
    };

    if(!fNativeTor)
    {
        if (mapArgs.count("-onlynet"))
        {
            std::set<enum Network> nets;
            for (std::string snet : mapMultiArgs["-onlynet"])
            {
                enum Network net = ParseNetwork(snet);
                if (net == NET_UNROUTABLE)
                    return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet.c_str()));
                nets.insert(net);
            };
            for (int n = 0; n < NET_MAX; n++)
            {
                enum Network net = (enum Network)n;
                if (!nets.count(net))
                    SetLimited(net);
            };
        };

        CService addrProxy;
        bool fProxy = false;
        if (mapArgs.count("-proxy"))
        {
            addrProxy = CService(mapArgs["-proxy"], 9089);
            if (!addrProxy.IsValid())
                return InitError(strprintf(_("Invalid -proxy address: '%s'"), mapArgs["-proxy"].c_str()));

            if (!IsLimited(NET_IPV4))
                SetProxy(NET_IPV4, addrProxy, nSocksVersion);
            if (nSocksVersion > 4)
            {
                if (!IsLimited(NET_IPV6))
                    SetProxy(NET_IPV6, addrProxy, nSocksVersion);
                SetNameProxy(addrProxy, nSocksVersion);
            };
            fProxy = true;
        };

        // -tor can override normal proxy, -notor disables tor entirely
        if (!(mapArgs.count("-tor") && mapArgs["-tor"] == "0") && (fProxy || mapArgs.count("-tor")))
        {
            CService addrOnion;
            if (!mapArgs.count("-tor"))
                addrOnion = addrProxy;
            else
                addrOnion = CService(mapArgs["-tor"], onion_port);

            if (!addrOnion.IsValid())
                return InitError(strprintf(_("Invalid -tor address: '%s'"), mapArgs["-tor"].c_str()));
            SetProxy(NET_TOR, addrOnion, 5);
            SetReachable(NET_TOR);
        };

    };

    // Native Tor Onion and -tor flag integration
    if(fNativeTor)
    {
        if (mapArgs.count("-tor") && mapArgs["-tor"] != "0")
        {
            CService addrOnion;
            if (mapArgs.count("-tor"))
                addrOnion = CService(mapArgs["-tor"], onion_port);
            else
                addrOnion = CService("127.0.0.1", onion_port);

            if (!addrOnion.IsValid())
                return InitError(strprintf(_("Invalid -tor address: '%s'"), mapArgs["-tor"].c_str()));
            SetProxy(NET_TOR, addrOnion);
            SetReachable(NET_TOR);
        };
    };

    // see Step 2: parameter interactions for more information about these
    if(!fNativeTor) // Available if nativetor is disabled
    {
        fNoListen = !GetBoolArg("-listen", true);
        fDiscover = GetBoolArg("-discover", true);
    };

    fNameLookup = GetBoolArg("-dns", true);
#ifdef USE_UPNP
    fUseUPnP = GetBoolArg("-upnp", USE_UPNP);
#endif

    bool fBound = false;
    if(!fNativeTor)
    {
        if (!fNoListen)
        {
            std::string strError;
            if (mapArgs.count("-bind"))
            {
                for (std::string strBind : mapMultiArgs["-bind"]) {
                    CService addrBind;
                    if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                        return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind.c_str()));
                    fBound |= Bind(addrBind);
                }
            } else
            {
                struct in_addr inaddr_any;
                inaddr_any.s_addr = INADDR_ANY;
                if (!IsLimited(NET_IPV6))
                    fBound |= Bind(CService(in6addr_any, GetListenPort()), false);
                if (!IsLimited(NET_IPV4))
                    fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound);
            };
            if (!fBound)
                return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
        };
    };

#ifdef USE_NATIVETOR
    // Native Tor Integration Continued - I n n o v a v3
    if(fNativeTor)
    {
        CService addrBind;
        if (!Lookup("127.0.0.1", addrBind, GetListenPort(), false))
            return InitError(strprintf(_("Cannot resolve binding address: '%s'"), "127.0.0.1"));

        fBound |= Bind(addrBind);

        if (!fBound)
            return InitError(_("Failed to listen on any port."));

        if (!(mapArgs.count("-tor") && mapArgs["-tor"] != "0")) {
              if (!NewThread(StartTor, NULL))
                      return InitError(_("Error: Could Not Start Tor Onion Node"));
        }
        wait_initialized();

        string automatic_onion;
        filesystem::path const hostname_path = GetDefaultDataDir() / "onion" / "hostname";

        if (!filesystem::exists(hostname_path)) {
            return InitError(_("No external address found."));
        }

        ifstream file(hostname_path.string().c_str());
        file >> automatic_onion;
        AddLocal(CService(automatic_onion, GetListenPort(), fNameLookup), LOCAL_MANUAL);
    };
#endif

    if (mapArgs.count("-externalip"))
    {
        for (string strAddr : mapMultiArgs["-externalip"])
        {
            CService addrLocal(strAddr, GetListenPort(), fNameLookup);
            if (!addrLocal.IsValid())
                return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr.c_str()));
            AddLocal(CService(strAddr, GetListenPort(), fNameLookup), LOCAL_MANUAL);
        };
    };

    if (mapArgs.count("-reservebalance")) // ppcoin: reserve balance amount
    {
        if (!ParseMoney(mapArgs["-reservebalance"], nReserveBalance))
        {
            InitError(_("Invalid amount for -reservebalance=<amount>"));
            return false;
        };
    };

    if (mapArgs.count("-checkpointkey")) // ppcoin: checkpoint master priv key
    {
        if (!Checkpoints::SetCheckpointPrivKey(GetArg("-checkpointkey", "")))
            InitError(_("Unable to sign checkpoint, wrong checkpointkey?\n"));
    };

    for (string strDest : mapMultiArgs["-seednode"])
        AddOneShot(strDest);

    // ********************************************************* Step 7: load blockchain

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    };

    if (GetBoolArg("-loadblockindextest"))
    {
        CTxDB txdb("r");
        txdb.LoadBlockIndex();
        PrintBlockTree();
        return false;
    };

    uiInterface.InitMessage(_("Loading block index..."));
    printf("Loading block index...\n");
    nStart = GetTimeMillis();
    if (!LoadBlockIndex())
        return InitError(_("Error loading blkindex.dat"));


    // as LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill bitcoin-qt during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        printf("Shutdown requested. Exiting.\n");
        return false;
    };
    printf(" block index %15" PRId64"ms\n", GetTimeMillis() - nStart);

    //Create Innova Name index - this must happen before ReacceptWalletTransactions()
    uiInterface.InitMessage(_("Loading name index..."));
    printf("Loading Innova name index...\n");
    nStart2 = GetTimeMillis();

    extern bool createNameIndexFile();
    if (!filesystem::exists(GetDataDir() / "innovanamesindex.dat") && !createNameIndexFile())
    {
        printf("Fatal error: Failed to create innovanamesindex.dat\n");
        return false;
    }

    printf("Loaded Name DB %15" PRId64"ms\n", GetTimeMillis() - nStart2);


    if (GetBoolArg("-printblockindex") || GetBoolArg("-printblocktree"))
    {
        PrintBlockTree();
        return false;
    };

    if (mapArgs.count("-printblock"))
    {
        string strMatch = mapArgs["-printblock"];
        int nFound = 0;
        for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        {
            uint256 hash = (*mi).first;
            if (strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0)
            {
                CBlockIndex* pindex = (*mi).second;
                CBlock block;
                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();
                block.print();
                printf("\n");
                nFound++;
            };
        };
        if (nFound == 0)
            printf("No blocks matching %s were found\n", strMatch.c_str());
        return false;
    };

    // ********************************************************* Step 8: load wallet

    if (GetBoolArg("-zapwallettxes", false)) {
        uiInterface.InitMessage(_("Zapping all transactions from INN wallet..."));

        pwalletMain = new CWallet("wallet.dat");
        DBErrors nZapWalletRet = pwalletMain->ZapWalletTx();
        if (nZapWalletRet != DB_LOAD_OK) {
            uiInterface.InitMessage(_("Error loading wallet.dat: INN Wallet corrupted"));
            return false;
        }

        delete pwalletMain;
        pwalletMain = NULL;
    }

    uiInterface.InitMessage(_("Loading INN wallet..."));
    printf("Loading INN wallet...\n");
    nStart = GetTimeMillis();
    bool fFirstRun = true;
    pwalletMain = new CWallet(strWalletFileName);
    DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)
            strErrors << _("Error loading wallet.dat: Wallet corrupted") << "\n";
        else
        if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            string msg(_("Warning: error reading wallet.dat! All keys read correctly, but transaction data"
                         " or address book entries might be missing or incorrect."));
            uiInterface.ThreadSafeMessageBox(msg, _("Innova"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        }
        else
        if (nLoadWalletRet == DB_TOO_NEW)
            strErrors << _("Error loading wallet.dat: Wallet requires newer version of Innova") << "\n";
        else
        if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            strErrors << _("Wallet needed to be rewritten: restart Innova to complete") << "\n";
            printf("%s", strErrors.str().c_str());
            return InitError(strErrors.str());
        }
        else
        {
            strErrors << _("Error loading wallet.dat") << "\n";
        };
    };

    if (GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            printf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        } else
        {
            printf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        };

        if (nMaxVersion < pwalletMain->GetVersion())
            strErrors << _("Cannot downgrade wallet") << "\n";
        pwalletMain->SetMaxVersion(nMaxVersion);
    };

    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        RandAddSeedPerfmon();

        CPubKey newDefaultKey;
        if (pwalletMain->GetKeyFromPool(newDefaultKey, false))
        {
            pwalletMain->SetDefaultKey(newDefaultKey);
            if (!pwalletMain->SetAddressBookName(pwalletMain->vchDefaultKey.GetID(), ""))
                strErrors << _("Cannot write default address") << "\n";
        };
    };

    printf("%s", strErrors.str().c_str());
    printf("Innova Wallet %15" PRId64"ms\n", GetTimeMillis() - nStart);

    RegisterWallet(pwalletMain);

    CBlockIndex *pindexRescan = pindexBest;
    if (GetBoolArg("-rescan"))
    {
        pindexRescan = pindexGenesisBlock;
    } else
    {
        CWalletDB walletdb(strWalletFileName);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = locator.GetBlockIndex();
    };

    if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
    {
        uiInterface.InitMessage(_("Rescanning..."));
        printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        pwalletMain->ScanForWalletTransactions(pindexRescan, true);
        printf(" rescan      %15" PRId64"ms\n", GetTimeMillis() - nStart);
    };

    // Add wallet transactions that aren't already in a block to mapTransactions
    pwalletMain->ReacceptWalletTransactions();

    // Init Bloom Filters
    //pwalletMain->InitBloomFilter();

    // ********************************************************* Step 9: import blocks

    if (mapArgs.count("-loadblock"))
    {
        uiInterface.InitMessage(_("Importing blockchain data file."));

        for (string strFile : mapMultiArgs["-loadblock"])
        {
            FILE *file = fopen(strFile.c_str(), "rb");
            if (file)
                LoadExternalBlockFile(file);
        }
        exit(0);
    }

    filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (filesystem::exists(pathBootstrap)) {
        uiInterface.InitMessage(_("Importing bootstrap blockchain data file."));

        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LoadExternalBlockFile(file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        }
    }

    // ********************************************************* Step 10: load peers

    uiInterface.InitMessage(_("Loading addresses..."));
    printf("Loading addresses...\n");
    nStart = GetTimeMillis();

    {
        CAddrDB adb;
        if (!adb.Read(addrman))
            printf("Invalid or missing peers.dat; recreating\n");
    }

    printf("Loaded %i addresses from peers.dat  %" PRId64"ms\n",
           addrman.size(), GetTimeMillis() - nStart);


    // ********************************************************* Step 10.1: startup secure messaging

    SecureMsgStart(fNoSmsg, GetBoolArg("-smsgscanchain"));

    // ********************************************************* Step 11: start node

    if (!CheckDiskSpace())
    {
        return InitError(_("Error: not enough disk space to start Innova."));
    }

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

    fCollateralNode = GetBoolArg("-collateralnode", false);
    strCollateralNodePrivKey = GetArg("-collateralnodeprivkey", "");
    if(fCollateralNode) {
        printf("Collateralnode Enabled\n");
        strCollateralNodeAddr = GetArg("-collateralnodeaddr", "");

        printf("Collateralnode address: %s\n", strCollateralNodeAddr.c_str());

        if(!strCollateralNodeAddr.empty()){
            CService addrTest = CService(strCollateralNodeAddr);
            if (!addrTest.IsValid()) {
                return InitError("Invalid -collateralnodeaddr address: " + strCollateralNodeAddr);
            }
        }

        if(strCollateralNodePrivKey.empty()){
            return InitError(_("You must specify a collateralnodeprivkey in the configuration. Please see documentation for help."));
        }
    }

    if(!strCollateralNodePrivKey.empty()){
        std::string errorMessage;

        CKey key;
        CPubKey pubkey;

        if(!colLateralSigner.SetKey(strCollateralNodePrivKey, errorMessage, key, pubkey))
        {
            return InitError(_("Invalid collateralnodeprivkey. Please see documenation."));
        }

        activeCollateralnode.pubKeyCollateralnode = pubkey;

    }

    if (pwalletMain) {
        if(GetBoolArg("-cnconflock", true)) {
            LOCK(pwalletMain->cs_wallet);
            printf("Locking Collateralnodes:\n");
            uint256 mnTxHash;
            int outputIndex;
            for (CCollateralnodeConfig::CCollateralnodeEntry mne : collateralnodeConfig.getEntries()) {
                mnTxHash.SetHex(mne.getTxHash());
                outputIndex = boost::lexical_cast<unsigned int>(mne.getOutputIndex());
                COutPoint outpoint = COutPoint(mnTxHash, outputIndex);
                // don't lock non-spendable outpoint (i.e. it's already spent or it's not from this wallet at all)
                if(pwalletMain->IsMine(CTxIn(outpoint)) != ISMINE_SPENDABLE) {
                    printf("  %s %s - IS NOT SPENDABLE, was not locked\n", mne.getTxHash().c_str(), mne.getOutputIndex().c_str());
                    continue;
                }
                pwalletMain->LockCoin(outpoint);
                printf("  %s %s - locked successfully\n", mne.getTxHash().c_str(), mne.getOutputIndex().c_str());
            }
        }
    }

    // Add any collateralnode.conf collateralnodes to the adrenaline nodes
    for (CCollateralnodeConfig::CCollateralnodeEntry mne : collateralnodeConfig.getEntries())
    {
        CAdrenalineNodeConfig c(mne.getAlias(), mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex());
        CWalletDB walletdb(strWalletFileName);

        // add it to wallet db if doesn't exist already
        if (!walletdb.ReadAdrenalineNodeConfig(c.sAddress, c))
        {
            if (!walletdb.WriteAdrenalineNodeConfig(c.sAddress, c))
                printf("Could not add collateralnode config %s to adrenaline nodes.", c.sAddress.c_str());
        }
        // add it to adrenaline nodes if it doesn't exist already
        if (!pwalletMain->mapMyAdrenalineNodes.count(c.sAddress))
            pwalletMain->mapMyAdrenalineNodes.insert(make_pair(c.sAddress, c));

        uiInterface.NotifyAdrenalineNodeChanged(c);
    }

    //Threading still needs reworking
    NewThread(ThreadCheckCollaTeralPool, NULL);

    RandAddSeedPerfmon();

    // reindex addresses found in blockchain
    if(GetBoolArg("-reindexaddr", false))
    {
        uiInterface.InitMessage(_("Rebuilding address index..."));
        nStart = GetTimeMillis();
        CBlockIndex *pblockAddrIndex = pindexBest;
    CTxDB txdbAddr("rw");
    while(pblockAddrIndex)
    {
        uiInterface.InitMessage(strprintf("Rebuilding address index, Block %i", pblockAddrIndex->nHeight));
        bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true);
        CBlock pblockAddr;
        if(pblockAddr.ReadFromDisk(pblockAddrIndex, true))
            pblockAddr.RebuildAddressIndex(txdbAddr);
        pblockAddrIndex = pblockAddrIndex->pprev;
    }

    printf("Rebuilt address index of %i blocks in %" PRId64"ms\n",
           pblockAddrIndex->nHeight, GetTimeMillis() - nStart);
    }

    //// debug print
    printf("mapBlockIndex.size() = %" PRIszu"\n",   mapBlockIndex.size());
    printf("nBestHeight = %d\n",            nBestHeight);
    printf("setKeyPool.size() = %" PRIszu"\n",      pwalletMain->setKeyPool.size());
    printf("mapWallet.size() = %" PRIszu"\n",       pwalletMain->mapWallet.size());
    printf("mapAddressBook.size() = %" PRIszu"\n",  pwalletMain->mapAddressBook.size());

    if(fNativeTor)
        printf("Native Tor Onion Relay Node Enabled\n");
    else
        printf("Native Tor Onion Relay Disabled, Using Regular Peers...\n");

    if (fDebug)
        printf("Debugging is Enabled.\n");
	else
        printf("Debugging is not enabled.\n");

    if (!NewThread(StartNode, NULL))
        InitError(_("Error: could not start node"));

    if (fServer)
        NewThread(ThreadRPCServer, NULL);

    // Init Innova DNS.
    if (GetBoolArg("-idns", true))
    {
        #define IDNS_PORT 6565
        int port = GetArg("-idnsport", IDNS_PORT);
        int verbose = GetArg("-idnsverbose", 1);
        if (port <= 0)
            port = IDNS_PORT;
        string suffix  = GetArg("-idnssuffix", "");
        string bind_ip = GetArg("-idnsbindip", "");
        string allowed = GetArg("-idnsallowed", "");
        string localcf = GetArg("-idnslocalcf", "");
        idns = new IDns(bind_ip.c_str(), port,
        suffix.c_str(), allowed.c_str(), localcf.c_str(), verbose);
        printf("Innova DNS Server started on %d!\n", port);
    }

    // ********************************************************* Step 12: finished

    uiInterface.InitMessage(_("Done loading"));
    printf("Done loading\n");

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

#if !defined(QT_GUI)
    // Loop until process is exit()ed from shutdown() function,
    // called from ThreadRPCServer thread when a "stop" command is received.
    if(idns) {
	    idns->Run();
    }
    while (1)
        //MilliSleep(5000);
        sleep(5);
#endif

    fSuccessfullyLoaded = true;

    return true;
}
