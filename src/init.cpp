// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2017-2021 The Denarius developers
// Copyright (c) 2019-2026 The Innova developers
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
#include "innova_spinner_frames.h"
#include "ringsig.h"
#include "nullsend.h"
#include "idns.h"
#include "bootstrap.h"
#include "zkproof.h"
#include "dandelion.h"
#include "finality.h"
#include "dag.h"

#ifdef USE_NATIVETOR
#include "tor/anonymize.h" //Tor native optional integration (Flag -nativetor=1)
#endif

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <atomic>
#include <algorithm>
#include <vector>
#include <cstring>
#include <limits>

#ifndef WIN32
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif


using namespace std;
namespace fs = boost::filesystem;

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

        CZKContext::Shutdown();

        if (fHybridSPV && pwalletMain)
        {
            printf("Saving SPV UTXO cache...\n");
            pwalletMain->SaveSPVUtxoCache();
        }

        // Save DAG clean height for incremental rebuild on restart
        if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_DAG)
        {
            CTxDB txdbClean;
            txdbClean.WriteDAGCleanHeight(pindexBest->nHeight);
            printf("IDAG: Saved DAG clean height %d\n", pindexBest->nHeight);
        }

        FlushIBDBatch();

        if(idns) {
            delete idns;
        }
        Finalise();
        // Drop the pid file last, once the databases are flushed and the datadir lock is
        // about to go. Left behind, it names a process that has exited, so anything that
        // reads it to decide whether a node is still running gets a stale answer.
        try
        {
            fs::remove(GetPidFile());
        }
        catch (const std::exception& e)
        {
            printf("Shutdown : could not remove the pid file: %s\n", e.what());
        }
        /*
        SecureMsgShutdown();

        mempool.AddTransactionsUpdated(1);
//        CTxDB().Close();
        bitdb.Flush(false);
        StopNode();
        bitdb.Flush(true);
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
namespace
{
class CStartupSpinner
{
public:
    CStartupSpinner() : fEnabled(false), fStop(false), nPrintedLines(0)
    {
#ifndef WIN32
        if (fDaemon)
            return;
        if (!isatty(STDERR_FILENO))
            return;
#endif
        fEnabled = true;
        spinnerThread = std::thread(&CStartupSpinner::Run, this);
    }

    ~CStartupSpinner()
    {
        Stop();
    }

private:
    static const int kSpinnerLineCount = INNOVA_SPINNER_LINE_COUNT;

    int GetFrameWidth(int frame) const
    {
        int width = 0;
        for (int i = 0; i < kSpinnerLineCount; ++i)
        {
            int lineWidth = static_cast<int>(strlen(INNOVA_SPINNER_FRAMES[frame][i]));
            if (lineWidth > width)
                width = lineWidth;
        }
        return width;
    }

    void GetTerminalSize(int& rows, int& cols) const
    {
        rows = 0;
        cols = 0;
#ifndef WIN32
        struct winsize ws;
        if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0)
        {
            if (ws.ws_row > 0)
                rows = ws.ws_row;
            if (ws.ws_col > 0)
                cols = ws.ws_col;
        }
#endif
    }

    void BuildScaledFrame(int frame, int targetWidth, int targetHeight, std::vector<std::string>& out) const
    {
        int srcHeight = kSpinnerLineCount;
        int srcWidth = GetFrameWidth(frame);
        if (targetWidth < 1)
            targetWidth = 1;
        if (targetHeight < 1)
            targetHeight = 1;
        out.clear();
        out.reserve(targetHeight);
        for (int y = 0; y < targetHeight; ++y)
        {
            int srcY = (y * srcHeight) / targetHeight;
            const char* srcLine = INNOVA_SPINNER_FRAMES[frame][srcY];
            int srcLineWidth = static_cast<int>(strlen(srcLine));
            std::string line;
            line.reserve(targetWidth);
            for (int x = 0; x < targetWidth; ++x)
            {
                int srcX = (x * srcWidth) / targetWidth;
                char ch = ' ';
                if (srcX < srcLineWidth)
                    ch = srcLine[srcX];
                line.push_back(ch);
            }
            out.push_back(line);
        }
    }

    void Stop()
    {
        if (!fEnabled)
            return;

        fStop = true;
        if (spinnerThread.joinable())
            spinnerThread.join();
        Clear();
    }

    void Clear()
    {
        int lines = nPrintedLines > 0 ? nPrintedLines : kSpinnerLineCount;
        for (int i = 0; i < lines; ++i)
        {
            fprintf(stderr, "\r\033[2K");
            if (i + 1 < lines)
                fprintf(stderr, "\n");
        }
        if (lines > 1)
            fprintf(stderr, "\033[%dA", lines - 1);
        fprintf(stderr, "\r");
        fflush(stderr);
    }

    void PrintFrame(int frame)
    {
        int rows = 0;
        int cols = 0;
        GetTerminalSize(rows, cols);
        int srcHeight = kSpinnerLineCount;
        int srcWidth = GetFrameWidth(frame);
        int maxRows = rows > 1 ? rows - 1 : rows;
        int maxCols = cols > 0 ? cols : srcWidth;
        double scale = 1.0;
        if ((maxRows > 0 && srcHeight > maxRows) || (maxCols > 0 && srcWidth > maxCols))
        {
            double scaleH = maxRows > 0 ? static_cast<double>(maxRows) / srcHeight : 1.0;
            double scaleW = maxCols > 0 ? static_cast<double>(maxCols) / srcWidth : 1.0;
            scale = scaleH < scaleW ? scaleH : scaleW;
            if (scale > 1.0)
                scale = 1.0;
        }
        int targetHeight = static_cast<int>(srcHeight * scale + 0.5);
        int targetWidth = static_cast<int>(srcWidth * scale + 0.5);
        if (targetHeight < 2)
            targetHeight = 2;
        if (targetWidth < 2)
            targetWidth = 2;
        if (nPrintedLines > 0 && nPrintedLines != targetHeight)
            Clear();
        if (targetHeight != srcHeight || targetWidth != srcWidth)
        {
            std::vector<std::string> scaled;
            BuildScaledFrame(frame, targetWidth, targetHeight, scaled);
            for (int i = 0; i < targetHeight; ++i)
                fprintf(stderr, "\r\033[2K%s\n", scaled[i].c_str());
        } else
        {
            for (int i = 0; i < kSpinnerLineCount; ++i)
                fprintf(stderr, "\r\033[2K%s\n", INNOVA_SPINNER_FRAMES[frame][i]);
        }
        nPrintedLines = targetHeight;
        fprintf(stderr, "\033[%dA", targetHeight);
        fflush(stderr);
    }

    void Run()
    {
        int frame = 0;
        while (!fStop)
        {
            PrintFrame(frame);
            frame = (frame + 1) % INNOVA_SPINNER_FRAME_COUNT;
            MilliSleep(97);
        }
    }

    bool fEnabled;
    std::atomic<bool> fStop;
    std::thread spinnerThread;
    int nPrintedLines;
};
}

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
        if (!fs::is_directory(GetDataDir(false)))
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
    if (fDaemon && mapArgs.count("-replayblocks"))
    {
        fprintf(stderr,
                "Error: -replayblocks must run in the foreground so its exit status is authoritative; use -daemon=0\n");
        return false;
    }
    if (fDaemon)
    {
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
        RAND_poll();
#endif

        pid_t sid = setsid();
        if (sid < 0)
            fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
    }
#endif

        CStartupSpinner startupSpinner;
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
        "  -dbcache=<n>           " + _("Set database cache size in megabytes (default: 300)") + "\n" +
        "  -dblogsize=<n>         " + _("Set database disk log size in megabytes (default: 100)") + "\n" +
        "  -timeout=<n>           " + _("Specify connection timeout in milliseconds (default: 5000)") + "\n" +
        "  -proxy=<ip:port>       " + _("Connect through socks proxy") + "\n" +
        "  -socks=<n>             " + _("Select the version of socks proxy to use (4-5, default: 5)") + "\n" +
        "  -tor=<ip:port>         " + _("Use proxy to reach tor hidden services (default: same as -proxy)") + "\n"
        "  -dns                   " + _("Allow DNS lookups for -addnode, -seednode and -connect") + "\n" +
        "  -port=<port>           " + _("Listen for connections on <port> (default: 14530 or testnet: 15539)") + "\n" +
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
        "  -stakingmode=<mode>    " + _("Staking mode: transparent or cold; legacy nullstake/coldprivate are regtest-only pending privacy vNext (default: transparent)") + "\n" +
        "  -finalityvotemode=<m>  " + _("Post-DAG finality voting mode: auto or transparent; legacy private modes are regtest-only pending privacy vNext (default: auto)") + "\n" +
        "  -finalitytallymode=<m> " + _("Hidden finality tally mode: off, committee, auto (default: off)") + "\n" +
        "  -finalitytallypubkey=<key> " + _("Advertise a finality tally committee public key") + "\n" +
        "  -finalitytallyprivkey=<key> " + _("Enable local finality tally share handling with a private key") + "\n" +
        "  -finalitytallythreshold=<m-of-n> " + _("Finality tally committee threshold descriptor") + "\n" +

        "\n" + _("SPV (Light Client) options:") + "\n" +
        "  -spv                   " + _("Run in SPV mode (light client, headers only)") + "\n" +
        "  -spvstartheight=<n>    " + _("Start SPV mode from block height <n> (default: 0)") + "\n" +
        "  -hybridspv             " + _("Run in hybrid SPV mode (optimized for constrained devices like Pi)") + "\n" +
        "  -maxheaders=<n>       " + _("Maximum block headers to keep in memory in SPV mode (default: 50000)") + "\n" +
        "  -spvutxocachesize=<n> " + _("Maximum SPV UTXO cache entries (default: 10000, Pi: 1000)") + "\n" +
        "  -cnsyncslots=<n>      " + _("Collateral node slots reserved for sync during IBD (default: 4)") + "\n" +
        "  -mixingpoolsize=<n>   " + _("NullSend mixing pool size (2-16, default: 5)") + "\n" +
        "  -rpcratelimit=<n>     " + _("RPC requests per second per IP (0=disabled, default: 100)") + "\n" +
        "  -minstakeinterval=<n>  " + _("Minimum time in seconds between successful stakes (default: 30)") + "\n" +
        "  -minersleep=<n>        " + _("Milliseconds between stake attempts. Lowering this param will not result in more stakes. (default: 1000)") + "\n" +
        "  -synctime              " + _("Sync time with other nodes. Disable if time on your system is precise e.g. syncing with NTP (default: 1)") + "\n" +
        "  -cppolicy              " + _("Sync checkpoints policy (default: strict)") + "\n" +
        "  -banscore=<n>          " + _("Threshold for disconnecting misbehaving peers (default: 100)") + "\n" +
        "  -bantime=<n>           " + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)") + "\n" +
        "  -softbantime=<n>       " + _("Number of seconds to keep soft banned peers from reconnecting (default: 3600)") + "\n" +
        "  -maxreceivebuffer=<n>  " + _("Maximum per-connection receive soft buffer, <n>*1000 bytes (default: 50000)") + "\n" +
        "  -maxsendbuffer=<n>     " + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 10000)") + "\n" +
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
        "  -regtest               " + _("Enter regression test mode (instant blocks, no stake age)") + "\n" +
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
        "  -rpcport=<port>        " + _("Listen for JSON-RPC connections on <port> (default: 14531 or testnet: 15531)") + "\n" +
        "  -rpcallowip=<ip>       " + _("Allow JSON-RPC connections from specified IP address") + "\n" +
        "  -rpcconnect=<ip>       " + _("Send commands to node running on <ip> (default: 127.0.0.1)") + "\n" +
        "  -disablerpchelp        " + _("Disable full RPC command listing in help (security)") + "\n" +
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
        "  -replayblocks=<dir>    " + _("Replay every blkNNNN.dat in <dir> through full validation (requires -replayexpectedheight/-replayexpectedhash), then exit") + "\n" +
        "  -replayexpectedheight=<n> " + _("Required trusted terminal height for -replayblocks") + "\n" +
        "  -replayexpectedhash=<hex> " + _("Required trusted terminal block hash for -replayblocks") + "\n" +
        "  -fullreplayverify      " + _("Force full ECDSA verification of all historic blocks (no checkpoint signature skip)") + "\n" +
        "  -acceptepochstate      " + _("Grandfather pre-marker epoch-state records as deterministic (only if they were written by a deterministic-anchor build; otherwise resync)") + "\n" +
        "  -regtestboundaryb=<n>  " + _("Regtest only: Boundary-B rehearsal activation height") + "\n" +
        "  -regtestiv5rehearsal   " + _("Regtest only: treat vNext as consensus ready for state-transition rehearsal (no IV5 verifier)") + "\n" +

        "\n" + _("Block creation options:") + "\n" +
        "  -blockminsize=<n>      "   + _("Set minimum block size in bytes (default: 0)") + "\n" +
        "  -blockmaxsize=<n>      "   + _("Set maximum block size in bytes (default: 250000)") + "\n" +
        "  -blockprioritysize=<n> "   + _("Set maximum size of high-priority/low-fee transactions in bytes (default: 27000)") + "\n" +
        "  -maxorphantx=<n>       "   + strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"), DEFAULT_MAX_ORPHAN_TRANSACTIONS) + "\n" +
        "  -maxorphanblocks=<n>   "   + strprintf(_("Keep at most <n> unconnectable blocks in memory (default: %u)"), DEFAULT_MAX_ORPHAN_BLOCKS) + "\n" +
        "  -maxmempool=<n>        "   + strprintf(_("Keep the transaction memory pool below <n> megabytes (default: %u)"), DEFAULT_MAX_MEMPOOL_SIZE) + "\n" +

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

namespace
{
struct CShieldedWalletRecoveryWork
{
    CBlockIndex* pindex;
    bool fConnect;
    std::set<uint256> setDAGSkippedTxs;

    CShieldedWalletRecoveryWork(CBlockIndex* pindexIn, bool fConnectIn)
        : pindex(pindexIn), fConnect(fConnectIn) {}
};

bool SameShieldedWalletRecoveryRecordForInit(
    const CShieldedWalletRecoveryRecord& a,
    const CShieldedWalletRecoveryRecord& b)
{
    return a.nSchema == b.nSchema &&
           a.hashOldTip == b.hashOldTip &&
           a.hashFork == b.hashFork &&
           a.hashNewTip == b.hashNewTip &&
           a.nDisconnect == b.nDisconnect &&
           a.nConnect == b.nConnect &&
           a.hashEffectPlan == b.hashEffectPlan;
}

bool RecoverPendingShieldedWalletTransitionImpl(
    CWallet* pwallet,
    bool& fPendingAcknowledgementOut,
    CShieldedWalletRecoveryRecord& pendingAcknowledgementOut,
    std::string& strErrorOut)
{
    strErrorOut.clear();
    fPendingAcknowledgementOut = false;
    pendingAcknowledgementOut = CShieldedWalletRecoveryRecord();
    if (!pwallet)
    {
        strErrorOut = "shielded wallet recovery requires a loaded wallet";
        return false;
    }

    CTxDB txdb("r+");
    CShieldedWalletRecoveryRecord record;
    const TxDBReadStatus status =
        txdb.ReadShieldedWalletRecoveryStatus(record);
    if (status == TXDB_READ_NOT_FOUND)
        return true;
    if (status != TXDB_READ_FOUND)
    {
        strErrorOut = "shielded wallet recovery outbox is corrupt or unreadable";
        return false;
    }

    uint256 hashPersistedBest;
    if (!txdb.ReadHashBestChain(hashPersistedBest) ||
        hashPersistedBest != record.hashNewTip || !pindexBest ||
        !pindexBest->phashBlock ||
        pindexBest->GetBlockHash() != record.hashNewTip)
    {
        strErrorOut = "shielded wallet recovery target does not match the durable canonical tip";
        return false;
    }

    std::vector<CShieldedWalletRecoveryWork> vDisconnect;
    std::vector<CShieldedWalletRecoveryWork> vConnectReverse;
    try
    {
        LOCK(cs_main);
        if ((size_t)record.nDisconnect > mapBlockIndex.size() ||
            (size_t)record.nConnect > mapBlockIndex.size())
        {
            strErrorOut = "shielded wallet recovery path count exceeds the loaded block index";
            return false;
        }

        CBlockIndex* pindexOld = NULL;
        CBlockIndex* pindexFork = NULL;
        CBlockIndex* pindexNew = NULL;
        if (record.hashOldTip != 0)
        {
            std::map<uint256, CBlockIndex*>::const_iterator it =
                mapBlockIndex.find(record.hashOldTip);
            if (it == mapBlockIndex.end())
            {
                strErrorOut = "shielded wallet recovery old tip is absent from the block index";
                return false;
            }
            pindexOld = it->second;
        }
        if (record.hashFork != 0)
        {
            std::map<uint256, CBlockIndex*>::const_iterator it =
                mapBlockIndex.find(record.hashFork);
            if (it == mapBlockIndex.end())
            {
                strErrorOut = "shielded wallet recovery fork is absent from the block index";
                return false;
            }
            pindexFork = it->second;
        }
        {
            std::map<uint256, CBlockIndex*>::const_iterator it =
                mapBlockIndex.find(record.hashNewTip);
            if (it == mapBlockIndex.end())
            {
                strErrorOut = "shielded wallet recovery new tip is absent from the block index";
                return false;
            }
            pindexNew = it->second;
        }
        if (pindexNew != pindexBest || !pindexNew->IsInMainChain() ||
            (pindexFork && !pindexFork->IsInMainChain()))
        {
            strErrorOut = "shielded wallet recovery topology is not anchored in the canonical chain";
            return false;
        }

        vDisconnect.reserve(record.nDisconnect);
        CBlockIndex* pindexWalk = pindexOld;
        for (uint32_t i = 0; i < record.nDisconnect; ++i)
        {
            if (!pindexWalk || pindexWalk == pindexFork ||
                !pindexWalk->phashBlock)
            {
                strErrorOut = "shielded wallet recovery disconnect path is truncated";
                return false;
            }
            vDisconnect.push_back(
                CShieldedWalletRecoveryWork(pindexWalk, false));
            pindexWalk = pindexWalk->pprev;
        }
        if (pindexWalk != pindexFork)
        {
            strErrorOut = "shielded wallet recovery disconnect count does not reach its recorded fork";
            return false;
        }

        vConnectReverse.reserve(record.nConnect);
        pindexWalk = pindexNew;
        for (uint32_t i = 0; i < record.nConnect; ++i)
        {
            if (!pindexWalk || pindexWalk == pindexFork ||
                !pindexWalk->phashBlock || !pindexWalk->IsInMainChain())
            {
                strErrorOut = "shielded wallet recovery connect path is truncated or non-canonical";
                return false;
            }
            vConnectReverse.push_back(
                CShieldedWalletRecoveryWork(pindexWalk, true));
            pindexWalk = pindexWalk->pprev;
        }
        if (pindexWalk != pindexFork)
        {
            strErrorOut = "shielded wallet recovery connect count does not reach its recorded fork";
            return false;
        }
        std::reverse(vConnectReverse.begin(), vConnectReverse.end());

        std::vector<CShieldedWalletEffectDigestEntry> vDigestEntries;
        vDigestEntries.reserve(vDisconnect.size() + vConnectReverse.size());
        for (size_t phase = 0; phase < 2; ++phase)
        {
            std::vector<CShieldedWalletRecoveryWork>& vWork =
                phase == 0 ? vDisconnect : vConnectReverse;
            for (std::vector<CShieldedWalletRecoveryWork>::iterator it =
                     vWork.begin(); it != vWork.end(); ++it)
            {
                CBlock block;
                if (!block.ReadFromDisk(it->pindex, true) ||
                    block.GetHash() != it->pindex->GetBlockHash())
                {
                    strErrorOut = strprintf(
                        "shielded wallet recovery block data is missing or corrupt at height %d",
                        it->pindex->nHeight);
                    return false;
                }
                it->setDAGSkippedTxs.clear();
                if (it->pindex->nHeight >= FORK_HEIGHT_DAG)
                {
                    std::string strActiveSetError;
                    const TxDBReadStatus activeSetStatus =
                        txdb.ReadDAGSkippedTxsStatus(
                            block, it->setDAGSkippedTxs,
                            strActiveSetError);
                    if (activeSetStatus != TXDB_READ_FOUND)
                    {
                        strErrorOut = strprintf(
                            "shielded wallet recovery exact DAG active set is %s "
                            "at height %d%s%s",
                            activeSetStatus == TXDB_READ_NOT_FOUND
                                ? "missing" : "corrupt",
                            it->pindex->nHeight,
                            strActiveSetError.empty() ? "" : ": ",
                            strActiveSetError.c_str());
                        return false;
                    }
                }
                vDigestEntries.push_back(CShieldedWalletEffectDigestEntry(
                    it->fConnect, it->pindex->GetBlockHash(),
                    it->setDAGSkippedTxs));
            }
        }
        if (ComputeShieldedWalletEffectPlanDigest(vDigestEntries) !=
            record.hashEffectPlan)
        {
            strErrorOut = "shielded wallet recovery plan digest does not match the committed transition";
            return false;
        }
    }
    catch (const std::exception& e)
    {
        strErrorOut = strprintf("shielded wallet recovery plan construction failed: %s",
                                e.what());
        return false;
    }
    catch (...)
    {
        strErrorOut = "shielded wallet recovery plan construction failed";
        return false;
    }

    printf("Recovering shielded wallet across committed transition: disconnect=%u connect=%u\n",
           record.nDisconnect, record.nConnect);
    for (size_t phase = 0; phase < 2; ++phase)
    {
        std::vector<CShieldedWalletRecoveryWork>& vWork =
            phase == 0 ? vDisconnect : vConnectReverse;
        for (std::vector<CShieldedWalletRecoveryWork>::const_iterator it =
                 vWork.begin(); it != vWork.end(); ++it)
        {
            CBlock block;
            if (!block.ReadFromDisk(it->pindex, true) ||
                block.GetHash() != it->pindex->GetBlockHash())
            {
                strErrorOut = strprintf(
                    "shielded wallet recovery could not reread block at height %d",
                    it->pindex->nHeight);
                return false;
            }
            std::string strWalletError;
            bool fApplied = true;
            if (it->pindex->nHeight >= FORK_HEIGHT_SHIELDED)
            {
                fApplied = it->fConnect
                    ? pwallet->ApplyShieldedBlockRecoveryChecked(
                          block, it->pindex, it->setDAGSkippedTxs,
                          strWalletError)
                    : pwallet->DisconnectShieldedBlockRecoveryChecked(
                          block, it->pindex, strWalletError);
            }
            if (fApplied && !it->fConnect)
                fApplied = pwallet->DisconnectAuxiliaryBlockRecoveryChecked(
                    block, it->setDAGSkippedTxs, strWalletError);
            if (!fApplied)
            {
                strErrorOut = strprintf(
                    "shielded wallet recovery %s failed at height %d: %s",
                    it->fConnect ? "connect" : "disconnect",
                    it->pindex->nHeight, strWalletError.c_str());
                return false;
            }
        }
    }

    std::string strReconcileError;
    if (record.nDisconnect > 0 &&
        !pwallet->ReconcileShieldedNoteSpentStateChecked(
            txdb, pindexBest->nHeight, strReconcileError))
    {
        strErrorOut = strprintf(
            "shielded wallet recovery spent-state reconciliation failed: %s",
            strReconcileError.c_str());
        return false;
    }

    // Do not acknowledge here: the LevelDB outbox stays live until replay, rescan, the wallet
    // locator and the Berkeley DB log flush have all succeeded.
    CShieldedWalletRecoveryRecord currentRecord;
    if (txdb.ReadShieldedWalletRecoveryStatus(currentRecord) !=
            TXDB_READ_FOUND ||
        !SameShieldedWalletRecoveryRecordForInit(currentRecord, record))
    {
        strErrorOut = "shielded wallet recovery outbox changed before acknowledgement";
        return false;
    }
    pendingAcknowledgementOut = record;
    fPendingAcknowledgementOut = true;
    printf("Shielded wallet recovery replay completed at %s; "
           "acknowledgement deferred until auxiliary rescan durability\n",
           record.hashNewTip.ToString().substr(0, 20).c_str());
    return true;
}

bool RecoverPendingShieldedWalletTransition(
    CWallet* pwallet,
    bool& fPendingAcknowledgementOut,
    CShieldedWalletRecoveryRecord& pendingAcknowledgementOut,
    std::string& strErrorOut)
{
    fPendingAcknowledgementOut = false;
    pendingAcknowledgementOut = CShieldedWalletRecoveryRecord();
    try
    {
        return RecoverPendingShieldedWalletTransitionImpl(
            pwallet, fPendingAcknowledgementOut,
            pendingAcknowledgementOut, strErrorOut);
    }
    catch (const std::exception& e)
    {
        strErrorOut = strprintf("shielded wallet recovery raised an exception: %s",
                                e.what());
        return false;
    }
    catch (...)
    {
        strErrorOut = "shielded wallet recovery raised an unknown exception";
        return false;
    }
}

bool AcknowledgePendingShieldedWalletTransition(
    const CShieldedWalletRecoveryRecord& expected,
    std::string& strErrorOut)
{
    strErrorOut.clear();
    if (!expected.IsValid())
    {
        strErrorOut = "pending shielded-wallet acknowledgement is invalid";
        return false;
    }

    // Wallet/name Berkeley DB uses DB_TXN_WRITE_NOSYNC.  The wallet's final
    // best-block locator is written before this call; flush every preceding
    // auxiliary mutation and the locator before the LevelDB outbox can clear.
    if (!bitdb.FlushLog())
    {
        strErrorOut = "could not flush auxiliary database logs before shielded-wallet acknowledgement";
        return false;
    }

    CTxDB txdb("r+");
    if (!txdb.AcknowledgeShieldedWalletRecovery(expected))
    {
        strErrorOut = "shielded-wallet recovery outbox is missing, corrupt, changed, or could not be durably acknowledged";
        return false;
    }
    printf("Shielded wallet recovery acknowledged at %s\n",
           expected.hashNewTip.ToString().substr(0, 20).c_str());
    return true;
}

bool HasPendingOrCorruptShieldedWalletRecovery(std::string& strErrorOut)
{
    strErrorOut.clear();
    try
    {
        CTxDB txdb("r");
        CShieldedWalletRecoveryRecord record;
        const TxDBReadStatus status =
            txdb.ReadShieldedWalletRecoveryStatus(record);
        if (status == TXDB_READ_NOT_FOUND)
            return false;
        strErrorOut = status == TXDB_READ_FOUND
            ? "a committed shielded-wallet transition is pending"
            : "the shielded-wallet recovery outbox is corrupt or unreadable";
        return true;
    }
    catch (const std::exception& e)
    {
        strErrorOut = strprintf("could not inspect the shielded-wallet recovery outbox: %s",
                                e.what());
        return true;
    }
    catch (...)
    {
        strErrorOut = "could not inspect the shielded-wallet recovery outbox";
        return true;
    }
}
} // namespace

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
// -replayblocks is a release gate: a run that cannot complete must exit
// non-zero. InitError alone unwinds into Shutdown(), which exits 0.
static bool ReplayFail(const std::string& strMsg)
{
    printf("-replayblocks FAILED: %s\n", strMsg.c_str());
    fprintf(stderr, "-replayblocks FAILED: %s\n", strMsg.c_str());
    exit(1);
    return false;
}

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
    nMinStakeInterval = std::max((int64_t)0, std::min((int64_t)600, GetArg("-minstakeinterval", 30)));
    nMinerSleep = std::max((int64_t)100, std::min((int64_t)60000, GetArg("-minersleep", 5000)));

    // Largest block you're willing to create (adaptive post-DAG, default half of ceiling)
    nBlockMaxSize = GetArg("-blockmaxsize", ADAPTIVE_BLOCK_CEILING / 2);
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(ADAPTIVE_BLOCK_CEILING - 1000), nBlockMaxSize));

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
    fRegTest = GetBoolArg("-regtest");

    if (fTestNet && fRegTest)
    {
        return InitError(_("Cannot use -testnet and -regtest together"));
    }

    if (fRegTest)
    {
        SoftSetBoolArg("-dnsseed", false);
        SoftSetBoolArg("-onionseed", false);
        SoftSetBoolArg("-listen", true);
    }

    // Boundary-B rehearsal knobs. Regtest only, and independent by design: a
    // height must never imply the vNext implementation is consensus ready.
    if (mapArgs.count("-regtestboundaryb") || GetBoolArg("-regtestiv5rehearsal", false))
    {
        if (!fRegTest)
            return InitError(_("-regtestboundaryb and -regtestiv5rehearsal require -regtest"));
        if (mapArgs.count("-regtestboundaryb"))
        {
            const int64_t nB = GetArg("-regtestboundaryb", (int64_t)PRIVACY_VNEXT_HEIGHT_UNSET);
            if (nB < 0 || nB > (int64_t)PRIVACY_VNEXT_HEIGHT_UNSET)
                return InitError(_("-regtestboundaryb is out of range"));
            nRegtestBoundaryBHeight = (int)nB;
        }
        fRegtestShieldedVNextRehearsal = GetBoolArg("-regtestiv5rehearsal", false);
        printf("Boundary-B rehearsal: height=%d ready=%d (regtest only; IV5 verifier is NOT wired into consensus)\n",
               nRegtestBoundaryBHeight, (int)fRegtestShieldedVNextRehearsal);
    }

    fCNLock = GetBoolArg("-cnconflock");
    fNativeTor = GetBoolArg("-nativetor");

    // Nyx Messaging defaults (overridable in innova.conf)
    SoftSetBoolArg("-smsg", true);
    SoftSetBoolArg("-nyx", true);
    SoftSetBoolArg("-nyxanon", true);
    SoftSetBoolArg("-nyxgroups", true);
    SoftSetBoolArg("-nyxfiles", true);
    SoftSetArg("-nyxchunksize", "1048576");
    SoftSetArg("-nyxmaxfilesize", "10995116277760");
    SoftSetArg("-nyxconcurrency", "8");

    // Default IPFS gateway
    SoftSetBoolArg("-hyperfilelocal", true);
    SoftSetArg("-hyperfileip", "ipfs.innova-foundation.com:5001");
    fHyperfileLocal = GetBoolArg("-hyperfilelocal");

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

    fSPVMode = GetBoolArg("-spv", false);
    nSPVStartHeight = GetArg("-spvstartheight", 0);
    fHybridSPV = GetBoolArg("-hybridspv", false);

    if (fHybridSPV)
    {
        printf("Hybrid SPV mode enabled - headers + wallet blocks only\n");
        printf("  Optimized for low-memory devices (Pi Zero/3, 256-512MB RAM)\n");
        fSPVMode = true;
        fSPVHeadersOnly = false;
        fSPVStakingEnabled = GetBoolArg("-staking", true);

        // Constrained device defaults: reduce memory footprint
        if (!mapArgs.count("-dbcache"))
            SoftSetArg("-dbcache", "50");
        if (!mapArgs.count("-maxconnections"))
            SoftSetArg("-maxconnections", "16");
        if (!mapArgs.count("-maxmempool"))
            SoftSetArg("-maxmempool", "10");       // 10MB mempool (vs 300MB default)
        if (!mapArgs.count("-maxorphantx"))
            SoftSetArg("-maxorphantx", "10");       // Reduce orphan tx limit
        if (!mapArgs.count("-maxorphanblocks"))
            SoftSetArg("-maxorphanblocks", "100");  // Reduce orphan block limit

        // Disable non-essential features for constrained devices
        if (!mapArgs.count("-nosmsg"))
            SoftSetBoolArg("-nosmsg", true);        // Disable secure messaging
        if (!mapArgs.count("-nohyperfile"))
            SoftSetBoolArg("-nohyperfile", true);   // Disable IPFS/Hyperfile

        // Header pruning: keep only recent headers to save memory
        int nMaxHeaders = GetArg("-maxheaders", 50000);
        printf("  Max headers in memory: %d\n", nMaxHeaders);
        printf("  Mempool limit: %s MB\n", GetArg("-maxmempool", "10").c_str());
        printf("  Staking: %s\n", fSPVStakingEnabled ? "enabled" : "disabled");
        printf("  Secure messaging: disabled (constrained mode)\n");
    }
    else if (fSPVMode)
    {
        printf("SPV mode enabled - operating as light client\n");
        fSPVHeadersOnly = true;
        SoftSetBoolArg("-staking", false);
        SoftSetBoolArg("-listen", false);

        if (!mapArgs.count("-maxmempool"))
            SoftSetArg("-maxmempool", "10");
        if (!mapArgs.count("-maxorphantx"))
            SoftSetArg("-maxorphantx", "10");
    }

    {
        const string strStakingMode = GetArg("-stakingmode", "transparent");
        StakingMode eRequestedStakingMode = STAKE_TRANSPARENT;
        if (strStakingMode == "nullstake" || strStakingMode == "private" || strStakingMode == "1")
            eRequestedStakingMode = STAKE_NULLSTAKE;
        else if (strStakingMode == "cold" || strStakingMode == "2")
            eRequestedStakingMode = STAKE_COLD;
        else if (strStakingMode == "coldprivate" || strStakingMode == "nullstakecold" || strStakingMode == "3")
            eRequestedStakingMode = STAKE_NULLSTAKE_COLD;
        else if (strStakingMode != "transparent" && strStakingMode != "0")
            printf("WARNING: Unknown -stakingmode '%s', using transparent\n", strStakingMode.c_str());

        if (IsLegacyPrivateStakingMode(eRequestedStakingMode) &&
            IsLegacyPrivacyPolicyDisabled())
        {
            return InitError(_("Legacy private staking modes are disabled on public networks pending privacy vNext; use -stakingmode=transparent or -stakingmode=cold."));
        }

        LOCK(cs_stakingMode);
        nStakingMode = eRequestedStakingMode;
    }

    {
        CFinalityTallyConfig tallyConfig = GetFinalityTallyConfig();
        if (!tallyConfig.fModeValid)
            printf("WARNING: Unknown -finalitytallymode, using off\n");
        if (tallyConfig.fEnabled && !tallyConfig.CanRelayPrivateVotes())
        {
            printf("WARNING: finality tally mode '%s' is enabled but requires ordered -finalitytallypubkey entries, a valid -finalitytallythreshold=<m-of-n>, and encrypted tally support; private finality promotion will stay disabled\n",
                   tallyConfig.strMode.c_str());
        }
        if (tallyConfig.fEnabled && tallyConfig.fPrivKeyConfigured && !tallyConfig.CanProduceCertificates())
        {
            printf("WARNING: -finalitytallyprivkey is configured but tally certificate production is disabled until committee pubkey and threshold config are valid\n");
        }
    }

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
    fs::path walletPath(strWalletFileName);
    if (strWalletFileName != (walletPath.stem().string() + walletPath.extension().string()))
        return InitError(strprintf(_("Wallet %s resides outside data directory %s."), strWalletFileName.c_str(), strDataDir.c_str()));

    // Make sure only a single Innova process is using the data directory.
    fs::path pathLockFile = GetDataDir() / ".lock";
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

    if (fs::exists(GetDataDir() / strWalletFileName))
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
        fs::path const hostname_path = GetDefaultDataDir() / "onion" / "hostname";

        if (!fs::exists(hostname_path)) {
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

    // ********************************************************* Step 6.5: Bootstrap download (optional)

    if (Bootstrap::IsNeeded(GetDataDir()))
    {
        bool fGetBootstrap = GetBoolArg("-getbootstrap", false);
        bool fNoBootstrap = GetBoolArg("-nobootstrap", false);

        if (!fNoBootstrap && !fGetBootstrap && !fDaemon)
        {
#ifdef QT_GUI
            fGetBootstrap = false;
#else
            printf("\n");
            printf("===============================================================\n");
            printf("  Innova Core - First Time Setup\n");
            printf("===============================================================\n");
            printf("\n");
            printf("  No blockchain data found. How would you like to sync?\n\n");
            printf("  [1] Download bootstrap (faster, ~4GB download)\n");
            printf("  [2] Sync from genesis block (slower, full verification)\n");
            printf("\n");
            printf("  Enter choice [1/2]: ");
            fflush(stdout);

            char choice = '2';
            if (scanf(" %c", &choice) != 1) {
                choice = '2';
            }
            fGetBootstrap = (choice == '1');
#endif
        }

        if (fGetBootstrap)
        {
            std::string url = GetArg("-bootstrapurl", "");
            printf("\n");

            int64_t lastPercent = -1;
            auto progressCallback = [&lastPercent](int64_t downloaded, int64_t total) {
                if (total > 0) {
                    int64_t percent = static_cast<int64_t>((static_cast<double>(downloaded) / total) * 100.0);
                    if (percent > 100) percent = 100;
                    if (percent < 0) percent = 0;
                    if (percent != lastPercent && percent % 5 == 0) {
                        printf("Bootstrap download: %lld%% (%lld MB / %lld MB)\n",
                               (long long)percent,
                               (long long)(downloaded / 1048576),
                               (long long)(total / 1048576));
                        fflush(stdout);
                        lastPercent = percent;
                    }
                }
            };

            if (!Bootstrap::DownloadAndApply(url, GetDataDir(), progressCallback))
            {
                printf("Bootstrap download failed. Starting normal sync from genesis block.\n");
            }
            printf("\n");
        }
    }

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

    InitIBDBatching();

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

    // Validate the retained connect-time DAG plans before loading any wallet or worker. Legacy
    // databases recover only with an exact CTxIndex position for every tx; otherwise fail closed.
    {
        CTxDB txdbDAGActiveSets("r+");
        std::string strDAGActiveSetError;
        if (!ValidateAndRecoverDAGActiveSetPersistence(
                txdbDAGActiveSets, strDAGActiveSetError))
            return InitError(strprintf(_(
                "DAG active-set persistence validation/recovery failed: %s. "
                "Do not infer the historical plan from the current DAG. If the "
                "message reports an ambiguous legacy transaction, preserve "
                "wallet.dat and restart with -reindex or resync the chain database."),
                strDAGActiveSetError.c_str()));
    }

    if (pindexBest && IsBoundaryBActiveAtHeight(pindexBest->nHeight))
    {
        CTxDB txdbPrivacyVNext("r");
        std::string strPrivacyVNextError;
        if (!ValidatePrivacyVNextNullifierPersistence(
                txdbPrivacyVNext, strPrivacyVNextError))
            return InitError(strprintf(_(
                "IV5 spent-key persistence validation failed: %s. "
                "The chain database is incomplete or inconsistent; preserve "
                "wallet.dat and restart with -reindex or resync."),
                strPrivacyVNextError.c_str()));
    }

    // Validate and backfill the missing auxiliary records for the 16 shielded genesis decoys
    // before starting threads. Never recreate a commitment or overwrite a conflicting record.
    if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_SHIELDED)
    {
        if (!CZKContext::Initialize())
            return InitError(_("Failed to initialize the zero-knowledge proof context while validating shielded genesis commitments."));

        CTxDB txdbShieldedGenesis("r+");
        std::string strShieldedGenesisError;
        if (!ValidateAndMigrateShieldedGenesisCommitmentIndexes(
                txdbShieldedGenesis, strShieldedGenesisError))
            return InitError(strprintf(_(
                "Shielded genesis commitment index validation failed: %s. "
                "The chain database is incomplete or conflicting; restart with "
                "-reindex or preserve wallet.dat and resync."),
                strShieldedGenesisError.c_str()));

        int nEpochSchema = 0;
        if (txdbShieldedGenesis.ReadEpochStateSchema(nEpochSchema) &&
            nEpochSchema >= EPOCHSTATE_SCHEMA_V3)
        {
            std::string strShieldedV3Error;
            if (!txdbShieldedGenesis.ValidateShieldedCommitmentIndexV3(
                    strShieldedV3Error))
                return InitError(strprintf(_(
                    "Shielded schema-V3 persistence validation failed: %s. "
                    "The reverse index/tree snapshot is incomplete or "
                    "conflicting; restart with -reindex or preserve wallet.dat "
                    "and resync."), strShieldedV3Error.c_str()));

            CIncrementalMerkleTree currentShieldedTree;
            int nCurrentAnchorHeight = -1;
            if (!txdbShieldedGenesis.ReadShieldedTree(
                    currentShieldedTree) ||
                txdbShieldedGenesis.ReadShieldedAnchorStatus(
                    currentShieldedTree.Root()) != TXDB_READ_FOUND ||
                txdbShieldedGenesis.ReadShieldedAnchorHeightStatus(
                    currentShieldedTree.Root(), nCurrentAnchorHeight) !=
                    TXDB_READ_FOUND ||
                nCurrentAnchorHeight < FORK_HEIGHT_SHIELDED ||
                nCurrentAnchorHeight > pindexBest->nHeight)
                return InitError(_(
                    "Shielded schema-V3 current tree/anchor pair is missing "
                    "or corrupt; restart with -reindex or preserve wallet.dat "
                    "and resync."));
        }
    }

    // Persisted relayed tally shares can outlive their pending votes across
    // a restart (pending votes are memory-only). Purge any share whose vote
    // no longer resolves so the miner never embeds a share that would make
    // its own block fail ConnectBlock. Must run after LoadBlockIndex so
    // connected votes and pindexBest are available.
    {
        CTxDB txdbFinality("r+");
        if (!g_finalityTracker.PurgeUnresolvableTallyShares(txdbFinality))
            return InitError(_("Failed to purge stale finality tally shares; "
                               "restart with -reindex/resync."));
    }

    //Create Innova Name index - this must happen before ReacceptWalletTransactions()
    uiInterface.InitMessage(_("Loading name index..."));
    printf("Loading Innova name index...\n");
    nStart2 = GetTimeMillis();

    extern bool createNameIndexFile();
    extern bool ValidateNameIndexTip(const CBlockIndex*, std::string&);

    {
        fs::path pathNamesDB = GetDataDir() / "innovanamesindex.dat";
        const bool fNameDBExists = fs::exists(pathNamesDB);
        bool fNeedRebuild = !fNameDBExists;
        std::string strNameIndexError;

        if (!fNeedRebuild &&
            !ValidateNameIndexTip(pindexBest, strNameIndexError))
        {
            fNeedRebuild = true;
            printf("Name index recovery cursor is not current: %s. Rebuilding...\n",
                   strNameIndexError.c_str());
        }
        else if (fNeedRebuild)
        {
            strNameIndexError = "name-index database is missing";
            printf("Name index is missing. Rebuilding...\n");
        }

        if (fNeedRebuild)
        {
            // Berkeley DB handles must be closed through the environment before
            // removal.  Removing the path directly can leave a cached handle
            // referring to the old, partially applied index.
            if (fNameDBExists && !bitdb.RemoveDb("innovanamesindex.dat"))
                return InitError(strprintf(_(
                    "Name index recovery required (%s), but the stale database "
                    "could not be removed. Stop all Innova processes and retry."),
                    strNameIndexError.c_str()));

            if (!createNameIndexFile())
                return InitError(_(
                    "Failed to rebuild innovanamesindex.dat from the canonical "
                    "chain. Block/index data may be missing or corrupt; restart "
                    "with -reindex or preserve wallet.dat and resync."));

            strNameIndexError.clear();
            if (!ValidateNameIndexTip(pindexBest, strNameIndexError))
                return InitError(strprintf(_(
                    "Name index rebuild completed without an exact canonical-tip "
                    "recovery cursor (%s). Restart with -reindex or preserve "
                    "wallet.dat and resync."), strNameIndexError.c_str()));
        }
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

    uiInterface.InitMessage(_("Loading your Innova wallet..."));
    printf("Loading your Innova wallet...\n");
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

    if (!pwalletMain->mapMofNDelegations.empty() || !pwalletMain->mapMofNMemberKeys.empty())
        printf("Loaded %zu M-of-N delegation(s) and %zu staker member key(s) from wallet\n",
               pwalletMain->mapMofNDelegations.size(), pwalletMain->mapMofNMemberKeys.size());

    bool fPendingShieldedWalletAcknowledgement = false;
    CShieldedWalletRecoveryRecord pendingShieldedWalletAcknowledgement;
    if (nLoadWalletRet == DB_LOAD_OK)
    {
        std::string strShieldedRecoveryError;
        if (!RecoverPendingShieldedWalletTransition(
                pwalletMain,
                fPendingShieldedWalletAcknowledgement,
                pendingShieldedWalletAcknowledgement,
                strShieldedRecoveryError))
            return InitError(strprintf(
                "Shielded wallet recovery failed: %s. Preserve both wallet.dat "
                "and txleveldb and retry after restoring the missing block/index "
                "data. Do not use -reindex or delete txleveldb while this marker "
                "is pending; doing so can destroy the abandoned-branch cleanup "
                "plan.",
                strShieldedRecoveryError.c_str()));
    }
    else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
    {
        std::string strPendingRecoveryError;
        if (HasPendingOrCorruptShieldedWalletRecovery(
                strPendingRecoveryError))
            return InitError(strprintf(
                "Wallet data loaded with noncritical errors while %s. The "
                "shielded recovery marker was preserved and cannot be "
                "acknowledged against an incomplete wallet. Restore or repair "
                "wallet.dat without deleting txleveldb, then restart.",
                strPendingRecoveryError.c_str()));
    }

    if (!pwalletMain->CacheAnonStats())
        printf("CacheAnonStats() failed; legacy anonymous balances will remain unavailable until a successful rescan\n");

    RegisterWallet(pwalletMain);

    if (!pindexBest || !pindexGenesisBlock)
        return InitError("Wallet recovery requires a loaded canonical chain; restart with -reindex/resync.");

    CBlockIndex *pindexRescan = pindexBest;
    bool fRepairWalletLocator = false;
    if (GetBoolArg("-rescan"))
    {
        pindexRescan = pindexGenesisBlock;
        fRepairWalletLocator = true;
    } else
    {
        CWalletDB walletdb(strWalletFileName);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = locator.GetBlockIndex();
        else
        {
            // A missing/unreadable locator can mean the process stopped after
            // the chain commit but before wallet effects completed.  Starting
            // at pindexBest would silently skip recovery.
            printf("Wallet best-block locator is missing or unreadable; rescanning from genesis\n");
            pindexRescan = pindexGenesisBlock;
            fRepairWalletLocator = true;
        }
    };

    if (!pindexRescan)
    {
        printf("Wallet best-block locator does not resolve to the canonical chain; rescanning from genesis\n");
        pindexRescan = pindexGenesisBlock;
        fRepairWalletLocator = true;
    }

    if (fPendingShieldedWalletAcknowledgement)
    {
        // Replay the committed canonical suffix from the recorded fork even if the locator already
        // reached the new tip, so transparent wallet connects recover before the outbox ack.
        CBlockIndex* pindexRecoveryRescan = pindexGenesisBlock;
        if (pendingShieldedWalletAcknowledgement.hashFork != 0)
        {
            std::map<uint256, CBlockIndex*>::const_iterator itFork =
                mapBlockIndex.find(
                    pendingShieldedWalletAcknowledgement.hashFork);
            if (itFork == mapBlockIndex.end() || !itFork->second ||
                !itFork->second->IsInMainChain())
                return InitError(
                    "Shielded wallet recovery fork is no longer canonical; "
                    "the recovery outbox was preserved.");
            pindexRecoveryRescan = itFork->second;
        }
        if (!pindexRecoveryRescan)
            return InitError(
                "Shielded wallet recovery has no safe transparent-wallet "
                "rescan start; the recovery outbox was preserved.");
        if (!pindexRescan ||
            pindexRecoveryRescan->nHeight < pindexRescan->nHeight)
            pindexRescan = pindexRecoveryRescan;
        fRepairWalletLocator = true;
    }

    if (pindexBest != pindexRescan && pindexBest && pindexRescan && pindexBest->nHeight > pindexRescan->nHeight)
    {
        uiInterface.InitMessage(_("Rescanning..."));
        printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        int nWalletTransactionsFound = 0;
        std::string strRescanError;
        if (!pwalletMain->ScanForWalletTransactionsChecked(
                pindexRescan, true, nWalletTransactionsFound,
                strRescanError))
            return InitError(strprintf("Wallet rescan failed: %s. Restore the wallet from a known-good backup or restart with -rescan after repairing block data.",
                                       strRescanError.c_str()));
        fRepairWalletLocator = true;
        printf(" rescan      %15" PRId64"ms\n", GetTimeMillis() - nStart);
    };

    if (fRepairWalletLocator &&
        !pwalletMain->SetBestChainChecked(CBlockLocator(pindexBest)))
        return InitError("Wallet rescan completed but its best-block locator could not be persisted; check wallet storage and restart with -rescan.");

    if (fPendingShieldedWalletAcknowledgement)
    {
        std::string strAcknowledgementError;
        if (!AcknowledgePendingShieldedWalletTransition(
                pendingShieldedWalletAcknowledgement,
                strAcknowledgementError))
            return InitError(strprintf(
                "Shielded wallet recovery replay and transparent rescan "
                "completed, but durable acknowledgement failed: %s. "
                "The recovery outbox was preserved; keep wallet.dat and "
                "txleveldb together and restart.",
                strAcknowledgementError.c_str()));
    }

    // Add wallet transactions that aren't already in a block to mapTransactions
    pwalletMain->ReacceptWalletTransactions();

    if (fHybridSPV)
    {
        uiInterface.InitMessage(_("Loading SPV UTXO cache..."));
        if (!pwalletMain->LoadSPVUtxoCache())
        {
            uiInterface.InitMessage(_("Building SPV UTXO cache..."));
            pwalletMain->PopulateSPVUtxosFromWallet();
        }
    }

    // Init Bloom Filters
    //pwalletMain->InitBloomFilter();

    // ********************************************************* Step 9: import blocks

    fFullReplayVerify = GetBoolArg("-fullreplayverify", false);

    // The import paths below run ConnectBlock, which for shielded chains needs the
    // ZK proof context (SeedGenesisCommitments / CreateBlindCommitment). It is
    // otherwise initialized at node start (Step 11), after this step, so initialize
    // it now when importing. Idempotent (boost::call_once) -> the Step 11 call no-ops.
    if (mapArgs.count("-replayblocks") || mapArgs.count("-loadblock"))
    {
        if (!CZKContext::Initialize())
            return InitError(_("Failed to initialize the zero-knowledge proof context for block import."));
    }

    // -replayblocks=<dir|file>: in-binary full-validation replay. Imports every
    // blkNNNN.dat in <dir> (or a single file) through the real ProcessBlock pipeline
    // with full ECDSA verification forced (no checkpoint signature skip), into the
    // active datadir. Used to re-validate chain history end to end without an
    // external tool. Files are imported in name order. An empty source, an unreadable file,
    // or a file yielding no new block fails the replay; release evidence uses a fresh datadir.
    if (mapArgs.count("-replayblocks"))
    {
        fFullReplayVerify = true;
        fs::path pathSrc = fs::path(GetArg("-replayblocks", ""));
        uiInterface.InitMessage(_("Replaying blocks with full verification..."));

        if (!mapArgs.count("-replayexpectedheight") ||
            !mapArgs.count("-replayexpectedhash"))
            return ReplayFail(
                "-replayblocks requires both -replayexpectedheight and "
                "-replayexpectedhash so a partial history cannot pass");
        const int64_t nExpectedHeight64 =
            GetArg("-replayexpectedheight", (int64_t)-1);
        const std::string strExpectedHash =
            GetArg("-replayexpectedhash", "");
        if (nExpectedHeight64 < 0 ||
            nExpectedHeight64 > std::numeric_limits<int>::max() ||
            strExpectedHash.size() != 64 || !IsHex(strExpectedHash))
            return ReplayFail(
                "-replayexpectedheight/-replayexpectedhash are malformed");
        uint256 hashExpected;
        hashExpected.SetHex(strExpectedHash);

        std::vector<fs::path> vFiles;
        if (fs::is_directory(pathSrc))
        {
            for (fs::directory_iterator it(pathSrc), end; it != end; ++it)
            {
                std::string name = it->path().filename().string();
                if (name.size() >= 8 && name.compare(0, 3, "blk") == 0 &&
                    name.compare(name.size() - 4, 4, ".dat") == 0)
                    vFiles.push_back(it->path());
            }
            std::sort(vFiles.begin(), vFiles.end());
        }
        else if (fs::exists(pathSrc))
        {
            vFiles.push_back(pathSrc);
        }

        if (vFiles.empty())
            return ReplayFail(strprintf(
                "-replayblocks found no blkNNNN.dat files at %s",
                pathSrc.string().c_str()));

        printf("-replayblocks: %d block file(s) from %s, full ECDSA verify ON\n",
               (int)vFiles.size(), pathSrc.string().c_str());
        for (const fs::path& f : vFiles)
        {
            FILE *file = fopen(f.string().c_str(), "rb");
            if (!file)
                return ReplayFail(strprintf(
                    "-replayblocks could not open %s",
                    f.string().c_str()));
            if (!LoadExternalBlockFile(file))
                return ReplayFail(strprintf(
                    "-replayblocks did not cleanly validate every block in %s",
                    f.string().c_str()));
        }
        if (!pindexBest ||
            pindexBest->nHeight != (int)nExpectedHeight64 ||
            pindexBest->GetBlockHash() != hashExpected)
            return ReplayFail(strprintf(
                "-replayblocks terminal tip mismatch: expected %d/%s, got %d/%s",
                (int)nExpectedHeight64, hashExpected.ToString().c_str(),
                pindexBest ? pindexBest->nHeight : -1,
                pindexBest ? pindexBest->GetBlockHash().ToString().c_str()
                           : uint256(0).ToString().c_str()));
        printf("-replayblocks: trusted terminal tip verified at %d/%s\n",
               (int)nExpectedHeight64, hashExpected.ToString().c_str());
        exit(0);
    }

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

    fs::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (fs::exists(pathBootstrap)) {
        uiInterface.InitMessage(_("Importing bootstrap blockchain data file."));

        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            fs::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
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

    // DAG manager initialized via global constructor
    // Links loaded during LoadBlockIndex() in txdb-leveldb.cpp
    if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_DAG)
    {
        // Check for clean height; use incremental rebuild if available
        // Also restore nPrunedBelowHeight for GetBlueSet boundary detection
        CTxDB txdbDAGInit;
        int nDAGCleanHeight = -1;
        if (txdbDAGInit.ReadDAGCleanHeight(nDAGCleanHeight) && nDAGCleanHeight > 0)
        {
            // PruneDAGData persists the actual exclusive prune boundary,
            // not the tip height. Subtracting DAG_PRUNE_DEPTH a second time
            // made restart disagree about which missing DAG records were
            // expected versus corrupt.
            g_dagManager.SetPrunedBelowHeight(nDAGCleanHeight);
        }
        if (nDAGCleanHeight > 0)
        {
            printf("IDAG: Found DAG clean height %d, using incremental rebuild\n", nDAGCleanHeight);
            g_dagManager.RebuildDAGOrderIncremental(nDAGCleanHeight);
        }
        else if (!g_dagManager.GetDAGTips().empty())
        {
            printf("IDAG: No clean height found, full DAG rebuild\n");
            g_dagManager.RebuildDAGOrder();
        }

        std::vector<uint256> vTips = g_dagManager.GetDAGTips();
        printf("IDAG: DAG active at height %d, %d tips, %d entries\n",
               pindexBest->nHeight, (int)vTips.size(), g_dagManager.GetDAGEntryCount());

        // DAGKNIGHT status
        if (pindexBest->nHeight >= FORK_HEIGHT_DAGKNIGHT)
            printf("IDAG Phase 4: DAGKNIGHT adaptive ordering active (no fixed k)\n");
        else
            printf("IDAG: GHOSTDAG ordering active (k=%d), DAGKNIGHT activates at height %d\n",
                   GHOSTDAG_K, FORK_HEIGHT_DAGKNIGHT);
    }

    // ------------------------------------------------------------------------------------------------
    // Epoch-state upgrade-safety guard (fail-closed). A binary that ACTIVATES the deterministic epoch
    // anchor (FORK_HEIGHT_EPOCH_STATE_V2) must not silently consume epoch-state records that a PRIOR
    // binary wrote under the old node-local (non-deterministic) regime -- doing so gives this node a
    // finalized-epoch root that diverges from the fleet, so a fleet-valid block is deterministically
    // rejected here (the exact stuck-node failure seen in testing). Records written under the
    // deterministic anchor stamp EPOCHSTATE_SCHEMA_V2 (main.cpp). If we are past the fork but the marker
    // is absent while epoch records exist, refuse to start rather than serve divergent roots. Escape
    // hatches: a fresh/empty epoch cache is stamped and proceeds; an operator certain the existing
    // records were produced by a deterministic-anchor build can grandfather them with -acceptepochstate.
    if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_EPOCH_STATE_V2)
    {
        CTxDB txdbEpochChk("rw");
        int nEpochSchema = 0;
        txdbEpochChk.ReadEpochStateSchema(nEpochSchema);
        if (nEpochSchema < EPOCHSTATE_SCHEMA_V2)
        {
            size_t nLoadedEpochs = g_dagManager.GetLoadedEpochStateCount();
            if (nLoadedEpochs == 0)
            {
                txdbEpochChk.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V2);
                printf("EpochState: stamped schema V2 (no pre-existing epoch records)\n");
            }
            else if (GetBoolArg("-acceptepochstate", false))
            {
                txdbEpochChk.WriteEpochStateSchema(EPOCHSTATE_SCHEMA_V2);
                printf("EpochState: -acceptepochstate given; grandfathered %d pre-marker epoch records to schema V2\n",
                       (int)nLoadedEpochs);
            }
            else
            {
                return InitError(strprintf(_(
                    "Epoch-state records (%d) predate the deterministic-epoch schema marker and may have been "
                    "computed under the old non-deterministic regime; consuming them could split this node from "
                    "the network. Refusing to start. Recover by removing the chain database (keep wallet.dat) and "
                    "resyncing. Only if you are certain these records were written by a deterministic-anchor "
                    "build, restart with -acceptepochstate to grandfather them in."),
                    (int)nLoadedEpochs));
            }
        }
    }

    // Schema V3 is intentionally not grandfatherable: its exact-boundary roots and
    // atomic state/tree invariant cannot be inferred from an older marker. A node whose
    // best chain has crossed the V3 activation must have committed the V3 marker in the
    // same batch as that best-chain transition. Anything else is a torn/old database.
    if (pindexBest && pindexBest->nHeight >= FORK_HEIGHT_EPOCH_STATE_V3)
    {
        CTxDB txdbEpochV3("r");
        int nEpochSchema = 0;
        std::string strEpochTipError;
        const bool fSchemaRead = txdbEpochV3.ReadEpochStateSchema(nEpochSchema);
        const int nExpectedEpochSchema =
            IsBoundaryBActiveAtHeight(pindexBest->nHeight)
                ? EPOCHSTATE_SCHEMA_V4 : EPOCHSTATE_SCHEMA_V3;
        const bool fEpochTipValid =
            fSchemaRead && nEpochSchema == nExpectedEpochSchema &&
            g_dagManager.GetLoadedEpochStateCount() > 0 &&
            g_dagManager.ValidateEpochStateTip(pindexBest, strEpochTipError);
        if (!fEpochTipValid)
        {
            if (strEpochTipError.empty())
                strEpochTipError = "schema marker or epoch-state set is missing";
            return InitError(strprintf(_(
                "Epoch-state schema %d is required at height %d, but the chain database has "
                "schema marker %d and %d loaded epoch records (%s). This indicates an old or torn "
                "epoch-state database; continuing could split consensus. Restart with -reindex "
                "or remove the chain database (preserve wallet.dat) and resync."),
                nExpectedEpochSchema, pindexBest->nHeight, nEpochSchema,
                (int)g_dagManager.GetLoadedEpochStateCount(), strEpochTipError.c_str()));
        }
    }

    // Background workers start only after every DAG and epoch-state integrity/schema
    // guard above has passed.
    NewThread(ThreadCheckCollaTeralPool, NULL);
    NewThread(ThreadNullSend, NULL);
    if (!GetBoolArg("-nofinalityvoting", false))
        NewThread(ThreadFinalityVoter, NULL);

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
        try {
            idns = new IDns(bind_ip.c_str(), port,
            suffix.c_str(), allowed.c_str(), localcf.c_str(), verbose);
            printf("Innova DNS Server started on %d!\n", port);
        } catch (const std::exception& e) {
            printf("WARNING: IDNS failed to start: %s\n", e.what());
            printf("         Node will continue without IDNS service.\n");
            idns = NULL;
        }
    }

    // Step 11.5: ZK proof context
    if (!CZKContext::Initialize())
    {
        printf("ERROR: Failed to initialize ZK proof context. Shielded transactions will be rejected.\n");
        printf("       This node will not be able to validate shielded blocks post fork height.\n");
    }

    // Step 11.6: Dandelion++
    if (GetBoolArg("-dandelion", true))
    {
        dandelionState.SetEnabled(true);
        printf("Dandelion++ network privacy enabled\n");
    }
    else
    {
        dandelionState.SetEnabled(false);
        printf("Dandelion++ network privacy disabled\n");
    }

    // ********************************************************* Step 12: finished

    uiInterface.InitMessage(_("Done loading"));
    printf("Done loading\n");

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

    fSuccessfullyLoaded = true;

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

    return true;
}
