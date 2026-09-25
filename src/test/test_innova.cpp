#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Bitcoin Test Suite
#include <boost/test/unit_test.hpp>

#include "checkpoints.h"
#include "db.h"
#include "main.h"
#include "txdb.h"
#include "wallet.h"
#include "zkproof.h"

#include <boost/filesystem.hpp>
#include <stdexcept>

#if defined(__SANITIZE_ADDRESS__)
#define INNOVA_TEST_LSAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define INNOVA_TEST_LSAN 1
#endif
#endif
#ifdef INNOVA_TEST_LSAN
#include <sanitizer/lsan_interface.h>
#endif

CWallet* pwalletMain;
CClientUIInterface uiInterface;
bool fConfChange = false;
bool fEnforceCanonical = true;
bool fUseFastIndex = true;
unsigned int nDerivationMethodIndex = 0;
unsigned int nMinerSleep = 5000;
unsigned int nNodeLifespan = 7;
enum Checkpoints::CPMode CheckpointsMode = Checkpoints::STRICT;

extern bool fPrintToConsole;
extern void noui_connect();

struct TestingSetup {
    boost::filesystem::path pathTestData;

    TestingSetup() {
        fRequestShutdown = false;
        fShutdown = false;
        pathTestData = boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("innova-test-%%%%-%%%%-%%%%");
        boost::filesystem::create_directories(pathTestData);
        mapArgs["-datadir"] = pathTestData.string();
        mapArgs["-regtest"] = "1";
        // AppInit derives these flags before LoadBlockIndex; the harness calls LoadBlockIndex
        // directly, so "-regtest" alone would load mainnet parameters and genesis.
        fRegTest = true;
        fTestNet = false;

        fPrintToDebugger = true; // don't want to write to debug.log file
        // Errors are otherwise invisible in a test run; opt in to see them on stdout.
        if (getenv("INNOVA_TEST_CONSOLE"))
            fPrintToConsole = true;
        noui_connect();
        bitdb.MakeMock();
        if (!LoadBlockIndex(true))
            throw std::runtime_error("test regtest block index failed to load");
        if (!CZKContext::Initialize())
            throw std::runtime_error("test zero-knowledge context failed to initialize");
        bool fFirstRun;
        pwalletMain = new CWallet("wallet.dat");
        if (pwalletMain->LoadWallet(fFirstRun) != DB_LOAD_OK)
            throw std::runtime_error("test wallet failed to load");
        RegisterWallet(pwalletMain);
    }
    ~TestingSetup()
    {
        // The production wallet flusher is explicitly owned and joinable.
        // Stop it while all chain/checkpoint/DB globals are still alive.
        fRequestShutdown = true;
        fShutdown = true;
        StopWalletDBFlushThread();
        UnregisterWallet(pwalletMain);
        delete pwalletMain;
        pwalletMain = NULL;
        CTxDB txdb;
        txdb.Close();
        bitdb.Flush(true);
        CZKContext::Shutdown();
        boost::filesystem::remove_all(pathTestData);
#ifdef INNOVA_TEST_LSAN
        // Leak check while the chain globals are alive. At exit, static teardown
        // destroys mapBlockIndex first, and a side-branch index reachable only
        // through it reads as leaked.
        __lsan_do_leak_check();
#endif
    }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);

void Shutdown(void* parg)
{
  exit(0);
}

void StartShutdown()
{
  exit(0);
}
