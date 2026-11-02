#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <fstream>

#include "../bootstrap.h"
#include "../util.h"

namespace fs = boost::filesystem;

namespace {

const int64_t NOW = 1800000000;
const int64_t DAY = 24 * 60 * 60;

void Put(const fs::path& p, const std::string& body)
{
    fs::create_directories(p.parent_path());
    std::ofstream(p.string().c_str(), std::ios::binary) << body;
}

std::string Get(const fs::path& p)
{
    std::ifstream f(p.string().c_str(), std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

struct Dirs
{
    fs::path root, data, stage;
    Dirs()
    {
        root = fs::temp_directory_path() / fs::unique_path("bootstrap-test-%%%%%%%%");
        data = root / "data";
        stage = root / "stage";
        Put(data / "wallet.dat", "wallet");
        Put(data / "innova.conf", "conf");
        Put(data / "peers.dat", "peers");
        Put(data / "smsgDB" / "000001.log", "msgs");
        Put(data / "blk0001.dat", "old1");
        Put(data / "blk0002.dat", "old2");
        Put(data / "blk0003.dat", "old3");
        Put(data / "txleveldb" / "000005.ldb", "oldidx");
        Put(stage / "blk0001.dat", "new1");
        Put(stage / "blk0002.dat", "new2");
        Put(stage / "txleveldb" / "000009.ldb", "newidx");
        Put(data / "cnannounce.dat", "cn");
        Put(data / "spvutxos.dat", "spv");
        Put(data / "txleveldb_backup" / "000001.ldb", "bak");
    }
    bool HasDerived()
    {
        return fs::exists(data / "cnannounce.dat") && fs::exists(data / "spvutxos.dat") &&
               fs::exists(data / "txleveldb_backup" / "000001.ldb");
    }
    bool NoDerived()
    {
        return !fs::exists(data / "cnannounce.dat") && !fs::exists(data / "spvutxos.dat") &&
               !fs::exists(data / "txleveldb_backup");
    }
    ~Dirs() { boost::system::error_code ec; fs::remove_all(root, ec); }
    void CheckKept()
    {
        BOOST_CHECK_EQUAL(Get(data / "wallet.dat"), "wallet");
        BOOST_CHECK_EQUAL(Get(data / "innova.conf"), "conf");
        BOOST_CHECK_EQUAL(Get(data / "peers.dat"), "peers");
        BOOST_CHECK_EQUAL(Get(data / "smsgDB" / "000001.log"), "msgs");
    }
    size_t Leftovers()
    {
        size_t n = 0;
        for (fs::directory_iterator it(data), end; it != end; ++it)
            n += it->path().string().find(".bootstrap-old") != std::string::npos;
        return n;
    }
};

}

BOOST_AUTO_TEST_SUITE(bootstrap_tests)

BOOST_AUTO_TEST_CASE(decide_empty)
{
    BOOST_CHECK(Bootstrap::Decide(true, 0, 0, -1, NOW) == Bootstrap::OFFER_EMPTY);
    BOOST_CHECK(Bootstrap::Decide(true, 0, 0, 8000000, NOW) == Bootstrap::OFFER_EMPTY);
}

BOOST_AUTO_TEST_CASE(decide_far_behind)
{
    BOOST_CHECK(Bootstrap::Decide(false, 100000, NOW - 30 * DAY, 8000000, NOW) == Bootstrap::OFFER_BEHIND);
    BOOST_CHECK(Bootstrap::Decide(false, 7989999, NOW - 3 * DAY, 8000000, NOW) == Bootstrap::OFFER_BEHIND);
    // Unreadable tip reads as height 0, time 0
    BOOST_CHECK(Bootstrap::Decide(false, 0, 0, 8000000, NOW) == Bootstrap::OFFER_BEHIND);
}

BOOST_AUTO_TEST_CASE(decide_near_tip)
{
    // Recent tip: never offered, whatever the published height
    BOOST_CHECK(Bootstrap::Decide(false, 100, NOW - DAY, 8000000, NOW) == Bootstrap::OFFER_NONE);
    BOOST_CHECK(Bootstrap::Decide(false, 100, NOW - 2 * DAY, -1, NOW) == Bootstrap::OFFER_NONE);
    // Stale tip within 10000 blocks of the bootstrap, or past it
    BOOST_CHECK(Bootstrap::Decide(false, 7990000, NOW - 10 * DAY, 8000000, NOW) == Bootstrap::OFFER_NONE);
    BOOST_CHECK(Bootstrap::Decide(false, 8100000, NOW - 10 * DAY, 8000000, NOW) == Bootstrap::OFFER_NONE);
}

BOOST_AUTO_TEST_CASE(decide_unknown_height)
{
    BOOST_CHECK(Bootstrap::Decide(false, 7999999, NOW - 2 * DAY - 1, -1, NOW) == Bootstrap::OFFER_NONE);
    BOOST_CHECK(Bootstrap::Decide(false, 0, 0, -1, NOW) == Bootstrap::OFFER_NONE);
    BOOST_CHECK(Bootstrap::Decide(false, 100, NOW - 30 * DAY, -1, NOW) == Bootstrap::OFFER_NONE);
    BOOST_CHECK(Bootstrap::Decide(false, 7999999, NOW - DAY, -1, NOW) == Bootstrap::OFFER_NONE);
}

BOOST_AUTO_TEST_CASE(manifest_height)
{
    const std::string h(64, 'a');
    BOOST_CHECK_EQUAL(Bootstrap::ParseManifestHeight("# height 8212345\n" + h + "  innovabootstrap.zip\n"), 8212345);
    BOOST_CHECK_EQUAL(Bootstrap::ParseManifestHeight(h + "  innovabootstrap.zip\n# height 42\r\n"), 42);
    BOOST_CHECK_EQUAL(Bootstrap::ParseManifestHeight(h + "  innovabootstrap.zip\n"), -1);
    BOOST_CHECK_EQUAL(Bootstrap::ParseManifestHeight("# height x12\n"), -1);
    BOOST_CHECK_EQUAL(Bootstrap::ParseManifestHeight("# height 99999999999\n"), -1);
}

BOOST_AUTO_TEST_CASE(swap_replaces_chain_only)
{
    Dirs d;
    BOOST_REQUIRE(Bootstrap::SwapInStaged(d.stage, d.data));
    BOOST_CHECK_EQUAL(Get(d.data / "blk0001.dat"), "new1");
    BOOST_CHECK_EQUAL(Get(d.data / "blk0002.dat"), "new2");
    BOOST_CHECK(!fs::exists(d.data / "blk0003.dat"));
    BOOST_CHECK_EQUAL(Get(d.data / "txleveldb" / "000009.ldb"), "newidx");
    BOOST_CHECK(!fs::exists(d.data / "txleveldb" / "000005.ldb"));
    BOOST_CHECK_EQUAL(d.Leftovers(), 0u);
    BOOST_CHECK(d.NoDerived());
    d.CheckKept();
}

BOOST_AUTO_TEST_CASE(swap_takes_only_chain_entries)
{
    Dirs d;
    Put(d.stage / "wallet.dat", "evil");
    Put(d.stage / "innova.conf", "evil");
    Put(d.stage / "smsgDB" / "000001.log", "evil");
    Put(d.stage / "blk0009.dat" / "x", "dir");
    BOOST_REQUIRE(Bootstrap::SwapInStaged(d.stage, d.data));
    BOOST_CHECK_EQUAL(Get(d.data / "blk0001.dat"), "new1");
    BOOST_CHECK(!fs::exists(d.data / "blk0009.dat"));
    BOOST_CHECK_EQUAL(d.Leftovers(), 0u);
    d.CheckKept();
}

BOOST_AUTO_TEST_CASE(apply_refuses_bootstrap_not_above_local)
{
    Dirs d;
    BOOST_CHECK(Bootstrap::IsNewerThanLocal(d.data, -1));
    BOOST_CHECK(!Bootstrap::IsNewerThanLocal(d.data, 0));
    BOOST_CHECK(Bootstrap::IsNewerThanLocal(d.data, 1));
    fs::remove_all(d.data / "txleveldb");
    fs::remove(d.data / "blk0001.dat");
    BOOST_CHECK(Bootstrap::IsNewerThanLocal(d.data, 0));
}

BOOST_AUTO_TEST_CASE(swap_failure_restores_everything)
{
    Dirs d;
    BOOST_CHECK(!Bootstrap::SwapInStaged(d.stage, d.data, "txleveldb"));
    BOOST_CHECK_EQUAL(Get(d.data / "blk0001.dat"), "old1");
    BOOST_CHECK_EQUAL(Get(d.data / "blk0002.dat"), "old2");
    BOOST_CHECK_EQUAL(Get(d.data / "blk0003.dat"), "old3");
    BOOST_CHECK_EQUAL(Get(d.data / "txleveldb" / "000005.ldb"), "oldidx");
    BOOST_CHECK(!fs::exists(d.data / "txleveldb" / "000009.ldb"));
    BOOST_CHECK_EQUAL(d.Leftovers(), 0u);
    BOOST_CHECK(d.HasDerived());
    d.CheckKept();
}

BOOST_AUTO_TEST_CASE(swap_failure_on_first_item)
{
    Dirs d;
    BOOST_CHECK(!Bootstrap::SwapInStaged(d.stage, d.data, "blk0001.dat"));
    BOOST_CHECK_EQUAL(Get(d.data / "blk0001.dat"), "old1");
    BOOST_CHECK_EQUAL(Get(d.data / "blk0003.dat"), "old3");
    BOOST_CHECK_EQUAL(d.Leftovers(), 0u);
    d.CheckKept();
}

BOOST_AUTO_TEST_CASE(swap_crash_at_every_step_recovers)
{
    int nOld = 0, nNew = 0;
    for (int n = 0;; ++n) {
        Dirs d;
        bool fDone = Bootstrap::SwapInStaged(d.stage, d.data, "", n);
        if (fDone) {
            BOOST_CHECK(!Bootstrap::RecoverJournal(d.data));
            BOOST_CHECK_GE(n, 8);
            break;
        }
        BOOST_REQUIRE_LT(n, 50);
        Bootstrap::RecoverJournal(d.data);
        BOOST_CHECK(!fs::exists(d.data / Bootstrap::JOURNAL_FILENAME));
        BOOST_CHECK_EQUAL(d.Leftovers(), 0u);
        d.CheckKept();
        if (Get(d.data / "txleveldb" / "000009.ldb") == "newidx") {
            ++nNew;
            BOOST_CHECK_EQUAL(Get(d.data / "blk0001.dat"), "new1");
            BOOST_CHECK_EQUAL(Get(d.data / "blk0002.dat"), "new2");
            BOOST_CHECK(!fs::exists(d.data / "blk0003.dat"));
            BOOST_CHECK(!fs::exists(d.data / "txleveldb" / "000005.ldb"));
            BOOST_CHECK(d.NoDerived());
        } else {
            ++nOld;
            BOOST_CHECK_EQUAL(Get(d.data / "blk0001.dat"), "old1");
            BOOST_CHECK_EQUAL(Get(d.data / "blk0002.dat"), "old2");
            BOOST_CHECK_EQUAL(Get(d.data / "blk0003.dat"), "old3");
            BOOST_CHECK_EQUAL(Get(d.data / "txleveldb" / "000005.ldb"), "oldidx");
            BOOST_CHECK(!fs::exists(d.data / "txleveldb" / "000009.ldb"));
            BOOST_CHECK(d.HasDerived());
        }
    }
    BOOST_CHECK_GT(nOld, 0);
    BOOST_CHECK_GT(nNew, 0);
}

BOOST_AUTO_TEST_CASE(journal_recovery_ignores_wallet)
{
    Dirs d;
    Put(d.data / "wallet.dat.bootstrap-old", "x");
    Put(d.data / Bootstrap::JOURNAL_FILENAME, "stage " + d.stage.string() + "\nplace wallet.dat\nplace ../wallet.dat\n");
    BOOST_CHECK(Bootstrap::RecoverJournal(d.data));
    BOOST_CHECK_EQUAL(Get(d.data / "wallet.dat"), "wallet");
    BOOST_CHECK(!fs::exists(d.data / Bootstrap::JOURNAL_FILENAME));
}

BOOST_AUTO_TEST_CASE(request_roundtrip)
{
    Dirs d;
    std::string url;
    BOOST_CHECK(!Bootstrap::ReadRequest(d.data, url));
    BOOST_CHECK(Bootstrap::WriteRequest(d.data, ""));
    BOOST_CHECK(Bootstrap::ReadRequest(d.data, url));
    BOOST_CHECK(url.empty());
    BOOST_CHECK(Bootstrap::WriteRequest(d.data, "https://github.com/x/innovabootstrap.sha256"));
    BOOST_CHECK(Bootstrap::ReadRequest(d.data, url));
    BOOST_CHECK_EQUAL(url, "https://github.com/x/innovabootstrap.sha256");
    Bootstrap::ClearRequest(d.data);
    BOOST_CHECK(!Bootstrap::ReadRequest(d.data, url));
}

BOOST_AUTO_TEST_CASE(local_tip_missing)
{
    Dirs d;
    int nHeight = -1;
    int64_t nTime = -1;
    BOOST_CHECK(!Bootstrap::ReadLocalTip(d.data, nHeight, nTime));
    BOOST_CHECK_EQUAL(nHeight, 0);
    BOOST_CHECK_EQUAL(nTime, 0);
}

BOOST_AUTO_TEST_SUITE_END()
