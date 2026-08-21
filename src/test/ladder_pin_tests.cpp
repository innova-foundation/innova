// Guards against stale ladder pins after a re-base: no test equality-pins a ladder constant
// to a disagreeing literal, and no test source is left out of the build.

#include <boost/test/unit_test.hpp>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/preprocessor/stringize.hpp>

#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "../main.h"
#include "../v5activation.h"

namespace fs = boost::filesystem;

extern bool fRegTest;
extern bool fTestNet;

namespace {

// src/test, from the data directory the build passes in.
fs::path TestSourceDir()
{
    return fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)).parent_path();
}

fs::path SrcDir()
{
    return TestSourceDir().parent_path();
}

std::string ReadFile(const fs::path& path)
{
    std::ifstream in(path.string().c_str());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::vector<fs::path> TestSources()
{
    std::vector<fs::path> vResult;
    const fs::path dir = TestSourceDir();
    if (!fs::is_directory(dir))
        return vResult;
    for (fs::directory_iterator it(dir); it != fs::directory_iterator(); ++it)
    {
        if (it->path().extension() == ".cpp")
            vResult.push_back(it->path());
    }
    return vResult;
}

// A ladder constant and every value it may hold. FORK_HEIGHT_DAG is pinned per network, so
// all three readings are allowed.
struct LadderConstant
{
    std::string strName;
    std::set<int64_t> setAllowed;
    std::string strAllowed;   // for the failure message
};

// Every literal equality-compared to strName must be in setAllowed. Derivations such as
// `7800000 + SHIFT` are not bare equalities and are not checked.
std::vector<LadderConstant> LiveLadderConstants()
{
    const bool fRegTestSaved = fRegTest;
    const bool fTestNetSaved = fTestNet;

    std::set<int64_t> setDag;
    fRegTest = false; fTestNet = false;
    setDag.insert((int64_t)FORK_HEIGHT_DAG);
    const int64_t nMainnetDag = (int64_t)FORK_HEIGHT_DAG;
    fRegTest = false; fTestNet = true;
    setDag.insert((int64_t)FORK_HEIGHT_DAG);
    fRegTest = true; fTestNet = false;
    setDag.insert((int64_t)FORK_HEIGHT_DAG);

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;

    std::ostringstream ssDag;
    for (std::set<int64_t>::const_iterator it = setDag.begin(); it != setDag.end(); ++it)
        ssDag << (it == setDag.begin() ? "" : "/") << *it;
    ssDag << " (mainnet " << nMainnetDag << ")";

    std::set<int64_t> setShift;
    setShift.insert((int64_t)MAINNET_V5_ACTIVATION_SHIFT);
    std::ostringstream ssShift;
    ssShift << MAINNET_V5_ACTIVATION_SHIFT;

    std::vector<LadderConstant> v;
    LadderConstant shift = { "MAINNET_V5_ACTIVATION_SHIFT", setShift, ssShift.str() };
    LadderConstant dag = { "FORK_HEIGHT_DAG", setDag, ssDag.str() };
    v.push_back(shift);
    v.push_back(dag);
    return v;
}

} // namespace

BOOST_AUTO_TEST_SUITE(ladder_pin_tests)

// A ladder constant may be pinned -- emission_curve_tests deliberately does, so
// the money supply cannot move silently -- but the pin must agree with the tree
// it is in. This is the check the five stale branches would have failed.
BOOST_AUTO_TEST_CASE(no_test_pins_a_ladder_constant_to_a_stale_literal)
{
    const std::vector<fs::path> vSources = TestSources();
    BOOST_REQUIRE(!vSources.empty());

    const std::vector<LadderConstant> vConstants = LiveLadderConstants();

    size_t nPinsSeen = 0;

    for (size_t i = 0; i < vSources.size(); i++)
    {
        // This file names the constants in its own prose and in its regexes.
        if (vSources[i].filename() == "ladder_pin_tests.cpp")
            continue;

        const std::string strSource = ReadFile(vSources[i]);

        for (size_t c = 0; c < vConstants.size(); c++)
        {
            const std::string strName = vConstants[c].strName;

            // BOOST_CHECK_EQUAL(NAME, 12345) and BOOST_CHECK_EQUAL(12345, NAME),
            // with an optional cast on either side. The constant must be the
            // whole argument: a trailing operator makes it a derivation.
            const std::string strCast = "(?:\\((?:int|int64_t|unsigned int)\\)\\s*)?";
            const std::regex reForward(
                "BOOST_CHECK_EQUAL\\s*\\(\\s*" + strCast + strName +
                "\\s*,\\s*" + strCast + "([0-9]+)L?L?\\s*\\)");
            const std::regex reReverse(
                "BOOST_CHECK_EQUAL\\s*\\(\\s*" + strCast + "([0-9]+)L?L?" +
                "\\s*,\\s*" + strCast + strName + "\\s*\\)");

            const std::regex* vRe[2] = { &reForward, &reReverse };
            for (int r = 0; r < 2; r++)
            {
                std::sregex_iterator it(strSource.begin(), strSource.end(), *vRe[r]);
                const std::sregex_iterator end;
                for (; it != end; ++it)
                {
                    nPinsSeen++;
                    const int64_t nPinned = strtoll((*it)[1].str().c_str(), NULL, 10);
                    BOOST_CHECK_MESSAGE(
                        vConstants[c].setAllowed.count(nPinned) > 0,
                        vSources[i].filename().string() << " pins " << strName
                            << " to " << nPinned << ", but this tree allows "
                            << vConstants[c].strAllowed
                            << ". Re-base the pin onto the current ladder; do not"
                               " restore the old gate.");
                }
            }
        }
    }

    // The guard is only worth anything while the pins it guards still exist.
    // If someone deletes every pin, this fails rather than passing vacuously.
    BOOST_CHECK_MESSAGE(nPinsSeen > 0,
                        "no ladder-constant pins found in src/test -- the guard "
                        "is passing vacuously");
}

// A test file that no makefile builds is a pin nobody evaluates. Both makefiles
// are checked: a suite registered in one and not the other is dark on the other
// platform, which is how a Linux-only build hides a defect from a macOS run.
BOOST_AUTO_TEST_CASE(no_test_source_is_dark)
{
    const std::vector<fs::path> vSources = TestSources();
    BOOST_REQUIRE(!vSources.empty());

    static const char* vMakefile[] = { "makefile.unix", "makefile.osx" };

    for (size_t m = 0; m < sizeof(vMakefile) / sizeof(vMakefile[0]); m++)
    {
        const fs::path makefile = SrcDir() / vMakefile[m];
        BOOST_REQUIRE_MESSAGE(fs::exists(makefile),
                              "missing " << makefile.string());
        const std::string strMakefile = ReadFile(makefile);

        for (size_t i = 0; i < vSources.size(); i++)
        {
            const std::string strStem = vSources[i].stem().string();
            const std::string strObject = "obj/test/" + strStem + ".o";
            BOOST_CHECK_MESSAGE(
                strMakefile.find(strObject) != std::string::npos,
                strStem << ".cpp is not built by " << vMakefile[m]
                        << " -- add " << strObject << " to its test objects, or"
                           " the suite never runs on that platform.");
        }
    }
}

// The ladder itself: every mainnet gate is BASE + SHIFT for some base, so a
// re-base moves all of them together and none can be left behind. The bases do
// not move when the shift does.
BOOST_AUTO_TEST_CASE(every_mainnet_gate_derives_from_the_shift)
{
    const bool fRegTestSaved = fRegTest;
    const bool fTestNetSaved = fTestNet;
    fRegTest = false;
    fTestNet = false;

    const int nGates[] = {
        GetForkHeightShielded(), GetForkHeightDSP(), GetForkHeightNullSend(),
        GetForkHeightNullStake(), GetForkHeightNullStakeV2(),
        GetForkHeightNullStakeV3(), GetForkHeightChaumianCJ(),
        GetForkHeightPoem(), GetForkHeightFinality(), GetForkHeightDAG(),
        GetForkHeightDAGKnight(),
    };

    for (size_t i = 0; i < sizeof(nGates) / sizeof(nGates[0]); i++)
    {
        const int nBase = nGates[i] - MAINNET_V5_ACTIVATION_SHIFT;
        // Every base is a round rung on the pre-shift ladder. A gate written as
        // an absolute literal rather than through ShiftMainnetV5Activation would
        // not survive this once the shift stops being a multiple of 5,000.
        BOOST_CHECK_MESSAGE(nBase % 5000 == 0,
                            "gate " << nGates[i] << " has base " << nBase
                                    << ", which is not a ladder rung -- it is"
                                       " probably an absolute literal rather than"
                                       " ShiftMainnetV5Activation(base)");
        BOOST_CHECK_EQUAL(ShiftMainnetV5Activation(nBase), nGates[i]);
    }

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;
}

BOOST_AUTO_TEST_SUITE_END()
