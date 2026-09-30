// Guards against stale ladder pins after a re-base: no test equality-pins a ladder constant
// to a disagreeing literal, and no test source is left out of the build.

#include <boost/test/unit_test.hpp>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/preprocessor/stringize.hpp>

#include <fstream>
#include <map>
#include <cstdlib>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "../finality.h"
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
        GetForkHeightMsTimestamp(),
        GetForkHeightPoem(), GetForkHeightFinality(), GetForkHeightDAG(),
        GetForkHeightDAGKnight(),
    };

    // The pre-shift base of each gate above, in order. A gate written as an absolute
    // literal rather than through ShiftMainnetV5Activation lands on another base.
    const int nBases[] = {
        7801000, 7801500, 7802000,
        7802500, 7803000,
        7803500, 7804000,
        7807000,
        7808000, 7808980, 7809960,
        7859960,
    };
    BOOST_REQUIRE_EQUAL(sizeof(nBases) / sizeof(nBases[0]), sizeof(nGates) / sizeof(nGates[0]));

    for (size_t i = 0; i < sizeof(nGates) / sizeof(nGates[0]); i++)
    {
        const int nBase = nGates[i] - MAINNET_V5_ACTIVATION_SHIFT;
        BOOST_CHECK_MESSAGE(nBase == nBases[i],
                            "gate " << nGates[i] << " has base " << nBase
                                    << ", which is not a ladder rung -- it is"
                                       " probably an absolute literal rather than"
                                       " ShiftMainnetV5Activation(base)");
        BOOST_CHECK_EQUAL(ShiftMainnetV5Activation(nBase), nGates[i]);
    }

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;
}

// Scan by value as well as by name: mainnet gates sit at base + SHIFT (SHIFT a
// multiple of 30,000), so a literal equal to base + k*30,000 for a non-current k is
// a gate pinned under a superseded ladder.
BOOST_AUTO_TEST_CASE(no_test_pins_a_gate_from_a_superseded_ladder)
{
    const bool fRegTestSaved = fRegTest;
    const bool fTestNetSaved = fTestNet;
    fRegTest = false;
    fTestNet = false;

    const int nGates[] = {
        GetForkHeightShielded(), GetForkHeightDSP(), GetForkHeightNullSend(),
        GetForkHeightNullStake(), GetForkHeightNullStakeV2(),
        GetForkHeightNullStakeV3(), GetForkHeightChaumianCJ(),
        GetForkHeightMsTimestamp(),
        GetForkHeightPoem(), GetForkHeightFinality(), GetForkHeightDAG(),
        GetForkHeightDAGKnight(), GetForkHeightBoundaryA(), GetForkHeightBoundaryB(),
    };
    const size_t nGateCount = sizeof(nGates) / sizeof(nGates[0]);

    // Stale values from every LEGAL shift (as v5activation.h derives it). A wider
    // sweep collides with ordinary numbers such as the 8,000,000 emission rung end.
    std::set<int64_t> setStale;
    std::map<int64_t, int> mapGateOf;
    for (size_t i = 0; i < nGateCount; i++)
    {
        const int64_t nBase = (int64_t)nGates[i] - MAINNET_V5_ACTIVATION_SHIFT;
        for (int64_t nShift = 330000; nShift <= 540000; nShift += 30000)
        {
            if (nShift == MAINNET_V5_ACTIVATION_SHIFT)
                continue;
            const int64_t nStale = nBase + nShift;
            setStale.insert(nStale);
            if (!mapGateOf.count(nStale))
                mapGateOf[nStale] = nGates[i];
        }
    }
    // A live gate is never stale, whatever other base could also reach it.
    for (size_t i = 0; i < nGateCount; i++)
        setStale.erase((int64_t)nGates[i]);

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;

    BOOST_REQUIRE(!setStale.empty());

    // Only literals in an equality comparison count as pins; table data does not.
    const std::regex reLiteral(
        "(?:BOOST_(?:CHECK|REQUIRE)_EQUAL\\s*\\([^;]*?|==\\s*)([0-9]{7,9})");
    const std::vector<fs::path> vSources = TestSources();
    BOOST_REQUIRE(!vSources.empty());

    size_t nScanned = 0;
    for (size_t i = 0; i < vSources.size(); i++)
    {
        // This file names superseded gates in its own prose.
        if (vSources[i].filename() == "ladder_pin_tests.cpp")
            continue;
        const std::string strBody = ReadFile(vSources[i]);
        nScanned++;
        for (std::sregex_iterator it(strBody.begin(), strBody.end(), reLiteral), end;
             it != end; ++it)
        {
            const int64_t nValue = (int64_t)strtoll((*it)[1].str().c_str(), NULL, 10);
            if (!setStale.count(nValue))
                continue;
            BOOST_ERROR(vSources[i].filename().string()
                        << " contains " << nValue
                        << ", which is a gate from a superseded ladder: the live value"
                           " for that gate is now " << mapGateOf[nValue]
                        << ". Write it as ShiftMainnetV5Activation(base), or re-derive"
                           " the literal for MAINNET_V5_ACTIVATION_SHIFT = "
                        << MAINNET_V5_ACTIVATION_SHIFT << ".");
        }
    }
    BOOST_CHECK(nScanned > 50);
}

// The note-vote height is derived, not a literal, and its gap must land on an epoch
// boundary.
BOOST_AUTO_TEST_CASE(the_note_vote_height_rides_the_ladder_and_opens_an_epoch)
{
    const bool fRegTestSaved = fRegTest;
    const bool fTestNetSaved = fTestNet;

    fRegTest = false; fTestNet = false;
    BOOST_CHECK(IsIV5NoteVoteConfigured());
    const int nBoundaryB = GetForkHeightBoundaryB();
    const int nHeight = GetForkHeightIV5NoteVote();
    BOOST_CHECK_EQUAL(nHeight, DeriveIV5NoteVoteHeight(nBoundaryB));
    BOOST_CHECK_EQUAL(nHeight - nBoundaryB, 4800);
    BOOST_CHECK(nHeight > nBoundaryB);
    // Checked against the ladder rather than written down: base 7,955,100 shifted is the
    // same block the gap produces.
    BOOST_CHECK_EQUAL(nHeight, ShiftMainnetV5Activation(7815060));

    fRegTest = false; fTestNet = true;
    BOOST_CHECK(IsIV5NoteVoteConfigured());
    BOOST_CHECK_EQUAL(GetForkHeightIV5NoteVote(),
                      DeriveIV5NoteVoteHeight(GetForkHeightBoundaryB()));
    BOOST_CHECK(GetForkHeightIV5NoteVote() > GetForkHeightBoundaryB());

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;
}

// The per-block note-vote gate (connect height) and the per-epoch gate
// (state.nHeightEnd) agree for every block only when the height opens an epoch.
BOOST_AUTO_TEST_CASE(the_note_vote_gate_and_the_epoch_end_gate_cannot_disagree)
{
    const bool fRegTestSaved = fRegTest;
    const bool fTestNetSaved = fTestNet;

    for (int nPass = 0; nPass < 2; nPass++)
    {
        fRegTest = false;
        fTestNet = (nPass == 1);

        const int nGate = GetForkHeightIV5NoteVote();
        const int nDAG = GetForkHeightDAG();
        BOOST_REQUIRE(nGate > nDAG);
        BOOST_CHECK_MESSAGE(
            (nGate - nDAG) % FINALITY_EPOCH_INTERVAL_POST_DAG == 0,
            "the note-vote gate " << nGate << " does not open a post-DAG epoch; the "
            "epoch that straddles it would be built as a note-vote epoch over blocks "
            "that can carry no note vote");
        BOOST_CHECK(IsEpochBoundaryHeight(nGate));

        // What the alignment buys, stated as the property rather than the arithmetic:
        // for every epoch, "this epoch's last height is at or above the gate" and "this
        // epoch's first height is at or above the gate" are the same answer.
        for (int i = -3; i <= 3; i++)
        {
            const int nOpen = nGate + i * FINALITY_EPOCH_INTERVAL_POST_DAG;
            if (nOpen < nDAG)
                continue;
            const int nEnd = nOpen + FINALITY_EPOCH_INTERVAL_POST_DAG - 1;
            BOOST_CHECK_EQUAL(IsIV5NoteVoteActiveAtHeight(nEnd),
                              IsIV5NoteVoteActiveAtHeight(nOpen));
        }
    }

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;
}

BOOST_AUTO_TEST_SUITE_END()
