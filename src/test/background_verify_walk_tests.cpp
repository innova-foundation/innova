// The background verification walk that re-verifies the proofs assume-valid skipped.
// Pins its bookkeeping: heights covered once each, in order, across window boundaries,
// and resume.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

#include "../main.h"
#include "../miner.h"
#include "../shielded.h"
#include "../txdb.h"
#include "../wallet.h"

extern bool fRegTest;
extern CWallet* pwalletMain;

namespace {

class CArgOverride
{
public:
    CArgOverride(const std::string& strKeyIn, const std::string& strValue)
        : strKey(strKeyIn), fHadValue(mapArgs.count(strKeyIn) != 0)
    {
        if (fHadValue)
            strSaved = mapArgs[strKey];
        mapArgs[strKey] = strValue;
    }
    ~CArgOverride()
    {
        if (fHadValue)
            mapArgs[strKey] = strSaved;
        else
            mapArgs.erase(strKey);
    }
private:
    std::string strKey;
    std::string strSaved;
    bool fHadValue;
};

struct RegtestBoundaryBGuard
{
    int nStored;
    RegtestBoundaryBGuard() : nStored(nRegtestBoundaryBHeight) {}
    ~RegtestBoundaryBGuard() { nRegtestBoundaryBHeight = nStored; }
};

// Restores whatever progress height the rest of the suite left behind.
struct VerifiedHeightGuard
{
    int nStored;
    VerifiedHeightGuard() : nStored(GetPrivacyVNextVerifiedHeight()) {}
    ~VerifiedHeightGuard()
    {
        CTxDB txdb("rw");
        txdb.WritePrivacyVNextVerifiedHeight(nStored);
    }
};

CBlockIndex* BestIndex() { return pindexBest; }

bool GrindHeader(CBlock* pblock)
{
    CBigNum target;
    target.SetCompact(pblock->nBits);
    const uint256 hashTarget = target.getuint256();
    unsigned int nHashes = 0;
    while (pblock->GetPoWHash() > hashTarget)
    {
        ++pblock->nNonce;
        if (pblock->nNonce == 0)
            ++pblock->nTime;
        if (++nHashes > 4000000U)
            return false;
    }
    return true;
}

bool MineTo(int nTarget)
{
    unsigned int nExtraNonce = 0;
    while (BestIndex() != NULL && BestIndex()->nHeight < nTarget)
    {
        CBlockIndex* pindexPrev = BestIndex();
        std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
        if (pblock.get() == NULL)
            return false;
        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
        if (!GrindHeader(pblock.get()))
            return false;
        if (!ProcessBlock(NULL, pblock.get()))
            return false;
        if (BestIndex()->nHeight != pindexPrev->nHeight + 1)
            return false;
    }
    return BestIndex() != NULL && BestIndex()->nHeight >= nTarget;
}

void SetVerifiedHeight(int nHeight)
{
    CTxDB txdb("rw");
    BOOST_REQUIRE(txdb.WritePrivacyVNextVerifiedHeight(nHeight));
}

// A chain, a floor, and a gate open to the tip -- which is the only configuration in which
// the walk has a body to run.
struct OpenWalk
{
    RegtestBoundaryBGuard boundary;
    VerifiedHeightGuard progress;
    std::unique_ptr<CArgOverride> gate;
    int nFloor;
    int nTip;

    explicit OpenWalk(int nBlocks)
    {
        BOOST_REQUIRE(fRegTest);
        BOOST_REQUIRE(BestIndex() != NULL);
        BOOST_REQUIRE_MESSAGE(MineTo(BestIndex()->nHeight + nBlocks),
                              "could not extend the fixture chain");
        nTip = BestIndex()->nHeight;
        nFloor = nTip - nBlocks + 1;
        BOOST_REQUIRE(nFloor > 0);
        nRegtestBoundaryBHeight = nFloor;
        BOOST_REQUIRE(IsBoundaryBConfigured());
        // The tip itself, so every block at or below it is an ancestor of the named hash.
        gate.reset(new CArgOverride("-assumevalid",
                                    BestIndex()->GetBlockHash().ToString()));
        BOOST_REQUIRE_MESSAGE(IsPrivacyVNextAssumeValidAncestor(BestIndex()),
                              "the gate did not open, so the walk has no body to run");
        SetVerifiedHeight(nFloor - 1);
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(background_verify_walk_tests)

// Every height from the floor to the tip, once each, in order, however the passes are cut.
BOOST_AUTO_TEST_CASE(the_walk_covers_every_height_once)
{
    OpenWalk walk(12);
    const int nExpected = walk.nTip - walk.nFloor + 1;

    int nTotal = 0;
    int nLastSeen = walk.nFloor - 1;
    for (int nPass = 0; nPass < 40; ++nPass)
    {
        int nVerified = 0;
        std::string strError;
        BOOST_REQUIRE_MESSAGE(RunPrivacyVNextBackgroundVerification(5, nVerified, strError),
                              strError);
        if (nVerified == 0)
            break;
        BOOST_CHECK_MESSAGE(nVerified <= 5,
                            "a pass walked " << nVerified << " blocks for a bound of 5");
        nTotal += nVerified;
        const int nNow = GetPrivacyVNextVerifiedHeight();
        BOOST_CHECK_MESSAGE(nNow == nLastSeen + nVerified,
                            "progress moved from " << nLastSeen << " to " << nNow
                            << " for " << nVerified << " blocks, so a height was skipped "
                            "or counted twice");
        nLastSeen = nNow;
    }
    BOOST_CHECK_EQUAL(nTotal, nExpected);
    BOOST_CHECK_EQUAL(GetPrivacyVNextVerifiedHeight(), walk.nTip);
}

// One pass longer than the read window. The window is an internal cut, so it must not
// show up as a skipped or repeated height.
BOOST_AUTO_TEST_CASE(a_pass_longer_than_the_window_is_still_contiguous)
{
    OpenWalk walk(20);
    const int nExpected = walk.nTip - walk.nFloor + 1;

    int nVerified = 0;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        RunPrivacyVNextBackgroundVerification(nExpected, nVerified, strError), strError);
    BOOST_CHECK_EQUAL(nVerified, nExpected);
    BOOST_CHECK_EQUAL(GetPrivacyVNextVerifiedHeight(), walk.nTip);

    // And it is finished: a further pass walks nothing rather than going round again.
    int nAgain = 0;
    BOOST_REQUIRE(RunPrivacyVNextBackgroundVerification(nExpected, nAgain, strError));
    BOOST_CHECK_EQUAL(nAgain, 0);
}

// It starts where it left off, not at the floor, so a restart does not re-prove history.
BOOST_AUTO_TEST_CASE(the_walk_resumes_where_it_stopped)
{
    OpenWalk walk(10);

    int nFirst = 0;
    std::string strError;
    BOOST_REQUIRE(RunPrivacyVNextBackgroundVerification(3, nFirst, strError));
    BOOST_CHECK_EQUAL(nFirst, 3);
    const int nAfterFirst = GetPrivacyVNextVerifiedHeight();
    BOOST_CHECK_EQUAL(nAfterFirst, walk.nFloor + 2);

    int nSecond = 0;
    BOOST_REQUIRE(RunPrivacyVNextBackgroundVerification(3, nSecond, strError));
    BOOST_CHECK_EQUAL(nSecond, 3);
    BOOST_CHECK_EQUAL(GetPrivacyVNextVerifiedHeight(), nAfterFirst + 3);
}

// With the gate shut there is nothing owed. The walk must not crawl the chain proving
// blocks that were already proved when they connected.
BOOST_AUTO_TEST_CASE(a_shut_gate_finishes_the_walk_outright)
{
    OpenWalk walk(6);
    {
        CArgOverride shut("-assumevalid", "0");
        BOOST_REQUIRE(!IsPrivacyVNextAssumeValidAncestor(BestIndex()));
        int nVerified = 0;
        std::string strError;
        BOOST_REQUIRE(RunPrivacyVNextBackgroundVerification(100, nVerified, strError));
        BOOST_CHECK_MESSAGE(nVerified == 0,
                            "the walk re-proved " << nVerified << " blocks the gate never "
                            "skipped");
        BOOST_CHECK_EQUAL(GetPrivacyVNextVerifiedHeight(), nBestHeight);
    }
}

// The floor is where payloads begin. Below it there is nothing to prove, and a walk that
// started at zero would read the whole pre-boundary chain for nothing.
BOOST_AUTO_TEST_CASE(the_walk_starts_at_the_boundary_not_at_zero)
{
    OpenWalk walk(8);
    SetVerifiedHeight(0);
    BOOST_REQUIRE(GetPrivacyVNextVerifiedHeight() < walk.nFloor);

    int nVerified = 0;
    std::string strError;
    BOOST_REQUIRE(RunPrivacyVNextBackgroundVerification(2, nVerified, strError));
    BOOST_CHECK_EQUAL(nVerified, 2);
    BOOST_CHECK_MESSAGE(GetPrivacyVNextVerifiedHeight() == walk.nFloor + 1,
                        "the walk started below the boundary, so it read blocks that "
                        "carry no payload at all");
}

// The walk's own chain carries no payload on regtest, so the window loop above proves the
// bookkeeping and this proves what the window hands to the warm pass. Between them there
// is no half that is wired but never run.
BOOST_AUTO_TEST_CASE(the_warm_set_is_every_payload_in_window_order)
{
    std::vector<std::pair<int, CBlock> > vWindow;

    // Payloads in the first and last block with an empty block between, so stopping early
    // gives a strict subset. The last block also has a vNext tx with no payload.
    const unsigned char vTags[3][3] = {
        { 0x01, 0x00, 0x02 },   // payload, plain, payload
        { 0x00, 0x00, 0x00 },   // no payloads at all
        { 0x00, 0x03, 0xFF },   // plain, payload, vNext with an empty payload
    };
    for (int b = 0; b < 3; ++b)
    {
        CBlock block;
        for (int i = 0; i < 3; ++i)
        {
            CTransaction tx;
            const unsigned char chTag = vTags[b][i];
            if (chTag == 0x00)
            {
                tx.nVersion = 1;
            }
            else if (chTag == 0xFF)
            {
                tx.nVersion = SHIELDED_TX_VERSION_DSP;
                tx.privacyVNext.vchPayload.clear();
            }
            else
            {
                tx.nVersion = SHIELDED_TX_VERSION_DSP;
                tx.privacyVNext.vchPayload.assign(4, chTag);
            }
            block.vtx.push_back(tx);
        }
        vWindow.push_back(std::make_pair(100 + b, block));
    }

    std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> > vWarm;
    CollectPrivacyVNextWarmSet(vWindow, vWarm);

    BOOST_REQUIRE_EQUAL(vWarm.size(), 3u);
    // Block order, then transaction order.
    BOOST_CHECK_EQUAL((int)(*vWarm[0].second)[0], 0x01);
    BOOST_CHECK_EQUAL((int)(*vWarm[1].second)[0], 0x02);
    BOOST_CHECK_MESSAGE((int)(*vWarm[2].second)[0] == 0x03,
                        "a payload in a later block of the window was not collected, so "
                        "every block after the first is verified cold");
    for (size_t i = 0; i < vWarm.size(); ++i)
        BOOST_CHECK_EQUAL((int)vWarm[i].first, SHIELDED_TX_VERSION_DSP);

    // The pointers are into the window, not into a copy: a warm pass reading a dangling
    // one would be reading whatever the allocator left behind.
    BOOST_CHECK(vWarm[0].second == &vWindow[0].second.vtx[0].privacyVNext.vchPayload);
    BOOST_CHECK(vWarm[2].second == &vWindow[2].second.vtx[1].privacyVNext.vchPayload);

    std::vector<std::pair<int, CBlock> > vEmpty;
    CollectPrivacyVNextWarmSet(vEmpty, vWarm);
    BOOST_CHECK(vWarm.empty());
}

BOOST_AUTO_TEST_SUITE_END()
