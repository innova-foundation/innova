// Millisecond block-timestamp commitment (coinbase OP_RETURN): codec, gate placement and
// AcceptBlock rules. Cases move the -regtestmstimestamp gate, so no absolute height is
// asserted; they mine, so this links near the end of TEST_OBJS.

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

#include "../bignum.h"
#include "../dag.h"
#include "../init.h"
#include "../main.h"
#include "../miner.h"
#include "../mstimestamp.h"
#include "../script.h"
#include "../uint256.h"
#include "../v5activation.h"
#include "../wallet.h"

extern bool fRegTest;
extern bool fTestNet;

BOOST_AUTO_TEST_SUITE(ms_timestamp_tests)

namespace
{

// Payload with an independently chosen offset, so a value the encoder refuses
// to produce can still be presented to the decoder.
std::vector<unsigned char> MakePayload(unsigned int nMs)
{
    std::vector<unsigned char> vch(MS_TIMESTAMP_TAG, MS_TIMESTAMP_TAG + 4);
    vch.push_back((unsigned char)(nMs & 0xff));
    vch.push_back((unsigned char)((nMs >> 8) & 0xff));
    return vch;
}

CScript WrapPayload(const std::vector<unsigned char>& vchPayload)
{
    CScript script;
    script << OP_RETURN << vchPayload;
    return script;
}

// Same payload, deliberately non-minimal push opcode.
CScript WrapPayloadWithOpcode(const std::vector<unsigned char>& vchPayload,
                              opcodetype pushOpcode)
{
    CScript script;
    script.push_back(OP_RETURN);
    script.push_back(pushOpcode);
    const unsigned int nSize = (unsigned int)vchPayload.size();
    if (pushOpcode == OP_PUSHDATA1)
        script.push_back((unsigned char)nSize);
    else if (pushOpcode == OP_PUSHDATA2)
        for (int i = 0; i < 2; ++i)
            script.push_back((unsigned char)((nSize >> (8 * i)) & 0xff));
    script.insert(script.end(), vchPayload.begin(), vchPayload.end());
    return script;
}

std::vector<CScript> CoinbaseScripts(const CBlock& block)
{
    std::vector<CScript> vScripts;
    if (block.vtx.empty())
        return vScripts;
    for (unsigned int i = 0; i < block.vtx[0].vout.size(); ++i)
        vScripts.push_back(block.vtx[0].vout[i].scriptPubKey);
    return vScripts;
}

// Index of the coinbase output the strict decoder reacts to at all, well
// formed or not.
int FindMsOutput(const CBlock& block)
{
    if (block.vtx.empty())
        return -1;
    for (unsigned int i = 0; i < block.vtx[0].vout.size(); ++i)
    {
        uint16_t nDecoded = 0;
        std::string strError;
        if (DecodeCanonicalMsTimestampScript(block.vtx[0].vout[i].scriptPubKey,
                                             nDecoded, strError) !=
            MS_TIMESTAMP_NOT_FOUND)
            return (int)i;
    }
    return -1;
}

bool SolveBlock(CBlock* pblock)
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

CBlockIndex* BestIndex()
{
    LOCK(cs_main);
    return pindexBest;
}

// Moves the regtest gate for one case and puts it back. The gate is read
// through GetForkHeightMsTimestamp on every consultation, so a boundary can be
// placed relative to wherever the shared chain already is.
struct MsGateGuard
{
    int nSaved;
    explicit MsGateGuard(int nHeight) : nSaved(nRegtestMsTimestampHeight)
    {
        nRegtestMsTimestampHeight = nHeight;
    }
    ~MsGateGuard() { nRegtestMsTimestampHeight = nSaved; }
};

// Extend the chain by one block and return it. The template is built under
// whatever gate is currently set.
std::unique_ptr<CBlock> MineOne()
{
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (!pblock.get())
        return pblock;
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    if (!SolveBlock(pblock.get()))
        return std::unique_ptr<CBlock>();
    const uint256 hash = pblock->GetHash();
    if (!ProcessBlock(NULL, pblock.get()))
        return std::unique_ptr<CBlock>();
    LOCK(cs_main);
    if (!mapBlockIndex.count(hash))
        return std::unique_ptr<CBlock>();
    return pblock;
}

void MineTo(int nTarget)
{
    while (BestIndex()->nHeight < nTarget)
        BOOST_REQUIRE(MineOne().get() != NULL);
}

// A solved template on the current tip, ready to be mutated and offered to
// AcceptBlock directly.
std::unique_ptr<CBlock> BuildTemplate()
{
    CBlockIndex* pindexPrev = BestIndex();
    std::unique_ptr<CBlock> pblock(CreateNewBlock(pwalletMain));
    if (!pblock.get())
        return pblock;
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);
    return pblock;
}

CBlockIndex* IndexFor(const uint256& hash)
{
    LOCK(cs_main);
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    return mi == mapBlockIndex.end() ? NULL : mi->second;
}

} // namespace


// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

// Positive control for every codec case below: the encoder's own output
// round-trips across the whole legal range, at both ends and across the
// low-byte carry.
BOOST_AUTO_TEST_CASE(the_encoder_round_trips_every_legal_offset)
{
    const unsigned int nOffsets[] = { 0, 1, 254, 255, 256, 500, 998, 999 };
    for (size_t i = 0; i < sizeof(nOffsets) / sizeof(nOffsets[0]); ++i)
    {
        const uint16_t nMs = (uint16_t)nOffsets[i];
        const CScript script = BuildMsTimestampScript(nMs);
        BOOST_REQUIRE_MESSAGE(script.size() == 8U,
                              "offset " << nOffsets[i] << " encoded to "
                                        << script.size() << " bytes");
        uint16_t nDecoded = 0;
        std::string strError;
        BOOST_CHECK_EQUAL(
            DecodeCanonicalMsTimestampScript(script, nDecoded, strError),
            MS_TIMESTAMP_VALID);
        BOOST_CHECK_EQUAL(strError, std::string());
        BOOST_CHECK_EQUAL((unsigned int)nDecoded, nOffsets[i]);
        // The whole point of the field: it separates two blocks inside one
        // labelled second.
        BOOST_CHECK_EQUAL(MsTimestampCombine(1700000000U, nDecoded),
                          1700000000LL * 1000 + (int64_t)nOffsets[i]);
    }
}

// The two ends of the range are accepted, and the first value past the end is
// rejected for being past the end -- not for some incidental encoding fault.
BOOST_AUTO_TEST_CASE(zero_and_nine_hundred_ninety_nine_are_accepted_and_a_thousand_is_not)
{
    uint16_t nDecoded = 0;
    std::string strError;

    BOOST_CHECK_EQUAL(
        DecodeCanonicalMsTimestampScript(WrapPayload(MakePayload(0)),
                                         nDecoded, strError),
        MS_TIMESTAMP_VALID);
    BOOST_CHECK_EQUAL((unsigned int)nDecoded, 0U);
    BOOST_CHECK_EQUAL(
        DecodeCanonicalMsTimestampScript(WrapPayload(MakePayload(999)),
                                         nDecoded, strError),
        MS_TIMESTAMP_VALID);
    BOOST_CHECK_EQUAL((unsigned int)nDecoded, 999U);

    const unsigned int nOverRange[] = { 1000, 1001, 4096, 32768, 65535 };
    for (size_t i = 0; i < sizeof(nOverRange) / sizeof(nOverRange[0]); ++i)
    {
        strError.clear();
        BOOST_CHECK_EQUAL(
            DecodeCanonicalMsTimestampScript(
                WrapPayload(MakePayload(nOverRange[i])), nDecoded, strError),
            MS_TIMESTAMP_MALFORMED);
        BOOST_CHECK_MESSAGE(
            strError.find("outside 0..999") != std::string::npos,
            "offset " << nOverRange[i] << " was rejected for the wrong reason: "
                      << strError);
    }

    // The encoder refuses to produce one, so an over-range commitment can only
    // be hand-built.
    BOOST_CHECK(BuildMsTimestampScript((uint16_t)1000).empty());
    BOOST_CHECK(BuildMsTimestampScript((uint16_t)65535).empty());
}

// A tagged payload of the wrong length is malformed, not invisible: shortening
// or padding it must not turn a commitment into an unrelated OP_RETURN.
BOOST_AUTO_TEST_CASE(a_tagged_payload_of_the_wrong_length_is_malformed)
{
    uint16_t nDecoded = 0;
    std::string strError;

    // Positive control on the same wrapper.
    BOOST_REQUIRE_EQUAL(
        DecodeCanonicalMsTimestampScript(WrapPayload(MakePayload(123)),
                                         nDecoded, strError),
        MS_TIMESTAMP_VALID);

    std::vector<unsigned char> vShort = MakePayload(123);
    vShort.pop_back();
    strError.clear();
    BOOST_CHECK_EQUAL(
        DecodeCanonicalMsTimestampScript(WrapPayload(vShort), nDecoded, strError),
        MS_TIMESTAMP_MALFORMED);
    BOOST_CHECK(strError.find("payload length") != std::string::npos);

    std::vector<unsigned char> vLong = MakePayload(123);
    vLong.push_back(0x00);
    strError.clear();
    BOOST_CHECK_EQUAL(
        DecodeCanonicalMsTimestampScript(WrapPayload(vLong), nDecoded, strError),
        MS_TIMESTAMP_MALFORMED);
    BOOST_CHECK(strError.find("payload length") != std::string::npos);

    // Tag alone, no offset at all.
    std::vector<unsigned char> vTagOnly(MS_TIMESTAMP_TAG, MS_TIMESTAMP_TAG + 4);
    strError.clear();
    BOOST_CHECK_EQUAL(
        DecodeCanonicalMsTimestampScript(WrapPayload(vTagOnly), nDecoded, strError),
        MS_TIMESTAMP_MALFORMED);
}

// A non-minimal push of a tagged payload is malformed rather than unread, so
// the same offset has exactly one valid encoding.
BOOST_AUTO_TEST_CASE(a_non_minimal_push_is_malformed)
{
    uint16_t nDecoded = 0;
    std::string strError;

    const std::vector<unsigned char> vchPayload = MakePayload(777);
    BOOST_REQUIRE_EQUAL(
        DecodeCanonicalMsTimestampScript(WrapPayload(vchPayload), nDecoded, strError),
        MS_TIMESTAMP_VALID);
    BOOST_REQUIRE_EQUAL((unsigned int)nDecoded, 777U);

    const opcodetype vOpcodes[] = { OP_PUSHDATA1, OP_PUSHDATA2 };
    for (size_t i = 0; i < sizeof(vOpcodes) / sizeof(vOpcodes[0]); ++i)
    {
        strError.clear();
        BOOST_CHECK_EQUAL(
            DecodeCanonicalMsTimestampScript(
                WrapPayloadWithOpcode(vchPayload, vOpcodes[i]), nDecoded, strError),
            MS_TIMESTAMP_MALFORMED);
        BOOST_CHECK_MESSAGE(
            strError.find("non-canonical") != std::string::npos,
            "opcode " << (int)vOpcodes[i] << ": " << strError);
    }
}

// Anything appended after the payload is malformed, so the commitment owns the
// whole script and cannot be hidden inside a larger one.
BOOST_AUTO_TEST_CASE(trailing_script_operations_are_malformed)
{
    uint16_t nDecoded = 0;
    std::string strError;

    CScript scriptGood = WrapPayload(MakePayload(42));
    BOOST_REQUIRE_EQUAL(
        DecodeCanonicalMsTimestampScript(scriptGood, nDecoded, strError),
        MS_TIMESTAMP_VALID);

    CScript scriptTrailing = scriptGood;
    scriptTrailing << OP_TRUE;
    strError.clear();
    BOOST_CHECK_EQUAL(
        DecodeCanonicalMsTimestampScript(scriptTrailing, nDecoded, strError),
        MS_TIMESTAMP_MALFORMED);
    BOOST_CHECK(strError.find("trailing") != std::string::npos);
}

// An OP_RETURN that does not carry the tag is invisible here, and carries no
// error: that is what keeps a coinbase able to hold other data outputs.
BOOST_AUTO_TEST_CASE(an_untagged_output_is_not_found)
{
    uint16_t nDecoded = 0;
    std::string strError;

    BOOST_REQUIRE_EQUAL(
        DecodeCanonicalMsTimestampScript(WrapPayload(MakePayload(5)),
                                         nDecoded, strError),
        MS_TIMESTAMP_VALID);

    std::vector<CScript> vOther;
    vOther.push_back(CScript());
    vOther.push_back(CScript() << OP_RETURN);
    std::vector<unsigned char> vchWrongTag = MakePayload(5);
    vchWrongTag[0] = 0x58;
    vOther.push_back(WrapPayload(vchWrongTag));
    vOther.push_back(CScript() << OP_DUP << OP_HASH160);

    for (size_t i = 0; i < vOther.size(); ++i)
    {
        strError.clear();
        BOOST_CHECK_MESSAGE(
            DecodeCanonicalMsTimestampScript(vOther[i], nDecoded, strError) ==
                MS_TIMESTAMP_NOT_FOUND,
            "script " << i << " was not classified NOT_FOUND");
        BOOST_CHECK_EQUAL(strError, std::string());
    }
}

// The two coinbase commitments are separately tagged and must stay mutually
// invisible: post-DAG a coinbase carries both, and either decoder reacting to
// the other's output would make one of them unrepresentable.
BOOST_AUTO_TEST_CASE(the_dag_and_ms_decoders_ignore_each_other)
{
    std::vector<uint256> vParents;
    vParents.push_back(uint256(1));
    vParents.push_back(uint256(2));
    const CScript scriptDAG = BuildDAGParentScript(vParents);
    const CScript scriptMs = BuildMsTimestampScript(321);
    BOOST_REQUIRE(!scriptDAG.empty());
    BOOST_REQUIRE(!scriptMs.empty());

    uint16_t nMs = 0;
    std::string strError;
    BOOST_CHECK_EQUAL(
        DecodeCanonicalMsTimestampScript(scriptDAG, nMs, strError),
        MS_TIMESTAMP_NOT_FOUND);
    BOOST_CHECK_EQUAL(strError, std::string());

    std::vector<uint256> vDecodedParents;
    strError.clear();
    BOOST_CHECK_EQUAL(
        DecodeCanonicalDAGParentScript(scriptMs, vDecodedParents, strError),
        DAG_PARENT_NOT_FOUND);
    BOOST_CHECK_EQUAL(strError, std::string());

    // Both in one coinbase: each extractor finds its own and only its own.
    std::vector<CScript> vScripts;
    vScripts.push_back(CScript());
    vScripts.push_back(scriptDAG);
    vScripts.push_back(scriptMs);

    nMs = 0;
    strError.clear();
    BOOST_CHECK(ExtractCanonicalMsTimestampCommitment(vScripts, nMs, strError));
    BOOST_CHECK_EQUAL((unsigned int)nMs, 321U);

    vDecodedParents.clear();
    strError.clear();
    BOOST_CHECK(ExtractCanonicalDAGParentCommitment(vScripts, vDecodedParents, strError));
    BOOST_CHECK_EQUAL(vDecodedParents.size(), 2U);
}

// Exactly one commitment: none and two are both rejected, and a malformed one
// alongside a good one is rejected for the malformed reason rather than
// silently accepting the good one.
BOOST_AUTO_TEST_CASE(the_extractor_requires_exactly_one_commitment)
{
    uint16_t nMs = 0;
    std::string strError;

    std::vector<CScript> vOne;
    vOne.push_back(CScript());
    vOne.push_back(BuildMsTimestampScript(600));
    BOOST_REQUIRE(ExtractCanonicalMsTimestampCommitment(vOne, nMs, strError));
    BOOST_REQUIRE_EQUAL((unsigned int)nMs, 600U);

    std::vector<CScript> vNone;
    vNone.push_back(CScript());
    std::vector<uint256> vParents(1, uint256(4));
    vNone.push_back(BuildDAGParentScript(vParents));
    nMs = 0;
    strError.clear();
    BOOST_CHECK(!ExtractCanonicalMsTimestampCommitment(vNone, nMs, strError));
    BOOST_CHECK(strError.find("missing") != std::string::npos);

    std::vector<CScript> vTwo;
    vTwo.push_back(BuildMsTimestampScript(600));
    vTwo.push_back(BuildMsTimestampScript(601));
    nMs = 0;
    strError.clear();
    BOOST_CHECK(!ExtractCanonicalMsTimestampCommitment(vTwo, nMs, strError));
    BOOST_CHECK(strError.find("multiple") != std::string::npos);

    // Two copies of the same offset are still two commitments.
    std::vector<CScript> vDuplicate;
    vDuplicate.push_back(BuildMsTimestampScript(600));
    vDuplicate.push_back(BuildMsTimestampScript(600));
    nMs = 0;
    strError.clear();
    BOOST_CHECK(!ExtractCanonicalMsTimestampCommitment(vDuplicate, nMs, strError));
    BOOST_CHECK(strError.find("multiple") != std::string::npos);

    std::vector<CScript> vMixed;
    vMixed.push_back(BuildMsTimestampScript(600));
    vMixed.push_back(WrapPayload(MakePayload(1000)));
    nMs = 0;
    strError.clear();
    BOOST_CHECK(!ExtractCanonicalMsTimestampCommitment(vMixed, nMs, strError));
    BOOST_CHECK(strError.find("outside 0..999") != std::string::npos);
}

// The below-gate absence rule keys on the tag, not on well-formedness: a
// malformed tagged output below the gate is still a commitment.
BOOST_AUTO_TEST_CASE(presence_covers_malformed_commitments_too)
{
    std::vector<CScript> vAbsent;
    vAbsent.push_back(CScript());
    std::vector<uint256> vParents(1, uint256(9));
    vAbsent.push_back(BuildDAGParentScript(vParents));
    BOOST_CHECK(!MsTimestampCommitmentPresent(vAbsent));

    std::vector<CScript> vValid = vAbsent;
    vValid.push_back(BuildMsTimestampScript(12));
    BOOST_CHECK(MsTimestampCommitmentPresent(vValid));

    std::vector<CScript> vMalformed = vAbsent;
    vMalformed.push_back(WrapPayload(MakePayload(1000)));
    BOOST_CHECK(MsTimestampCommitmentPresent(vMalformed));

    std::vector<CScript> vNonCanonical = vAbsent;
    vNonCanonical.push_back(WrapPayloadWithOpcode(MakePayload(12), OP_PUSHDATA1));
    BOOST_CHECK(MsTimestampCommitmentPresent(vNonCanonical));
}


// ---------------------------------------------------------------------------
// Gate placement
// ---------------------------------------------------------------------------

// The mainnet rung: derived from the shift, a multiple of 5,000, strictly
// between the IDNS reset and POEM, and adjacent to no other gate.
BOOST_AUTO_TEST_CASE(the_mainnet_gate_sits_between_the_idns_reset_and_poem)
{
    const bool fRegTestSaved = fRegTest;
    const bool fTestNetSaved = fTestNet;
    fRegTest = false;
    fTestNet = false;

    const int nGate = GetForkHeightMsTimestamp();
    BOOST_CHECK_EQUAL(nGate, ShiftMainnetV5Activation(7920000));
    BOOST_CHECK_EQUAL((nGate - MAINNET_V5_ACTIVATION_SHIFT) % 5000, 0);

    BOOST_CHECK_GT(nGate, GetForkHeightIDNSReset());
    BOOST_CHECK_LT(nGate, GetForkHeightPoem());
    BOOST_CHECK_LT(nGate, GetForkHeightDAG());

    // Separated from the rungs on either side, and from the DAG fork: the
    // point of the placement is a soak window at 15-second spacing, not a
    // gate that activates alongside another one.
    BOOST_CHECK_EQUAL(nGate - GetForkHeightIDNSReset(), 20000);
    BOOST_CHECK_EQUAL(GetForkHeightPoem() - nGate, 20000);
    BOOST_CHECK_EQUAL(GetForkHeightDAG() - nGate, 30000);

    // The absence rule is bounded at the v5 first gate rather than at genesis,
    // so a resync does not replay a new rejection over pre-v5 history.
    BOOST_CHECK_EQUAL(GetMsTimestampAbsenceFloor(),
                      ShiftMainnetV5Activation(MAINNET_V5_ACTIVATION_BASE));
    BOOST_CHECK_LT(GetMsTimestampAbsenceFloor(), nGate);

    const int nOthers[] = {
        GetForkHeightShielded(), GetForkHeightDSP(), GetForkHeightNullSend(),
        GetForkHeightNullStake(), GetForkHeightNullStakeV2(),
        GetForkHeightNullStakeV3(), GetForkHeightChaumianCJ(),
        GetForkHeightIDNSReset(), GetForkHeightPoem(), GetForkHeightFinality(),
        GetForkHeightDAG(), GetForkHeightDAGKnight(),
    };
    for (size_t i = 0; i < sizeof(nOthers) / sizeof(nOthers[0]); ++i)
        BOOST_CHECK_MESSAGE(nOthers[i] != nGate,
                            "another mainnet gate shares height " << nGate);

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;
}

// Off mainnet the gate has to leave a pre-gate window and still land below the
// DAG fork, so both eras are reachable on a chain that remines from genesis.
BOOST_AUTO_TEST_CASE(the_regtest_and_testnet_gates_precede_their_dag_gates)
{
    const bool fRegTestSaved = fRegTest;
    const bool fTestNetSaved = fTestNet;

    fRegTest = false;
    fTestNet = true;
    BOOST_CHECK_EQUAL(GetForkHeightMsTimestamp(), 30);
    BOOST_CHECK_LT(GetForkHeightMsTimestamp(), GetForkHeightDAG());
    BOOST_CHECK_GT(GetForkHeightMsTimestamp(), 1);
    BOOST_CHECK_EQUAL(GetMsTimestampAbsenceFloor(), 1);

    fRegTest = true;
    fTestNet = false;
    {
        MsGateGuard guard(9);
        BOOST_CHECK_EQUAL(GetForkHeightMsTimestamp(), 9);
        BOOST_CHECK_LT(GetForkHeightMsTimestamp(), GetForkHeightDAG());
    }
    // The override is what the boundary cases below steer.
    {
        MsGateGuard guard(12345);
        BOOST_CHECK_EQUAL(GetForkHeightMsTimestamp(), 12345);
    }
    BOOST_CHECK_EQUAL(GetMsTimestampAbsenceFloor(), 1);

    fRegTest = fRegTestSaved;
    fTestNet = fTestNetSaved;
}


// ---------------------------------------------------------------------------
// t_ms ordering
// ---------------------------------------------------------------------------

// Two blocks sharing one labelled second are strictly ordered in t_ms and not by
// nTime. A property of the arithmetic, not enforced on chain.
BOOST_AUTO_TEST_CASE(t_ms_orders_a_series_that_shares_one_second)
{
    struct Sample { unsigned int nTime; uint16_t nTimeMs; };
    const Sample vSeries[] = {
        { 1700000000U,   0 },
        { 1700000000U, 250 },   // same labelled second as the one before
        { 1700000000U, 500 },
        { 1700000000U, 999 },
        { 1700000001U,   0 },   // one millisecond after the one before
        { 1700000001U, 400 },
        { 1700000003U,  10 },
    };
    const size_t nCount = sizeof(vSeries) / sizeof(vSeries[0]);

    std::vector<CBlockIndex> vIndex(nCount);
    for (size_t i = 0; i < nCount; ++i)
    {
        vIndex[i].nTime = vSeries[i].nTime;
        vIndex[i].nTimeMs = vSeries[i].nTimeMs;
    }

    bool fSecondsStrictlyIncrease = true;
    for (size_t i = 1; i < nCount; ++i)
    {
        BOOST_CHECK_MESSAGE(
            vIndex[i].GetBlockTimeMs() > vIndex[i - 1].GetBlockTimeMs(),
            "t_ms did not advance at index " << i);
        BOOST_CHECK_EQUAL(vIndex[i].GetBlockTimeMs(),
                          (int64_t)vSeries[i].nTime * 1000 +
                              (int64_t)vSeries[i].nTimeMs);
        if (vIndex[i].GetBlockTime() <= vIndex[i - 1].GetBlockTime())
            fSecondsStrictlyIncrease = false;
    }
    // Without the offset three of these pairs are indistinguishable in time.
    BOOST_CHECK(!fSecondsStrictlyIncrease);

    // The step across the second boundary is one millisecond, which is the
    // resolution the field exists to provide.
    BOOST_CHECK_EQUAL(vIndex[4].GetBlockTimeMs() - vIndex[3].GetBlockTimeMs(), 1);

    // Below the gate nTimeMs is 0, so t_ms degenerates to the scaled second and
    // orders exactly as nTime does.
    CBlockIndex belowA, belowB;
    belowA.nTime = 1700000000U;
    belowB.nTime = 1700000001U;
    BOOST_CHECK_EQUAL(belowA.nTimeMs, 0);
    BOOST_CHECK_EQUAL(belowB.nTimeMs, 0);
    BOOST_CHECK_EQUAL(belowA.GetBlockTimeMs(), belowA.GetBlockTime() * 1000);
    BOOST_CHECK_LT(belowA.GetBlockTimeMs(), belowB.GetBlockTimeMs());
}


// ---------------------------------------------------------------------------
// Block rules
// ---------------------------------------------------------------------------

// Positive control: with the gate two blocks ahead, the block below it has no commitment,
// and the block on it has exactly one, matching the index.
BOOST_AUTO_TEST_CASE(the_boundary_blocks_carry_what_their_heights_require)
{
    BOOST_REQUIRE(fRegTest);
    const int nBase = BestIndex()->nHeight;
    MsGateGuard guard(nBase + 2);

    std::unique_ptr<CBlock> pBelow(MineOne());
    BOOST_REQUIRE(pBelow.get() != NULL);
    BOOST_REQUIRE_EQUAL(BestIndex()->nHeight, nBase + 1);
    BOOST_CHECK_LT(BestIndex()->nHeight, FORK_HEIGHT_MS_TIMESTAMP);
    BOOST_CHECK_EQUAL(FindMsOutput(*pBelow), -1);
    BOOST_CHECK(!MsTimestampCommitmentPresent(CoinbaseScripts(*pBelow)));
    CBlockIndex* pindexBelow = IndexFor(pBelow->GetHash());
    BOOST_REQUIRE(pindexBelow != NULL);
    BOOST_CHECK_EQUAL(pindexBelow->nTimeMs, 0);
    BOOST_CHECK_EQUAL(pindexBelow->GetBlockTimeMs(),
                      pindexBelow->GetBlockTime() * 1000);

    // The block landing exactly on the gate. The template is checked, then its offset
    // is overwritten with a nonzero value, since a regtest offset floors at 0 and
    // comparing against 0 would pass without the cache.
    std::unique_ptr<CBlock> pAt(BuildTemplate());
    BOOST_REQUIRE(pAt.get() != NULL);

    const int nOut = FindMsOutput(*pAt);
    BOOST_REQUIRE_MESSAGE(nOut >= 0,
                          "the block at the gate carries no commitment");
    // On a proof-of-stake carrier the commitment cannot occupy vout[0]; the
    // producer appends, so it never does on either carrier.
    BOOST_CHECK_GE(nOut, 1);
    BOOST_CHECK_EQUAL(pAt->vtx[0].vout[nOut].nValue, 0);

    const uint16_t nForced = 617;
    BOOST_REQUIRE_NE(nForced, 0);
    pAt->vtx[0].vout[nOut].scriptPubKey = BuildMsTimestampScript(nForced);
    pAt->hashMerkleRoot = pAt->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pAt.get()));
    const uint256 hashAt = pAt->GetHash();
    BOOST_REQUIRE(ProcessBlock(NULL, pAt.get()));
    BOOST_REQUIRE_EQUAL(BestIndex()->nHeight, nBase + 2);
    BOOST_CHECK_EQUAL(BestIndex()->nHeight, FORK_HEIGHT_MS_TIMESTAMP);

    uint16_t nCommitted = 0;
    std::string strError;
    BOOST_REQUIRE(ExtractCanonicalMsTimestampCommitment(CoinbaseScripts(*pAt),
                                                        nCommitted, strError));
    BOOST_CHECK_EQUAL(nCommitted, nForced);
    BOOST_CHECK_LE((unsigned int)nCommitted, MS_TIMESTAMP_MAX);

    CBlockIndex* pindexAt = IndexFor(hashAt);
    BOOST_REQUIRE(pindexAt != NULL);
    BOOST_REQUIRE_EQUAL(pindexAt->nHeight, FORK_HEIGHT_MS_TIMESTAMP);
    // The block on the gate itself, not one above it: a cache that starts one
    // block late reads 0 here.
    BOOST_CHECK_EQUAL(pindexAt->nTimeMs, nForced);
    BOOST_CHECK_EQUAL(pindexAt->GetBlockTimeMs(),
                      MsTimestampCombine(pAt->nTime, nForced));
}

// At or above the gate a missing commitment is invalid. The positive control
// is the block the producer built, which is accepted unmodified.
BOOST_AUTO_TEST_CASE(a_missing_commitment_at_the_gate_is_rejected)
{
    BOOST_REQUIRE(fRegTest);
    const int nBase = BestIndex()->nHeight;
    MsGateGuard guard(nBase + 1);

    std::unique_ptr<CBlock> pGood(MineOne());
    BOOST_REQUIRE(pGood.get() != NULL);
    BOOST_REQUIRE_GE(BestIndex()->nHeight, FORK_HEIGHT_MS_TIMESTAMP);
    BOOST_REQUIRE(FindMsOutput(*pGood) >= 0);

    std::unique_ptr<CBlock> pblock(BuildTemplate());
    BOOST_REQUIRE(pblock.get() != NULL);
    const int nOut = FindMsOutput(*pblock);
    BOOST_REQUIRE(nOut >= 0);
    pblock->vtx[0].vout.erase(pblock->vtx[0].vout.begin() + nOut);
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pblock.get()));

    pblock->nDoS = 0;
    BOOST_CHECK(!pblock->AcceptBlock());
    BOOST_CHECK_EQUAL(pblock->nDoS, 100);
    BOOST_CHECK(IndexFor(pblock->GetHash()) == NULL);
}

// An offset past the end of a second is invalid at the gate, and rejected for
// being past the end.
BOOST_AUTO_TEST_CASE(an_over_range_commitment_at_the_gate_is_rejected)
{
    BOOST_REQUIRE(fRegTest);
    const int nBase = BestIndex()->nHeight;
    MsGateGuard guard(nBase + 1);

    std::unique_ptr<CBlock> pGood(MineOne());
    BOOST_REQUIRE(pGood.get() != NULL);
    BOOST_REQUIRE_GE(BestIndex()->nHeight, FORK_HEIGHT_MS_TIMESTAMP);

    // 999 is legal and 1000 is not; both are offered on the same chain tip so
    // the difference is the value and nothing else.
    std::unique_ptr<CBlock> pAtMax(BuildTemplate());
    BOOST_REQUIRE(pAtMax.get() != NULL);
    int nOut = FindMsOutput(*pAtMax);
    BOOST_REQUIRE(nOut >= 0);
    pAtMax->vtx[0].vout[nOut].scriptPubKey =
        BuildMsTimestampScript((uint16_t)MS_TIMESTAMP_MAX);
    pAtMax->hashMerkleRoot = pAtMax->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pAtMax.get()));
    const uint256 hashAtMax = pAtMax->GetHash();
    BOOST_CHECK(ProcessBlock(NULL, pAtMax.get()));
    CBlockIndex* pindexAtMax = IndexFor(hashAtMax);
    BOOST_REQUIRE(pindexAtMax != NULL);
    BOOST_CHECK_EQUAL(pindexAtMax->nTimeMs, (uint16_t)MS_TIMESTAMP_MAX);

    std::unique_ptr<CBlock> pOver(BuildTemplate());
    BOOST_REQUIRE(pOver.get() != NULL);
    nOut = FindMsOutput(*pOver);
    BOOST_REQUIRE(nOut >= 0);
    pOver->vtx[0].vout[nOut].scriptPubKey = WrapPayload(MakePayload(1000));
    pOver->hashMerkleRoot = pOver->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pOver.get()));

    pOver->nDoS = 0;
    BOOST_CHECK(!pOver->AcceptBlock());
    BOOST_CHECK_EQUAL(pOver->nDoS, 100);
    BOOST_CHECK(IndexFor(pOver->GetHash()) == NULL);
}

// Two commitments in one coinbase are invalid, so no block can name two
// different sub-second times for itself.
BOOST_AUTO_TEST_CASE(a_duplicated_commitment_at_the_gate_is_rejected)
{
    BOOST_REQUIRE(fRegTest);
    const int nBase = BestIndex()->nHeight;
    MsGateGuard guard(nBase + 1);

    std::unique_ptr<CBlock> pGood(MineOne());
    BOOST_REQUIRE(pGood.get() != NULL);
    BOOST_REQUIRE_GE(BestIndex()->nHeight, FORK_HEIGHT_MS_TIMESTAMP);
    BOOST_REQUIRE(FindMsOutput(*pGood) >= 0);

    std::unique_ptr<CBlock> pblock(BuildTemplate());
    BOOST_REQUIRE(pblock.get() != NULL);
    const int nOut = FindMsOutput(*pblock);
    BOOST_REQUIRE(nOut >= 0);
    CTxOut extra;
    extra.nValue = 0;
    extra.scriptPubKey = BuildMsTimestampScript(3);
    pblock->vtx[0].vout.push_back(extra);
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pblock.get()));

    pblock->nDoS = 0;
    BOOST_CHECK(!pblock->AcceptBlock());
    BOOST_CHECK_EQUAL(pblock->nDoS, 100);
    BOOST_CHECK(IndexFor(pblock->GetHash()) == NULL);
}

// A malformed commitment at the gate is invalid: a tagged output that does not
// decode cannot be treated as no commitment at all.
BOOST_AUTO_TEST_CASE(a_malformed_commitment_at_the_gate_is_rejected)
{
    BOOST_REQUIRE(fRegTest);
    const int nBase = BestIndex()->nHeight;
    MsGateGuard guard(nBase + 1);

    std::unique_ptr<CBlock> pGood(MineOne());
    BOOST_REQUIRE(pGood.get() != NULL);
    BOOST_REQUIRE_GE(BestIndex()->nHeight, FORK_HEIGHT_MS_TIMESTAMP);

    std::vector<CScript> vBad;
    vBad.push_back(WrapPayloadWithOpcode(MakePayload(7), OP_PUSHDATA1));
    std::vector<unsigned char> vShort = MakePayload(7);
    vShort.pop_back();
    vBad.push_back(WrapPayload(vShort));

    for (size_t i = 0; i < vBad.size(); ++i)
    {
        std::unique_ptr<CBlock> pblock(BuildTemplate());
        BOOST_REQUIRE(pblock.get() != NULL);
        const int nOut = FindMsOutput(*pblock);
        BOOST_REQUIRE(nOut >= 0);
        pblock->vtx[0].vout[nOut].scriptPubKey = vBad[i];
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();
        BOOST_REQUIRE(SolveBlock(pblock.get()));

        pblock->nDoS = 0;
        BOOST_CHECK_MESSAGE(!pblock->AcceptBlock(),
                            "malformed shape " << i << " was accepted");
        BOOST_CHECK_EQUAL(pblock->nDoS, 100);
        BOOST_CHECK(IndexFor(pblock->GetHash()) == NULL);
    }
}

// Below the gate the commitment must be absent. The positive control is the
// same height accepting a block with no commitment.
BOOST_AUTO_TEST_CASE(a_commitment_below_the_gate_is_rejected)
{
    BOOST_REQUIRE(fRegTest);
    const int nBase = BestIndex()->nHeight;
    MsGateGuard guard(nBase + 100);

    BOOST_REQUIRE_GE(nBase + 1, GetMsTimestampAbsenceFloor());

    std::unique_ptr<CBlock> pGood(MineOne());
    BOOST_REQUIRE(pGood.get() != NULL);
    BOOST_REQUIRE_LT(BestIndex()->nHeight, FORK_HEIGHT_MS_TIMESTAMP);
    BOOST_REQUIRE_EQUAL(FindMsOutput(*pGood), -1);

    // A well-formed commitment is still a commitment below the gate.
    std::unique_ptr<CBlock> pblock(BuildTemplate());
    BOOST_REQUIRE(pblock.get() != NULL);
    BOOST_REQUIRE_EQUAL(FindMsOutput(*pblock), -1);
    CTxOut msOut;
    msOut.nValue = 0;
    msOut.scriptPubKey = BuildMsTimestampScript(250);
    pblock->vtx[0].vout.push_back(msOut);
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pblock.get()));

    pblock->nDoS = 0;
    BOOST_CHECK(!pblock->AcceptBlock());
    BOOST_CHECK_EQUAL(pblock->nDoS, 100);
    BOOST_CHECK(IndexFor(pblock->GetHash()) == NULL);

    // And so is a malformed one: the rule keys on the tag.
    std::unique_ptr<CBlock> pMalformed(BuildTemplate());
    BOOST_REQUIRE(pMalformed.get() != NULL);
    CTxOut badOut;
    badOut.nValue = 0;
    badOut.scriptPubKey = WrapPayload(MakePayload(1000));
    pMalformed->vtx[0].vout.push_back(badOut);
    pMalformed->hashMerkleRoot = pMalformed->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pMalformed.get()));

    pMalformed->nDoS = 0;
    BOOST_CHECK(!pMalformed->AcceptBlock());
    BOOST_CHECK_EQUAL(pMalformed->nDoS, 100);
    BOOST_CHECK(IndexFor(pMalformed->GetHash()) == NULL);
}

// The block one below the gate and the block on it, back to back on one chain:
// the rule flips at exactly the gate height and nowhere else.
BOOST_AUTO_TEST_CASE(the_rule_flips_at_exactly_the_gate_height)
{
    BOOST_REQUIRE(fRegTest);
    const int nBase = BestIndex()->nHeight;
    const int nGate = nBase + 3;
    MsGateGuard guard(nGate);

    for (int i = 0; i < 5; ++i)
    {
        std::unique_ptr<CBlock> pblock(MineOne());
        BOOST_REQUIRE(pblock.get() != NULL);
        const int nHeight = BestIndex()->nHeight;
        const bool fPresent = MsTimestampCommitmentPresent(CoinbaseScripts(*pblock));
        BOOST_CHECK_MESSAGE(fPresent == (nHeight >= nGate),
                            "height " << nHeight << " gate " << nGate
                                      << " present=" << fPresent);
        CBlockIndex* pindex = IndexFor(pblock->GetHash());
        BOOST_REQUIRE(pindex != NULL);
        if (nHeight < nGate)
            BOOST_CHECK_EQUAL(pindex->nTimeMs, 0);
    }
    BOOST_CHECK_EQUAL(BestIndex()->nHeight, nBase + 5);
}

// The DAG fork with the offset already live: post-DAG coinbases carry both
// commitments, each decoder reads its own, and the index caches both.
BOOST_AUTO_TEST_CASE(the_dag_transition_carries_both_commitments)
{
    BOOST_REQUIRE(fRegTest);
    MsGateGuard guard(1);
    BOOST_REQUIRE_LT(FORK_HEIGHT_MS_TIMESTAMP, FORK_HEIGHT_DAG);

    MineTo(FORK_HEIGHT_DAG + 2);
    BOOST_REQUIRE_GE(BestIndex()->nHeight, FORK_HEIGHT_DAG + 2);

    std::unique_ptr<CBlock> pblock(MineOne());
    BOOST_REQUIRE(pblock.get() != NULL);
    const int nHeight = BestIndex()->nHeight;
    BOOST_REQUIRE_GE(nHeight, FORK_HEIGHT_DAG);

    const std::vector<CScript> vScripts = CoinbaseScripts(*pblock);

    uint16_t nMs = 0;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(
        ExtractCanonicalMsTimestampCommitment(vScripts, nMs, strError),
        "post-DAG block has no readable ms commitment: " << strError);
    BOOST_CHECK_LE((unsigned int)nMs, MS_TIMESTAMP_MAX);

    std::vector<uint256> vParents;
    strError.clear();
    BOOST_REQUIRE_MESSAGE(
        ReadDAGParentCommitmentAtHeight(vScripts, nHeight, vParents, strError),
        "post-DAG block has no readable parent commitment: " << strError);
    BOOST_REQUIRE(!vParents.empty());
    BOOST_CHECK(vParents[0] == pblock->hashPrevBlock);

    // Two distinct outputs, neither shadowing the other.
    const int nMsOut = FindMsOutput(*pblock);
    BOOST_REQUIRE(nMsOut >= 0);
    int nDagOut = -1;
    for (unsigned int i = 0; i < vScripts.size(); ++i)
    {
        std::vector<uint256> vDecoded;
        std::string strDecodeError;
        if (DecodeCanonicalDAGParentScript(vScripts[i], vDecoded,
                                           strDecodeError) != DAG_PARENT_NOT_FOUND)
            nDagOut = (int)i;
    }
    BOOST_REQUIRE(nDagOut >= 0);
    BOOST_CHECK_NE(nMsOut, nDagOut);

    CBlockIndex* pindex = IndexFor(pblock->GetHash());
    BOOST_REQUIRE(pindex != NULL);
    BOOST_CHECK_EQUAL(pindex->nTimeMs, nMs);
    BOOST_CHECK_EQUAL(pindex->GetBlockTimeMs(),
                      MsTimestampCombine(pblock->nTime, nMs));

    // Removing the offset from a post-DAG block is still invalid: the DAG
    // commitment does not stand in for it.
    std::unique_ptr<CBlock> pStripped(BuildTemplate());
    BOOST_REQUIRE(pStripped.get() != NULL);
    const int nStripOut = FindMsOutput(*pStripped);
    BOOST_REQUIRE(nStripOut >= 0);
    pStripped->vtx[0].vout.erase(pStripped->vtx[0].vout.begin() + nStripOut);
    pStripped->hashMerkleRoot = pStripped->BuildMerkleTree();
    BOOST_REQUIRE(SolveBlock(pStripped.get()));

    pStripped->nDoS = 0;
    BOOST_CHECK(!pStripped->AcceptBlock());
    BOOST_CHECK_EQUAL(pStripped->nDoS, 100);
    BOOST_CHECK(IndexFor(pStripped->GetHash()) == NULL);
}

// The producer's own offset is in range on every block it builds, and the
// commitment it emits is the one the validator reads back.
BOOST_AUTO_TEST_CASE(the_producer_commitment_round_trips)
{
    BOOST_REQUIRE(fRegTest);
    MsGateGuard guard(1);

    for (int i = 0; i < 4; ++i)
    {
        std::unique_ptr<CBlock> pblock(MineOne());
        BOOST_REQUIRE(pblock.get() != NULL);

        const int nOut = FindMsOutput(*pblock);
        BOOST_REQUIRE(nOut >= 0);
        const CScript commitment = pblock->vtx[0].vout[nOut].scriptPubKey;
        BOOST_CHECK_EQUAL(commitment.size(), 8U);

        uint16_t nDecoded = 0;
        std::string strError;
        BOOST_REQUIRE_EQUAL(
            DecodeCanonicalMsTimestampScript(commitment, nDecoded, strError),
            MS_TIMESTAMP_VALID);
        BOOST_CHECK_LE((unsigned int)nDecoded, MS_TIMESTAMP_MAX);
        BOOST_CHECK(BuildMsTimestampScript(nDecoded) == commitment);

        uint16_t nExtracted = 0;
        strError.clear();
        BOOST_REQUIRE(ExtractCanonicalMsTimestampCommitment(
            CoinbaseScripts(*pblock), nExtracted, strError));
        BOOST_CHECK_EQUAL(nExtracted, nDecoded);

        CBlockIndex* pindex = IndexFor(pblock->GetHash());
        BOOST_REQUIRE(pindex != NULL);
        BOOST_CHECK_EQUAL(pindex->nTimeMs, nDecoded);
    }
}

BOOST_AUTO_TEST_SUITE_END()
