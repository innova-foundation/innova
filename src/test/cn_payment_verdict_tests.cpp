// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// No ConnectBlock verdict may depend on node-local state, and only a DoS-scored verdict
// may persist as BLOCK_FAILED_VALID.

#include <boost/test/unit_test.hpp>

#include <boost/preprocessor/stringize.hpp>

#include <cstddef>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../main.h"

BOOST_AUTO_TEST_SUITE(cn_payment_verdict_tests)

namespace {

std::string MainSourcePath()
{
    // TEST_DATA_DIR is src/test/data; main.cpp sits two levels up.
    return std::string(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) + "/../../main.cpp";
}

std::string ReadFile(const std::string& strPath)
{
    std::ifstream in(strPath.c_str());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Blanks comments and the contents of string/char literals, keeping every offset
// and every newline. Brace matching and token scanning then cannot be fooled by a
// brace inside a printf format or by the word "return" inside a comment.
std::string MaskLiteralsAndComments(const std::string& s)
{
    std::string out = s;
    enum State { CODE, LINE_COMMENT, BLOCK_COMMENT, STRING, CHARLIT };
    State st = CODE;
    for (size_t i = 0; i < s.size(); i++)
    {
        const char c = s[i];
        const char n = (i + 1 < s.size()) ? s[i + 1] : '\0';
        switch (st)
        {
        case CODE:
            if (c == '/' && n == '/') { st = LINE_COMMENT; out[i] = ' '; }
            else if (c == '/' && n == '*') { st = BLOCK_COMMENT; out[i] = ' '; }
            else if (c == '"') st = STRING;
            else if (c == '\'') st = CHARLIT;
            break;
        case LINE_COMMENT:
            if (c == '\n') st = CODE; else out[i] = ' ';
            break;
        case BLOCK_COMMENT:
            if (c == '*' && n == '/') { out[i] = ' '; out[i + 1] = ' '; i++; st = CODE; }
            else if (c != '\n') out[i] = ' ';
            break;
        case STRING:
            if (c == '\\') { out[i] = ' '; if (i + 1 < s.size()) { out[i + 1] = ' '; i++; } }
            else if (c == '"') st = CODE;
            else out[i] = ' ';
            break;
        case CHARLIT:
            if (c == '\\') { out[i] = ' '; if (i + 1 < s.size()) { out[i + 1] = ' '; i++; } }
            else if (c == '\'') st = CODE;
            else out[i] = ' ';
            break;
        }
    }
    return out;
}

// The brace-delimited block opened by the first '{' at or after nFrom.
// Returns false if the braces do not balance.
bool BraceBlockAt(const std::string& masked, size_t nFrom, size_t& nBeginOut, size_t& nEndOut)
{
    const size_t nOpen = masked.find('{', nFrom);
    if (nOpen == std::string::npos)
        return false;
    int nDepth = 0;
    for (size_t i = nOpen; i < masked.size(); i++)
    {
        if (masked[i] == '{') nDepth++;
        else if (masked[i] == '}')
        {
            nDepth--;
            if (nDepth == 0)
            {
                nBeginOut = nOpen;
                nEndOut = i;
                return true;
            }
        }
    }
    return false;
}

bool IsIdentChar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

// Occurrences of strNeedle as a whole identifier.
size_t CountIdentifier(const std::string& masked, const std::string& strNeedle)
{
    size_t nCount = 0;
    size_t pos = masked.find(strNeedle);
    while (pos != std::string::npos)
    {
        const bool fLeft = (pos == 0) || !IsIdentChar(masked[pos - 1]);
        const size_t nAfter = pos + strNeedle.size();
        const bool fRight = (nAfter >= masked.size()) || !IsIdentChar(masked[nAfter]);
        if (fLeft && fRight)
            nCount++;
        pos = masked.find(strNeedle, pos + 1);
    }
    return nCount;
}

int LineOf(const std::string& s, size_t nPos)
{
    int nLine = 1;
    for (size_t i = 0; i < nPos && i < s.size(); i++)
        if (s[i] == '\n')
            nLine++;
    return nLine;
}

// The identifier that follows the `return` keyword at nPos, or "" for a
// non-identifier (a literal, an operator, a bare `return;`).
std::string TokenAfterReturn(const std::string& masked, size_t nPos)
{
    size_t i = nPos + 6;
    while (i < masked.size() && (masked[i] == ' ' || masked[i] == '\t' ||
                                 masked[i] == '\n' || masked[i] == '\r'))
        i++;
    size_t nBegin = i;
    while (i < masked.size() && IsIdentChar(masked[i]))
        i++;
    return masked.substr(nBegin, i - nBegin);
}

// A node-local gated scope inside ConnectBlock: the brace block guarded by one of
// the gate predicates. Everything decided inside is decided from state this node
// happens to hold, so nothing decided inside may be written down.
struct GatedScope
{
    std::string strGate;      // gate predicate name
    size_t nGate;             // offset of the gate call
    size_t nBegin;            // offset of '{'
    size_t nEnd;              // offset of matching '}'
};

struct ConnectBlockSource
{
    std::string strFile;      // raw source, for line numbers
    std::string strMasked;    // literals/comments blanked
    size_t nBodyBegin;        // ConnectBlock's '{'
    size_t nBodyEnd;          // ConnectBlock's matching '}'
    std::vector<GatedScope> vScopes;

    std::string Body(const GatedScope& s) const
    {
        return strMasked.substr(s.nBegin, s.nEnd - s.nBegin + 1);
    }
    // The gate call plus the rest of the condition, up to the opening brace.
    std::string Condition(const GatedScope& s) const
    {
        return strMasked.substr(s.nGate, s.nBegin - s.nGate);
    }
};

const char* const kGatePredicates[] = { "CollateralnodePaymentRuleApplies" };
const size_t kGateCount = sizeof(kGatePredicates) / sizeof(kGatePredicates[0]);

// Every gated scope inside ConnectBlock's own body. Restricting the search to that
// body is what keeps the predicates' own definitions -- one of which calls the
// other -- out of the scan.
bool LoadGatedScopes(ConnectBlockSource& out)
{
    out.strFile = ReadFile(MainSourcePath());
    if (out.strFile.empty())
        return false;
    out.strMasked = MaskLiteralsAndComments(out.strFile);

    const size_t nDef = out.strMasked.find("bool CBlock::ConnectBlock(");
    if (nDef == std::string::npos)
        return false;
    if (!BraceBlockAt(out.strMasked, nDef, out.nBodyBegin, out.nBodyEnd))
        return false;

    for (size_t g = 0; g < kGateCount; g++)
    {
        const std::string strCall = std::string(kGatePredicates[g]) + "(";
        size_t pos = out.strMasked.find(strCall, out.nBodyBegin);
        while (pos != std::string::npos && pos < out.nBodyEnd)
        {
            GatedScope scope;
            scope.strGate = kGatePredicates[g];
            scope.nGate = pos;
            if (!BraceBlockAt(out.strMasked, pos, scope.nBegin, scope.nEnd))
                return false;
            out.vScopes.push_back(scope);
            pos = out.strMasked.find(strCall, pos + 1);
        }
    }
    return true;
}

// Every whole-identifier `return` in strBody, as (offset, following token).
void CollectReturns(const std::string& strBody,
                    std::vector<std::pair<size_t, std::string> >& vOut)
{
    size_t pos = strBody.find("return");
    while (pos != std::string::npos)
    {
        const bool fLeft = (pos == 0) || !IsIdentChar(strBody[pos - 1]);
        const bool fRight = (pos + 6 >= strBody.size()) || !IsIdentChar(strBody[pos + 6]);
        if (fLeft && fRight)
            vOut.push_back(std::make_pair(pos, TokenAfterReturn(strBody, pos)));
        pos = strBody.find("return", pos + 1);
    }
}

} // namespace

// The gate's own arithmetic: 20 * nCoinbaseMaturity is 1,300 s on mainnet, so validators
// whose clocks differ by more disagree about whether the rule was evaluated.
BOOST_AUTO_TEST_CASE(window_is_a_wall_clock_span_wide_enough_to_matter)
{
    const int nSaved = nCoinbaseMaturity;
    nCoinbaseMaturity = 65;
    BOOST_CHECK_EQUAL(CollateralnodePaymentWindowSeconds(), (int64_t)1300);
    nCoinbaseMaturity = 1;
    BOOST_CHECK_EQUAL(CollateralnodePaymentWindowSeconds(), (int64_t)20);
    nCoinbaseMaturity = nSaved;

    BOOST_CHECK_MESSAGE(20 * (int64_t)nCoinbaseMaturity ==
                            CollateralnodePaymentWindowSeconds(),
                        "the window must stay derived from nCoinbaseMaturity");
}

// Entry is decided by the validator's own clock against a header time. Same block,
// two honest validators, different answers -- which is the whole reason nothing
// decided inside may be written down.
BOOST_AUTO_TEST_CASE(rule_entry_is_decided_by_the_validators_own_clock)
{
    const int nSaved = nCoinbaseMaturity;
    nCoinbaseMaturity = 65;
    const int64_t nWindow = CollateralnodePaymentWindowSeconds();
    const int64_t nBlockTime = 1750000000;

    // A validator whose clock agrees with the header evaluates the rule.
    BOOST_CHECK(CollateralnodePaymentRuleApplies(false, nBlockTime, nBlockTime, true));

    // The last clock reading that still evaluates it, and the first that does not.
    BOOST_CHECK(CollateralnodePaymentRuleApplies(false, nBlockTime,
                                                 nBlockTime + nWindow - 1, true));
    BOOST_CHECK(!CollateralnodePaymentRuleApplies(false, nBlockTime,
                                                  nBlockTime + nWindow, true));

    // The disagreement, stated as two validators and one block.
    const int64_t nSlowClock = nBlockTime;
    const int64_t nFastClock = nBlockTime + nWindow + 60;
    BOOST_CHECK(CollateralnodePaymentRuleApplies(false, nBlockTime, nSlowClock, true));
    BOOST_CHECK(!CollateralnodePaymentRuleApplies(false, nBlockTime, nFastClock, true));

    // A clock behind the header never suppresses the check.
    BOOST_CHECK(CollateralnodePaymentRuleApplies(false, nBlockTime,
                                                 nBlockTime - 86400, true));

    // The other gate inputs.
    BOOST_CHECK(!CollateralnodePaymentRuleApplies(true, nBlockTime, nBlockTime, true));
    BOOST_CHECK(!CollateralnodePaymentRuleApplies(false, nBlockTime, nBlockTime, false));
    BOOST_CHECK(!CollateralnodePaymentRuleApplies(false, nBlockTime, nBlockTime, true, true));

    nCoinbaseMaturity = nSaved;
}

// The persistence rule itself: only a deterministic consensus verdict may be
// written into the block index. BLOCK_FAILED_VALID is serialized and cleared only
// by reconsiderblock, so anything else here is a permanent split.
BOOST_AUTO_TEST_CASE(only_a_consensus_invalid_result_may_be_persisted)
{
    BOOST_CHECK(ConnectResultMayPersistVerdict(CBlock::CONNECT_RESULT_INVALID));
    BOOST_CHECK(!ConnectResultMayPersistVerdict(CBlock::CONNECT_RESULT_TRANSIENT));
    BOOST_CHECK(!ConnectResultMayPersistVerdict(CBlock::CONNECT_RESULT_OK));
}

// ConnectBlock reads no gossiped CN state, wall clock, IBD flag or local tip, so its
// verdict depends only on the chain.
BOOST_AUTO_TEST_CASE(connectblock_reads_no_node_local_state)
{
    ConnectBlockSource src;
    BOOST_REQUIRE(LoadGatedScopes(src));
    BOOST_CHECK_EQUAL(src.vScopes.size(), (size_t)0);
    const std::string strBody =
        src.strMasked.substr(src.nBodyBegin, src.nBodyEnd - src.nBodyBegin + 1);
    static const char* const kNodeLocal[] = {
        "CollateralnodePaymentRuleApplies", "ColdStakeCNPayeeIsRegistered", "GetBlockPayee",
        "vecCollateralnodes", "GetCollateralnodeRanks", "CheckCNPayment", "CheckPoSCNPayment",
        "FindCNPayment", "IsInitialBlockDownload", "GetTime", "pindexBest" };
    for (size_t k = 0; k < sizeof(kNodeLocal) / sizeof(kNodeLocal[0]); k++)
        BOOST_CHECK_MESSAGE(CountIdentifier(strBody, kNodeLocal[k]) == 0,
                            "ConnectBlock reads " << kNodeLocal[k]);
}

// The persistence rule has to exist once. A second inline `== CONNECT_RESULT_INVALID`
// is how the two best-chain sites drift apart.
BOOST_AUTO_TEST_CASE(the_persistence_rule_has_a_single_definition)
{
    const std::string strFile = ReadFile(MainSourcePath());
    BOOST_REQUIRE(!strFile.empty());
    const std::string strMasked = MaskLiteralsAndComments(strFile);

    // Reorganize, SetBestChainInner, plus the definition.
    BOOST_CHECK_MESSAGE(CountIdentifier(strMasked, "ConnectResultMayPersistVerdict") >= 3,
                        "both best-chain sites must reach the persistence rule "
                        "through ConnectResultMayPersistVerdict");

    // The enum may be assigned and defaulted; it may not be compared to decide
    // persistence.
    size_t nInline = 0;
    size_t pos = strMasked.find("connectResult");
    while (pos != std::string::npos)
    {
        const size_t nStop = strMasked.find(')', pos);
        const std::string strTail =
            strMasked.substr(pos, (nStop == std::string::npos ? 60 : nStop - pos));
        if (strTail.find("==") != std::string::npos &&
            strTail.find("CONNECT_RESULT_INVALID") != std::string::npos)
        {
            nInline++;
            BOOST_CHECK_MESSAGE(false,
                "main.cpp:" << LineOf(strFile, pos)
                    << ": persistence decided by comparing connectResult inline; "
                       "call ConnectResultMayPersistVerdict so the two best-chain "
                       "sites cannot drift");
        }
        pos = strMasked.find("connectResult", pos + 1);
    }
    BOOST_CHECK_EQUAL(nInline, (size_t)0);
}

// AddToBlockIndex keeps a permanently-invalid index flagged but erases a transient
// one, so the block is requested again on the next inv.
BOOST_AUTO_TEST_CASE(a_transient_refusal_leaves_the_block_requestable)
{
    const std::string strFile = ReadFile(MainSourcePath());
    BOOST_REQUIRE(!strFile.empty());
    const std::string strMasked = MaskLiteralsAndComments(strFile);

    const size_t nCall = strMasked.find("if (!SetBestChain(txdb, pindexNew, &fPermanentInvalid, &failReason))");
    BOOST_REQUIRE_MESSAGE(nCall != std::string::npos,
                          "could not locate the AddToBlockIndex best-chain call");
    size_t nOuterBegin = 0, nOuterEnd = 0;
    BOOST_REQUIRE(BraceBlockAt(strMasked, nCall, nOuterBegin, nOuterEnd));

    const size_t nPermIf = strMasked.find("if (fPermanentInvalid)", nOuterBegin);
    BOOST_REQUIRE(nPermIf != std::string::npos && nPermIf < nOuterEnd);
    size_t nPermBegin = 0, nPermEnd = 0;
    BOOST_REQUIRE(BraceBlockAt(strMasked, nPermIf, nPermBegin, nPermEnd));

    const std::string strPermanent = strMasked.substr(nPermBegin, nPermEnd - nPermBegin + 1);
    const std::string strTransient = strMasked.substr(nPermEnd + 1, nOuterEnd - nPermEnd);

    // Persisted: flagged, written back, and deliberately kept in the map.
    BOOST_CHECK(strPermanent.find("SetFailedValid()") != std::string::npos);
    BOOST_CHECK(strPermanent.find("WriteBlockIndex") != std::string::npos);
    BOOST_CHECK_MESSAGE(strPermanent.find("mapBlockIndex.erase") == std::string::npos,
                        "the permanent branch must keep the flagged index so the "
                        "block is not re-requested forever");

    // Refused: forgotten entirely, on disk and in memory.
    BOOST_CHECK_MESSAGE(strTransient.find("mapBlockIndex.erase(hash)") != std::string::npos,
                        "the transient branch must drop the index, or a refused "
                        "block is never re-attempted and the node stalls instead "
                        "of splitting");
    BOOST_CHECK(strTransient.find("EraseBlockIndex(hash)") != std::string::npos);
    BOOST_CHECK_MESSAGE(strTransient.find("SetFailedValid") == std::string::npos,
                        "the transient branch must not flag the index");

    // And that dropping the index is what makes the block requestable again.
    const size_t nHaveBlock = strMasked.find("case MSG_BLOCK:");
    BOOST_REQUIRE(nHaveBlock != std::string::npos);
    const std::string strHave = strMasked.substr(nHaveBlock, 160);
    BOOST_CHECK_MESSAGE(strHave.find("mapBlockIndex.count(inv.hash)") != std::string::npos,
                        "AlreadyHave no longer answers from mapBlockIndex; the "
                        "re-request argument above needs redoing");
}

// What persisting one costs, so the invariant above is not guarding a cheap
// mistake: the flag round-trips the on-disk index record.
BOOST_AUTO_TEST_CASE(a_persisted_verdict_survives_restart)
{
    CBlockIndex indexNew;
    indexNew.nHeight = 8220301;
    indexNew.nFlags = 0;
    BOOST_CHECK(!indexNew.IsFailed());
    BOOST_CHECK(!indexNew.IsInvalid());

    indexNew.SetFailedValid();
    BOOST_CHECK(indexNew.IsFailed());

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << CDiskBlockIndex(&indexNew);
    CDiskBlockIndex diskRead;
    ss >> diskRead;

    CBlockIndex indexReloaded;
    ApplyDiskBlockIndexFields(diskRead, &indexReloaded);
    BOOST_CHECK_MESSAGE(indexReloaded.IsFailed(),
                        "BLOCK_FAILED_VALID must round-trip the index record -- "
                        "that permanence is what makes a node-local verdict a "
                        "permanent split");
    BOOST_CHECK(indexReloaded.IsInvalid());

    indexReloaded.ClearFailed();
    BOOST_CHECK(!indexReloaded.IsInvalid());
}

// Every return in ConnectBlock is scored, wrapped, or the one bare `false` under the scope
// guard; no bare `return error(...)` remains and the guard must be installed.
BOOST_AUTO_TEST_CASE(every_connectblock_return_is_scored_wrapped_or_guarded)
{
    ConnectBlockSource src;
    BOOST_REQUIRE_MESSAGE(LoadGatedScopes(src), "could not locate ConnectBlock");
    const std::string strBody =
        src.strMasked.substr(src.nBodyBegin, src.nBodyEnd - src.nBodyBegin + 1);
    BOOST_CHECK_MESSAGE(CountIdentifier(strBody, "CVerdictScopeGuard") >= 1,
                        "ConnectBlock no longer installs the verdict scope guard, so an "
                        "unscored bare return is persistable again");

    std::vector<std::pair<size_t, std::string> > vReturns;
    CollectReturns(strBody, vReturns);
    BOOST_REQUIRE_GE(vReturns.size(), (size_t)100);
    size_t nBareFalse = 0;
    for (size_t i = 0; i < vReturns.size(); i++)
    {
        const std::string& strToken = vReturns[i].second;
        if (strToken == "DoS" || strToken == "TransientFailure" || strToken == "Connected")
            continue;
        if (strToken == "fReturn" || strToken == "true") // the wrapper lambdas' own returns
            continue;
        if (strToken == "false")
        {
            nBareFalse++;
            continue;
        }
        BOOST_CHECK_MESSAGE(false,
                            "main.cpp:" << LineOf(src.strFile, src.nBodyBegin + vReturns[i].first)
                                << ": return yields '" << strToken << "'. Unscored, so the "
                                   "scope guard makes it transient; if the site is "
                                   "deterministic it must be DoS-scored, otherwise wrap it "
                                   "in TransientFailure so the intent is explicit.");
    }
    // The CheckBlock re-run: unscored only for the clock check and CheckTransaction's
    // local-failure paths, which is exactly what the guard is for.
    BOOST_CHECK_EQUAL(nBareFalse, (size_t)1);
}

BOOST_AUTO_TEST_SUITE_END()
