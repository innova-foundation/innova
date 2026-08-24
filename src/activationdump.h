// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Renders the activation ladder as JSON for the hidden -printactivations path. Reads
// no chain state; values come from the consensus gate helpers.

#ifndef INNOVA_ACTIVATIONDUMP_H
#define INNOVA_ACTIVATIONDUMP_H

#include "main.h"
#include "curvetree.h"
#include "lelantus.h"
#include "shielded.h"
#include "dag.h"
#include "finality.h"
#include "namecoin.h"
#include "version.h"

#include <sstream>
#include <string>

static const int ACTIVATION_DUMP_SCHEMA = 1;

// A gate whose helper resolves to a height.  pfnHeight is the gate itself.
struct CActivationHeightGate
{
    const char* pszName;            // macro or constant name
    const char* pszHelper;          // helper symbol
    const char* pszDecl;            // declaring header
    int (*pfnHeight)();             // resolver
    bool fMainnetLadder;            // mainnet value routed through the shift
    const int* pnSentinel;          // sentinel this gate may return, or NULL
    const char* pszSentinelName;
    const char* pszDerivedFrom;     // parent gate, or NULL
    bool fDerivedMainnetOnly;       // parent applies on mainnet only
    const char* pszMovableBy;       // startup argument, or NULL
    const char* pszSemantics;
    const char* pszSemanticsAtZero; // meaning of a zero height, or NULL
    const char* pszAliasOf;         // alias macro target, or NULL
};

// A gate that resolves to a bool with no height.
struct CActivationBoolGate
{
    const char* pszName;
    const char* pszDecl;
    bool (*pfnValue)();
    bool fNetworkBranched;          // reads fTestNet/fRegTest
    const char* pszMovableBy;
    const char* pszSemantics;
};

// A predicate that only resolves against a candidate height, which does not
// exist yet at this point in startup.  Named so coverage stays complete; never
// given a value.
struct CActivationParamPredicate
{
    const char* pszName;
    const char* pszDecl;
    const char* pszParams;
};

// A consensus constant consumed by one of the gates above.
struct CActivationConst
{
    const char* pszName;
    const char* pszHelper;
    const char* pszDecl;
    int64_t nValue;
    const char* pszUnit;
};

inline std::string ActivationJsonStr(const char* psz)
{
    return psz ? (std::string("\"") + psz + "\"") : std::string("null");
}

inline std::string ActivationJsonBool(bool f)
{
    return f ? std::string("true") : std::string("false");
}

inline std::string ActivationJsonInt(int64_t n)
{
    std::ostringstream ss;
    ss << n;
    return ss.str();
}

inline const char* ClassifyActivationHeight(const CActivationHeightGate& g, int nHeight)
{
    extern bool fRegTest;
    extern bool fTestNet;
    if (g.pnSentinel && nHeight == *g.pnSentinel)
        return "sentinel";
    // Every startup override is regtest-guarded, so off regtest the argument
    // cannot move the gate and the height is whatever the ladder says.
    if (g.pszMovableBy && fRegTest)
        return "build-flag";
    if (!fRegTest && !fTestNet && g.fMainnetLadder)
        return "ladder";
    return "raw-literal";
}

inline const char* ClassifyActivationBool(const CActivationBoolGate& g)
{
    if (g.pszMovableBy)
        return "build-flag";
    return g.fNetworkBranched ? "network-predicate" : "raw-literal";
}

inline std::string GetActivationLadderJSON()
{
    extern bool fRegTest;
    extern bool fTestNet;
    extern unsigned int nTargetSpacing;

    static const CActivationHeightGate vHeightGates[] = {
    { "FORK_HEIGHT_TIGHTER_DRIFT", "GetForkHeightTighterDrift", "src/main.h",
      &GetForkHeightTighterDrift, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_CN_PAYMENT_VALIDATION", "GetForkHeightCNPaymentValidation", "src/main.h",
      &GetForkHeightCNPaymentValidation, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    // The payment era itself, which is older than the ladder: a raw literal on
    // mainnet and testnet, and zero -- disabled -- on regtest until
    // -regtestcnpayments names a height.
    { "COLLATERALNODE_PAYMENT_ERA_HEIGHT", "GetCollateralnodePaymentEraHeight", "src/main.h",
      &GetCollateralnodePaymentEraHeight, false, NULL, NULL, NULL, false, "-regtestcnpayments",
      "activates_at", "disabled_when_zero", NULL },
    { "FORK_HEIGHT_COLD_STAKING", "GetForkHeightColdStaking", "src/main.h",
      &GetForkHeightColdStaking, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_SHIELDED", "GetForkHeightShielded", "src/main.h",
      &GetForkHeightShielded, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    // Zero here means active from genesis on every network -- the opposite of the
    // zero FORK_HEIGHT_IDNS_RESET returns off mainnet.
    { "FORK_HEIGHT_RINGSIG_DEPRECATION", "GetForkHeightRingSigDeprecation", "src/main.h",
      &GetForkHeightRingSigDeprecation, false, NULL, NULL, NULL, false, NULL, "always_active", "always_active", NULL },
    { "FORK_HEIGHT_DSP", "GetForkHeightDSP", "src/main.h",
      &GetForkHeightDSP, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_NULLSEND", "GetForkHeightNullSend", "src/main.h",
      &GetForkHeightNullSend, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_CJOIN", "GetForkHeightNullSend", "src/main.h",
      &GetForkHeightNullSend, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, "FORK_HEIGHT_NULLSEND" },
    { "FORK_HEIGHT_FCMP", "GetForkHeightFCMP", "src/curvetree.h",
      &GetForkHeightFCMP, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_FCMP_VALIDATION", "GetForkHeightFCMP", "src/main.h",
      &GetForkHeightFCMP, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, "FORK_HEIGHT_FCMP" },
    { "FORK_HEIGHT_NULLSTAKE", "GetForkHeightNullStake", "src/main.h",
      &GetForkHeightNullStake, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_NULLSTAKE_V2", "GetForkHeightNullStakeV2", "src/main.h",
      &GetForkHeightNullStakeV2, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_NULLSTAKE_V3", "GetForkHeightNullStakeV3", "src/main.h",
      &GetForkHeightNullStakeV3, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_CHAUMIAN_CJ", "GetForkHeightChaumianCJ", "src/main.h",
      &GetForkHeightChaumianCJ, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_SERIAL_V2", "GetForkHeightSerialV2", "src/lelantus.h",
      &GetForkHeightSerialV2, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_POEM", "GetForkHeightPoem", "src/main.h",
      &GetForkHeightPoem, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_FINALITY", "GetForkHeightFinality", "src/main.h",
      &GetForkHeightFinality, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_DAG", "GetForkHeightDAG", "src/main.h",
      &GetForkHeightDAG, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_SUPPLY_CAP", "GetForkHeightSupplyCap", "src/main.h",
      &GetForkHeightSupplyCap, true, NULL, NULL, "FORK_HEIGHT_DAG", false,
      "-regtestsupplycapheight", "activates_at", NULL, NULL },
    { "FORK_HEIGHT_EPOCH_ROOT_FCMP", "GetForkHeightEpochRootFCMP", "src/main.h",
      &GetForkHeightEpochRootFCMP, true, NULL, NULL, "FORK_HEIGHT_DAG", false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_VOTESET_ROOT", "GetForkHeightVoteSetRoot", "src/main.h",
      &GetForkHeightVoteSetRoot, true, NULL, NULL, "FORK_HEIGHT_DAG", false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_EPOCH_STATE_V2", "GetForkHeightEpochStateV2", "src/main.h",
      &GetForkHeightEpochStateV2, true, NULL, NULL, "FORK_HEIGHT_DAG", false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_CONNECTED_FINALITY_CARRIER", "GetForkHeightConnectedFinalityCarrier", "src/main.h",
      &GetForkHeightConnectedFinalityCarrier, true,
      &TESTNET_CONNECTED_FINALITY_CARRIER_HEIGHT_UNSET, "TESTNET_CONNECTED_FINALITY_CARRIER_HEIGHT_UNSET",
      "FORK_HEIGHT_DAG", false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_EPOCH_STATE_V3", "GetForkHeightEpochStateV3", "src/main.h",
      &GetForkHeightEpochStateV3, true,
      &TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET, "TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET",
      "FORK_HEIGHT_DAG", false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_BOUNDARY_A", "GetForkHeightBoundaryA", "src/main.h",
      &GetForkHeightBoundaryA, true,
      &TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET, "TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET",
      "FORK_HEIGHT_EPOCH_STATE_V3", false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_BOUNDARY_B", "GetForkHeightBoundaryB", "src/main.h",
      &GetForkHeightBoundaryB, false,
      &PRIVACY_VNEXT_HEIGHT_UNSET, "PRIVACY_VNEXT_HEIGHT_UNSET",
      NULL, false, "-regtestboundaryb", "activates_at", NULL, NULL },
    { "FORK_HEIGHT_IV5_FEE_NOTE", "GetForkHeightIV5FeeNote", "src/main.h",
      &GetForkHeightIV5FeeNote, false,
      &PRIVACY_VNEXT_HEIGHT_UNSET, "PRIVACY_VNEXT_HEIGHT_UNSET",
      NULL, false, "-regtestiv5feenote", "activates_at", NULL, NULL },
    { "FORK_HEIGHT_IV5_NOTE_VOTE", "GetForkHeightIV5NoteVote", "src/main.h",
      &GetForkHeightIV5NoteVote, false,
      &PRIVACY_VNEXT_HEIGHT_UNSET, "PRIVACY_VNEXT_HEIGHT_UNSET",
      NULL, false, "-regtestiv5notevote", "activates_at", NULL, NULL },
    { "FORK_HEIGHT_NULLIFIER_BINDING", "GetForkHeightNullifierBinding", "src/main.h",
      &GetForkHeightNullifierBinding, true, NULL, NULL, "FORK_HEIGHT_SHIELDED", true, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_KERNEL_PINNING", "GetForkHeightKernelPinning", "src/main.h",
      &GetForkHeightKernelPinning, true, NULL, NULL, "FORK_HEIGHT_NULLSTAKE_V2", true, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_DAGKNIGHT", "GetForkHeightDAGKnight", "src/main.h",
      &GetForkHeightDAGKnight, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_COMMITTEE_SIG_CANONICAL", "GetForkHeightCommitteeSigCanonical", "src/main.h",
      &GetForkHeightCommitteeSigCanonical, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_TALLY_GOVERNANCE", "GetForkHeightTallyGovernance", "src/main.h",
      &GetForkHeightTallyGovernance, true, NULL, NULL, "FORK_HEIGHT_DAG", true, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_NULLSTAKE_DELEGSET", "GetForkHeightNullStakeDelegSet", "src/main.h",
      &GetForkHeightNullStakeDelegSet, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_NULLSTAKE_RECLAIM", "GetForkHeightNullStakeReclaim", "src/main.h",
      &GetForkHeightNullStakeReclaim, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    { "FORK_HEIGHT_NULLSTAKE_B2C", "GetForkHeightNullStakeB2C", "src/main.h",
      &GetForkHeightNullStakeB2C, true, NULL, NULL, NULL, false, NULL, "activates_at", NULL, NULL },
    // Zero off mainnet means no reset, so the same literal that makes ring
    // signatures active everywhere disables this gate.
    { "FORK_HEIGHT_IDNS_RESET", "GetForkHeightIDNSReset", "src/main.h",
      &GetForkHeightIDNSReset, true, NULL, NULL, NULL, false, NULL, "activates_at", "disabled_when_zero", NULL },
    // The one height gate outside the FORK_HEIGHT_ family; predates the ladder
    // and does not move with the shift.
    { "RELEASE_HEIGHT", "GetIDNSReleaseHeight", "src/namecoin.h",
      &GetIDNSReleaseHeight, false, NULL, NULL, NULL, false, NULL, "activates_at", "always_active", NULL },
    };

    static const CActivationBoolGate vBoolGates[] = {
    { "IsConnectedFinalityCarrierConfigured", "src/main.h",
      &IsConnectedFinalityCarrierConfigured, true, NULL, "gate_predicate" },
    { "IsBoundaryAConfigured", "src/main.h",
      &IsBoundaryAConfigured, true, NULL, "gate_predicate" },
    { "IsEpochStateV3Configured", "src/main.h",
      &IsEpochStateV3Configured, true, NULL, "gate_predicate" },
    { "IsBoundaryBConfigured", "src/main.h",
      &IsBoundaryBConfigured, true, "-regtestboundaryb", "gate_predicate" },
    { "IsIV5FeeNoteConfigured", "src/main.h",
      &IsIV5FeeNoteConfigured, true, "-regtestiv5feenote", "gate_predicate" },
    { "IsIV5NoteVoteConfigured", "src/main.h",
      &IsIV5NoteVoteConfigured, true, "-regtestiv5notevote", "gate_predicate" },
    { "IsLegacyPrivacyPolicyDisabled", "src/main.h",
      &IsLegacyPrivacyPolicyDisabled, true, NULL, "gate_predicate" },
    { "IsShieldedVNextConsensusReady", "src/shielded.h",
      &IsShieldedVNextConsensusReady, true, "-regtestiv5rehearsal", "gate_predicate" },
    // Post-IDAG stake votes for finality instead of producing blocks, so every
    // height that may carry a privacy encoding has to sit above the DAG gate.
    { "PrivateStakeIsFinalityOnly", "src/main.h",
      &PrivateStakeIsFinalityOnly, true, "-regtestboundaryb", "gate_predicate" },
    { "IsPrivacyVNextLeafIndexAssignmentHeld", "src/shielded.h",
      &IsPrivacyVNextLeafIndexAssignmentHeld, true, "-regtestiv5holdleafindex", "wallet_predicate" },
    };

    static const CActivationParamPredicate vParamPredicates[] = {
    { "IsConnectedFinalityCarrierActiveAtHeight", "src/main.h", "int nHeight" },
    { "IsBoundaryAActiveAtHeight", "src/main.h", "int nHeight" },
    { "IsBoundaryBActiveAtHeight", "src/main.h", "int nHeight" },
    { "IsIV5FeeNoteActiveAtHeight", "src/main.h", "int nHeight" },
    { "IsIV5NoteVoteActiveAtHeight", "src/main.h", "int nHeight" },
    { "IsSupplyCapActiveAtHeight", "src/main.h", "int nHeight" },
    { "IsLegacyPrivateStakeCreationAllowed", "src/main.h", "StakingMode eMode, int nCandidateHeight" },
    { "IsNullStakeBlockProductionReachableAtHeight", "src/main.h", "int nHeight" },
    { "IsPrivacyVNextCoinStakeReachableAtHeight", "src/main.h", "int nHeight" },
    { "IsFinalitySettlementHeight", "src/finality.h", "int nHeight, int* pnEpochOut" },
    };

    const CActivationConst vConsts[] = {
    { "FORK_MIN_CN_PROTO_VERSION", NULL, "src/main.h", FORK_MIN_CN_PROTO_VERSION, "protocol_version" },
    { "NULLSTAKE_PINNED_AGE", NULL, "src/main.h", NULLSTAKE_PINNED_AGE, "seconds" },
    { "RECLAIM_TIMELOCK", "GetReclaimTimelock", "src/main.h", RECLAIM_TIMELOCK, "blocks" },
    { "MIN_SHIELDED_SPEND_DEPTH", NULL, "src/shielded.h", MIN_SHIELDED_SPEND_DEPTH, "blocks" },
    // The effective cap, not the MAX_MONEY literal: regtest may lower it.
    { "GetSupplyCapAmount", "GetSupplyCapAmount", "src/main.h", GetSupplyCapAmount(), "satoshi" },
    { "FINALITY_EPOCH_INTERVAL_PRE_DAG", NULL, "src/finality.h", FINALITY_EPOCH_INTERVAL_PRE_DAG, "blocks" },
    { "FINALITY_EPOCH_INTERVAL_POST_DAG", NULL, "src/finality.h", FINALITY_EPOCH_INTERVAL_POST_DAG, "blocks" },
    { "FINALITY_VOTE_INCLUSION_WINDOW", NULL, "src/finality.h", FINALITY_VOTE_INCLUSION_WINDOW, "blocks" },
    { "FINALITY_SETTLEMENT_OFFSET", NULL, "src/finality.h", FINALITY_SETTLEMENT_OFFSET, "blocks" },
    { "FINALITY_MIN_VOTERS", NULL, "src/finality.h", FINALITY_MIN_VOTERS, "voters" },
    { "FINALITY_CONFIRMATION_EPOCHS", NULL, "src/finality.h", FINALITY_CONFIRMATION_EPOCHS, "epochs" },
    { "FINALITY_MAX_BLOCK_VOTES", NULL, "src/finality.h", FINALITY_MAX_BLOCK_VOTES, "votes" },
    { "MAX_DAG_PARENTS", NULL, "src/dag.h", MAX_DAG_PARENTS, "parents" },
    { "DAG_MERGE_DEPTH", NULL, "src/dag.h", DAG_MERGE_DEPTH, "blocks" },
    };

    const char* pszNetwork = fRegTest ? "regtest" : (fTestNet ? "testnet" : "mainnet");

    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"schema\": " << ACTIVATION_DUMP_SCHEMA << ",\n";

    ss << "  \"provenance\": {\n";
    ss << "    \"source\": \"innovad -printactivations\",\n";
    ss << "    \"build_desc\": " << ActivationJsonStr(FormatFullVersion().c_str()) << ",\n";
    ss << "    \"client_name\": " << ActivationJsonStr(CLIENT_NAME.c_str()) << ",\n";
    ss << "    \"client_date\": " << ActivationJsonStr(CLIENT_DATE.c_str()) << ",\n";
    ss << "    \"client_version\": " << CLIENT_VERSION << "\n";
    ss << "  },\n";

    // Effective network, never the argument the harness passed: a configuration
    // file can set testnet= or regtest= without the flag appearing on argv.
    ss << "  \"network\": {\n";
    ss << "    \"effective\": " << ActivationJsonStr(pszNetwork) << ",\n";
    ss << "    \"fTestNet\": " << ActivationJsonBool(fTestNet) << ",\n";
    ss << "    \"fRegTest\": " << ActivationJsonBool(fRegTest) << "\n";
    ss << "  },\n";

    ss << "  \"ladder\": {\n";
    ss << "    \"MAINNET_V5_ACTIVATION_BASE\": " << MAINNET_V5_ACTIVATION_BASE << ",\n";
    ss << "    \"MAINNET_V5_ACTIVATION_SHIFT\": " << MAINNET_V5_ACTIVATION_SHIFT << ",\n";
    ss << "    \"first_gate\": " << ShiftMainnetV5Activation(MAINNET_V5_ACTIVATION_BASE) << "\n";
    ss << "  },\n";

    // Three separately named sentinels currently share one value; a gate names
    // the one it may return so the coincidence stays visible.
    ss << "  \"sentinels\": {\n";
    ss << "    \"PRIVACY_VNEXT_HEIGHT_UNSET\": " << PRIVACY_VNEXT_HEIGHT_UNSET << ",\n";
    ss << "    \"TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET\": " << TESTNET_EPOCH_STATE_V3_HEIGHT_UNSET << ",\n";
    ss << "    \"TESTNET_CONNECTED_FINALITY_CARRIER_HEIGHT_UNSET\": "
       << TESTNET_CONNECTED_FINALITY_CARRIER_HEIGHT_UNSET << "\n";
    ss << "  },\n";

    ss << "  \"runtime_overrides\": {\n";
    ss << "    \"nRegtestBoundaryBHeight\": " << nRegtestBoundaryBHeight << ",\n";
    ss << "    \"nRegtestSupplyCapHeight\": " << nRegtestSupplyCapHeight << ",\n";
    ss << "    \"nRegtestSupplyCapAmount\": " << nRegtestSupplyCapAmount << ",\n";
    ss << "    \"nRegtestCNPaymentsHeight\": " << nRegtestCNPaymentsHeight << ",\n";
    ss << "    \"nRegtestIV5FeeNoteHeight\": " << nRegtestIV5FeeNoteHeight << ",\n";
    ss << "    \"nRegtestIV5NoteVoteHeight\": " << nRegtestIV5NoteVoteHeight << ",\n";
    ss << "    \"fRegtestShieldedVNextRehearsal\": " << ActivationJsonBool(fRegtestShieldedVNextRehearsal) << ",\n";
    ss << "    \"fRegtestHoldPrivacyVNextLeafIndex\": " << ActivationJsonBool(fRegtestHoldPrivacyVNextLeafIndex) << ",\n";
    ss << "    \"nTargetSpacing\": " << nTargetSpacing << "\n";
    ss << "  },\n";

    ss << "  \"gates\": [\n";
    bool fFirst = true;

    for (unsigned int i = 0; i < sizeof(vHeightGates) / sizeof(vHeightGates[0]); i++)
    {
        const CActivationHeightGate& g = vHeightGates[i];
        const int nHeight = g.pfnHeight();
        const char* pszClass = ClassifyActivationHeight(g, nHeight);
        const bool fUnset = (strcmp(pszClass, "sentinel") == 0);
        const bool fLadder = (strcmp(pszClass, "ladder") == 0);
        const char* pszSemantics = (nHeight == 0 && g.pszSemanticsAtZero)
                                   ? g.pszSemanticsAtZero : g.pszSemantics;
        const bool fShowParent = g.pszDerivedFrom && !fUnset &&
                                 (!g.fDerivedMainnetOnly || (!fRegTest && !fTestNet));

        ss << (fFirst ? "    " : ",\n    ");
        fFirst = false;
        ss << "{\"name\": " << ActivationJsonStr(g.pszName)
           << ", \"helper\": " << ActivationJsonStr(g.pszHelper)
           << ", \"decl\": " << ActivationJsonStr(g.pszDecl)
           << ", \"kind\": " << (g.pszAliasOf ? "\"alias\"" : "\"height\"")
           << ", \"class\": " << ActivationJsonStr(pszClass)
           << ", \"height\": " << (fUnset ? std::string("\"UNSET\"") : ActivationJsonInt(nHeight))
           << ", \"base\": " << (fLadder ? ActivationJsonInt(nHeight - MAINNET_V5_ACTIVATION_SHIFT)
                                         : std::string("null"))
           << ", \"sentinel\": " << ActivationJsonStr(fUnset ? g.pszSentinelName : NULL)
           << ", \"derived_from\": " << ActivationJsonStr(fShowParent ? g.pszDerivedFrom : NULL)
           << ", \"alias_of\": " << ActivationJsonStr(g.pszAliasOf)
           << ", \"runtime_movable_by\": " << ActivationJsonStr(g.pszMovableBy)
           << ", \"semantics\": " << ActivationJsonStr(pszSemantics)
           << "}";
    }

    for (unsigned int i = 0; i < sizeof(vBoolGates) / sizeof(vBoolGates[0]); i++)
    {
        const CActivationBoolGate& g = vBoolGates[i];
        ss << ",\n    ";
        ss << "{\"name\": " << ActivationJsonStr(g.pszName)
           << ", \"helper\": " << ActivationJsonStr(g.pszName)
           << ", \"decl\": " << ActivationJsonStr(g.pszDecl)
           << ", \"kind\": \"bool\""
           << ", \"class\": " << ActivationJsonStr(ClassifyActivationBool(g))
           << ", \"value\": " << ActivationJsonBool(g.pfnValue())
           << ", \"runtime_movable_by\": " << ActivationJsonStr(g.pszMovableBy)
           << ", \"semantics\": " << ActivationJsonStr(g.pszSemantics)
           << "}";
    }

    for (unsigned int i = 0; i < sizeof(vParamPredicates) / sizeof(vParamPredicates[0]); i++)
    {
        const CActivationParamPredicate& p = vParamPredicates[i];
        ss << ",\n    ";
        ss << "{\"name\": " << ActivationJsonStr(p.pszName)
           << ", \"helper\": " << ActivationJsonStr(p.pszName)
           << ", \"decl\": " << ActivationJsonStr(p.pszDecl)
           << ", \"kind\": \"predicate_at_height\""
           << ", \"class\": \"network-predicate\""
           << ", \"value\": null"
           << ", \"params\": " << ActivationJsonStr(p.pszParams)
           << ", \"semantics\": \"gate_predicate\""
           << ", \"reason\": \"resolves only against a candidate height; no chain state exists at this point in startup\""
           << "}";
    }

    for (unsigned int i = 0; i < sizeof(vConsts) / sizeof(vConsts[0]); i++)
    {
        const CActivationConst& c = vConsts[i];
        ss << ",\n    ";
        ss << "{\"name\": " << ActivationJsonStr(c.pszName)
           << ", \"helper\": " << ActivationJsonStr(c.pszHelper)
           << ", \"decl\": " << ActivationJsonStr(c.pszDecl)
           << ", \"kind\": \"const\""
           << ", \"class\": \"raw-literal\""
           << ", \"value\": " << c.nValue
           << ", \"unit\": " << ActivationJsonStr(c.pszUnit)
           << ", \"semantics\": \"constant\""
           << "}";
    }

    // Height-parameterized, and the only pair whose two sides are both consensus
    // values, so it is emitted as the pair rather than a scalar.
    ss << ",\n    ";
    ss << "{\"name\": \"GetTargetSpacingForHeight\""
       << ", \"helper\": \"GetTargetSpacingForHeight\""
       << ", \"decl\": \"src/main.h\""
       << ", \"kind\": \"const_pair\""
       << ", \"class\": \"raw-literal\""
       << ", \"value\": {\"pre_dag\": " << GetTargetSpacingForHeight(0)
       << ", \"post_dag\": " << GetTargetSpacingForHeight(GetForkHeightDAG()) << "}"
       << ", \"unit\": \"seconds\""
       << ", \"derived_from\": \"FORK_HEIGHT_DAG\""
       << ", \"semantics\": \"constant\""
       << "}";

    ss << "\n  ]\n";
    ss << "}\n";
    return ss.str();
}

#endif // INNOVA_ACTIVATIONDUMP_H
