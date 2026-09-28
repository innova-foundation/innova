// Connect-time rules of the note finality vote (IV5 op 10): spent-key path, fork gate,
// inclusion window, boundary ancestry, and the E-1 anchor; plus carrier shape and caps.
// Synthetic block indexes; epoch records and spent-key entries are restored per case.

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <limits>
#include <set>
#include <string>
#include <vector>

#include "../privacy_vnext/rust/include/innova_privacy_vnext.h"
#include "../dag.h"
#include "../finality.h"
#include "../main.h"
#include "../ed25519_zk.h"
#include "../privacy_vnext_builder.h"
#include "../privacy_vnext/iv5_protocol.h"
#include "../privacy_vnext_ffi.h"
#include "../privacy_vnext_store.h"
#include "../shielded.h"
#include "../txdb.h"
#include "synthetic_chain.h"

#include <algorithm>

extern bool fRegTest;
extern bool fTestNet;

namespace
{

// A note at the finality stake floor (500 INN), the note a vote spends.
const uint64_t kVoteNote = 500ULL * 100000000ULL;

// The post-DAG epoch the votes name. Its boundary is 1211 on regtest; E-1 ends at 1210.
const int kEpoch = 5;

int BoundaryHeight()
{
    return GetEpochBoundaryHeight(kEpoch, 0);
}

PrivacyVNextDigest CollateralDigest(unsigned char fill)
{
    PrivacyVNextDigest d;
    d.fill(fill);
    return d;
}

PrivacyVNextDigest CollateralScalar(unsigned char low)
{
    PrivacyVNextDigest d;
    d.fill(0);
    d[0] = low;
    return d;
}

PrivacyVNextDigest LocalGenesis()
{
    PrivacyVNextDigest d;
    PrivacyVNextLocalGenesis(d.data());
    return d;
}

uint8_t LocalNetwork()
{
    return PrivacyVNextLocalNetworkId();
}

PrivacyVNextDigest NoTransparentSide()
{
    PrivacyVNextDigest d;
    const uint256 binding = GetPrivacyVNextTransparentBinding(CTransaction());
    std::memcpy(d.data(), binding.begin(), 32);
    return d;
}

// Input context of a shield with no transparent side; hand-funded notes only need
// encrypt and scan to agree on it.
PrivacyVNextDigest FundingContext()
{
    PrivacyVNextDigest context;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        DerivePrivacyVNextInputContext(iv5::NOTE_SHIELD, NoTransparentSide(),
                                       std::vector<PrivacyVNextDigest>(), context,
                                       error),
        error);
    return context;
}

uint256 AsUint256(const PrivacyVNextDigest& d)
{
    uint256 out;
    std::memcpy(out.begin(), d.data(), d.size());
    return out;
}

PrivacyVNextDigest BlockDigest(const CBlockIndex* pindex)
{
    PrivacyVNextDigest d;
    const uint256 hash = pindex->GetBlockHash();
    std::memcpy(d.data(), hash.begin(), 32);
    return d;
}

// One note of a chosen amount, placed in a fresh tree and reopened by its owner, with the
// membership witness a proof over it needs.
struct FundedNote
{
    PrivacyVNextDerivedKeys keys;
    PrivacyVNextEncryptedOutput encrypted;
    PrivacyVNextSpendNote spend;
    PrivacyVNextDigest finalizedRoot;
    uint64_t nTreeSize;

    FundedNote() : nTreeSize(0) { finalizedRoot.fill(0); }
};

// Notes of a chosen amount, grown together into one fresh tree and reopened by their
// owners, each with its membership witness against the shared root.
bool FundNotes(CTxDB& txdb, const std::vector<unsigned char>& vSeeds, uint64_t nAmount,
               const std::vector<FundedNote*>& vOut, std::string& error)
{
    const PrivacyVNextDigest genesis = LocalGenesis();
    if (vOut.size() != vSeeds.size())
    {
        error = "funding needs one note per seed";
        return false;
    }
    std::vector<PrivacyVNextOutputLeaf> vLeaves;
    for (size_t n = 0; n < vSeeds.size(); ++n)
    {
        const unsigned char nSeed = vSeeds[n];
        FundedNote& out = *vOut[n];
        if (!DerivePrivacyVNextKeys(CollateralDigest(nSeed), genesis, 0,
                                    LocalNetwork(), 0, out.keys, error))
            return false;
        if (!EncryptPrivacyVNextNote(
                LocalNetwork(), 0, 0, genesis, out.keys.spendPublic,
                out.keys.viewPublic, out.keys.outgoingViewSecret,
                CollateralScalar(nSeed + 1), CollateralScalar(nSeed + 2), nAmount,
                CollateralScalar(nSeed + 3), CollateralScalar(nSeed + 4),
                FundingContext(),
                out.encrypted, error))
            return false;
        vLeaves.push_back(out.encrypted.leaf);
    }

    PrivacyVNextEpochSeed epochSeed;
    if (!LoadPrivacyVNextEpochSeed(epochSeed, error))
        return false;
    std::vector<unsigned char> treeState = epochSeed.vchTreeState;
    if (!TrimPrivacyVNextTreeStore(txdb, 0, treeState, error))
        return false;
    if (!GrowPrivacyVNextTreeStore(txdb, vLeaves, treeState, error))
        return false;

    std::vector<unsigned char> vchRoot;
    uint64_t nTreeSize = 0;
    if (!DecodePrivacyVNextTreeState(treeState, vchRoot, nTreeSize, error))
        return false;

    std::vector<uint64_t> vTargets;
    for (size_t n = 0; n < vSeeds.size(); ++n)
        vTargets.push_back(n);
    std::vector<unsigned char> vchPaths;
    if (!ReadPrivacyVNextTreePaths(txdb, nTreeSize, treeState, vTargets,
                                   vchPaths, error))
        return false;
    std::vector<PrivacyVNextMembershipWitness> vWitnesses;
    PrivacyVNextDigest treeRoot;
    if (!BuildPrivacyVNextWitnessesFromPaths(treeState, vTargets, vchPaths,
                                             vWitnesses, treeRoot, error))
        return false;
    if (vWitnesses.size() != vSeeds.size())
    {
        error = "funding returned the wrong witness count";
        return false;
    }

    for (size_t n = 0; n < vSeeds.size(); ++n)
    {
        FundedNote& out = *vOut[n];
        out.nTreeSize = nTreeSize;
        std::memcpy(out.finalizedRoot.data(), &vchRoot[0], 32);

        PrivacyVNextEncryptedNote onChain;
        onChain.nOutputIndex = 0;
        onChain.genesis = genesis;
        onChain.leafO = out.encrypted.leaf.owner;
        onChain.leafC = out.encrypted.leaf.commitment;
        onChain.noteEphemeral = out.encrypted.noteEphemeral;
        onChain.tweakEphemeral = out.encrypted.tweakEphemeral;
        onChain.vchCiphertext = out.encrypted.vchRecipientCiphertext;
        onChain.inputContext = FundingContext();
        PrivacyVNextScannedNote scanned;
        if (!ScanPrivacyVNextNote(PRIVACY_VNEXT_SCAN_FULL, LocalNetwork(), 0,
                                  onChain, out.keys.viewSecret,
                                  out.keys.spendSecret, scanned, error))
            return false;

        out.spend.spendSecret = scanned.spendSecret;
        out.spend.y = scanned.y;
        out.spend.mask = scanned.mask;
        out.spend.nAmount = scanned.nAmount;
        out.spend.leaf = out.encrypted.leaf;
        out.spend.vchWitnessRecord = vWitnesses[n].vchRecord;
    }
    return true;
}

bool FundNote(CTxDB& txdb, unsigned char nSeed, uint64_t nAmount,
              FundedNote& out, std::string& error)
{
    return FundNotes(txdb, std::vector<unsigned char>(1, nSeed), nAmount,
                     std::vector<FundedNote*>(1, &out), error);
}

// A transaction that carries a payload, which is all the consensus transitions read.
CTransaction CarryingTx(const std::vector<unsigned char>& payload, uint32_t nTime)
{
    CTransaction tx;
    tx.nVersion = INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION;
    tx.nTime = nTime;
    tx.privacyVNext.vchPayload = payload;
    return tx;
}

// Regtest fork height for note-weighted finality, restored on scope exit.
struct ScopedNoteVoteHeight
{
    int nSaved;
    explicit ScopedNoteVoteHeight(int nHeight)
        : nSaved(nRegtestIV5NoteVoteHeight)
    {
        nRegtestIV5NoteVoteHeight = nHeight;
    }
    ~ScopedNoteVoteHeight() { nRegtestIV5NoteVoteHeight = nSaved; }
};

// Compact size the way the payload decoder reads it: the short form below 253, the
// two-byte form above it. A membership proof is well past 253 bytes.
void PutCompact(std::vector<unsigned char>& out, uint64_t nSize)
{
    if (nSize < 253)
    {
        out.push_back((unsigned char)nSize);
        return;
    }
    if (nSize <= 0xffff)
    {
        out.push_back(253);
        out.push_back((unsigned char)nSize);
        out.push_back((unsigned char)(nSize >> 8));
        return;
    }
    out.push_back(254);
    for (size_t i = 0; i < 4; ++i)
        out.push_back((unsigned char)(nSize >> (8 * i)));
}

void PutDigest(std::vector<unsigned char>& out, const PrivacyVNextDigest& d)
{
    out.insert(out.end(), d.begin(), d.end());
}

void PutLE64(std::vector<unsigned char>& out, uint64_t v)
{
    for (size_t i = 0; i < 8; ++i)
        out.push_back((unsigned char)(v >> (8 * i)));
}

void PutSection(std::vector<unsigned char>& out, const std::vector<unsigned char>& v)
{
    PutCompact(out, v.size());
    out.insert(out.end(), v.begin(), v.end());
}

std::vector<unsigned char> DigestBytes(const PrivacyVNextDigest& d)
{
    return std::vector<unsigned char>(d.begin(), d.end());
}

// Contract digest; the decoder carries but does not judge it, so any nonzero value works.
PrivacyVNextDigest ContractDigest()
{
    PrivacyVNextDigest d;
    BOOST_REQUIRE(iv5::DecodeDigestHex(iv5::PROTOCOL_CONTRACT_SHA256, d.data()));
    return d;
}

// A note vote built from the wallet builder's primitives; shape-rule fields are set by
// the caller. The reissue pays the voting note's own address under the vote's context.
bool BuildShapedNoteVote(const FundedNote& note,
                         const PrivacyVNextDigest& parameterDigest,
                         uint64_t nReissueAmount,
                         int64_t nTransparentValueBalance,
                         uint64_t nFee,
                         const PrivacyVNextDigest& boundaryHash,
                         uint32_t nBoundaryHeight,
                         std::vector<unsigned char>& vchPayloadOut,
                         PrivacyVNextDigest& keyImageOut,
                         PrivacyVNextOutputLeaf& reissueOut,
                         std::string& error,
                         bool fProveUnshifted = false,
                         const FundedNote* pSecond = NULL)
{
    vchPayloadOut.clear();
    const PrivacyVNextDigest entropy = CollateralScalar(0x5c);

    // pSecond spends a second note of the same tree alongside the first.
    std::vector<const FundedNote*> vNotes(1, &note);
    if (pSecond)
        vNotes.push_back(pSecond);
    const size_t nInputs = vNotes.size();
    std::vector<PrivacyVNextSpendInput> vInputs(nInputs);
    for (size_t i = 0; i < nInputs; ++i)
    {
        vInputs[i].spendScalar = vNotes[i]->spend.spendSecret;
        vInputs[i].commitmentScalar = vNotes[i]->spend.y;
        vInputs[i].leaf = vNotes[i]->spend.leaf;
        vInputs[i].vchWitnessRecord = vNotes[i]->spend.vchWitnessRecord;
    }

    // Pass one fixes the pseudo-output and key image the entropy determines.
    PrivacyVNextDigest provisional;
    provisional.fill(0);
    provisional[0] = 1;
    std::vector<PrivacyVNextSpendConstruction> vDraft;
    std::vector<unsigned char> vchDraft;
    if (!ProvePrivacyVNextMembership(note.finalizedRoot, provisional, entropy,
                                     vInputs, vDraft, vchDraft, error))
        return false;
    if (vDraft.size() != nInputs)
    {
        error = "shaped vote proving returned the wrong input count";
        return false;
    }

    // The reissue derives under the vote's context: operation 10, the binding, the key
    // image. Unique per note, so the reissue's one-time key cannot recur.
    std::vector<PrivacyVNextDigest> vKeyImages;
    for (size_t i = 0; i < nInputs; ++i)
        vKeyImages.push_back(vDraft[i].keyImage);
    PrivacyVNextDigest context;
    if (!DerivePrivacyVNextInputContext(iv5::NOTE_FINALITY_VOTE, NoTransparentSide(),
                                        vKeyImages, context, error))
        return false;
    const PrivacyVNextDigest outputMask = CollateralScalar(0x61);
    PrivacyVNextEncryptedOutput reissue;
    if (!EncryptPrivacyVNextNote(LocalNetwork(), 0, 0, LocalGenesis(),
                                 note.keys.spendPublic, note.keys.viewPublic,
                                 note.keys.outgoingViewSecret, CollateralScalar(0x62),
                                 CollateralScalar(0x63), nReissueAmount,
                                 CollateralScalar(0x64), outputMask, context, reissue,
                                 error))
        return false;

    std::vector<unsigned char> prefix;
    prefix.push_back((unsigned char)iv5::PROTOCOL_SCHEMA);
    prefix.push_back(0);
    prefix.push_back(iv5::NOTE_FINALITY_VOTE);
    prefix.push_back(0);                         // finality profile: none
    prefix.push_back(iv5::AUTH_OWNER);
    prefix.push_back(iv5::DISCLOSURE_MASK);
    prefix.push_back(0);                         // finality object: none
    prefix.push_back(LocalNetwork());
    prefix.push_back(0);                         // reserved
    PutDigest(prefix, LocalGenesis());
    PutDigest(prefix, parameterDigest);
    PutDigest(prefix, note.finalizedRoot);
    PutLE64(prefix, note.nTreeSize);
    PutLE64(prefix, (uint64_t)nTransparentValueBalance);
    PutLE64(prefix, nFee);
    PutDigest(prefix, NoTransparentSide());
    PutCompact(prefix, nInputs);
    for (size_t i = 0; i < nInputs; ++i)
    {
        PutDigest(prefix, vDraft[i].pseudoOut);
        PutDigest(prefix, vDraft[i].keyImage);
    }
    PutCompact(prefix, 1);
    PutDigest(prefix, reissue.leaf.owner);
    PutDigest(prefix, reissue.leaf.commitment);
    PutDigest(prefix, reissue.noteEphemeral);
    PutDigest(prefix, reissue.tweakEphemeral);
    PutSection(prefix, reissue.vchRecipientCiphertext);
    PutSection(prefix, reissue.vchOutgoingCiphertext);
    PutDigest(prefix, boundaryHash);             // the vote names its boundary
    for (size_t i = 0; i < 4; ++i)
        prefix.push_back((unsigned char)(nBoundaryHeight >> (8 * i)));
    PutSection(prefix, std::vector<unsigned char>());   // finality body

    PrivacyVNextDigest signingHash;
    if (!HashPrivacyVNextPayloadPrefix(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                       prefix, signingHash, error))
        return false;

    std::vector<PrivacyVNextSpendConstruction> vFinal;
    std::vector<unsigned char> vchMembership;
    if (!ProvePrivacyVNextMembership(note.finalizedRoot, signingHash, entropy,
                                     vInputs, vFinal, vchMembership, error))
        return false;
    if (vFinal.size() != nInputs)
    {
        error = "shaped vote proving returned the wrong input count";
        return false;
    }
    for (size_t i = 0; i < nInputs; ++i)
        if (vFinal[i].pseudoOut != vDraft[i].pseudoOut ||
            vFinal[i].keyImage != vDraft[i].keyImage)
        {
            error = "shaped vote proving is not deterministic in its entropy";
            return false;
        }

    // excess = sum(note mask + rerandomization delta) - reissue mask
    std::vector<unsigned char> vchInputMask;
    std::vector<unsigned char> vchNegatedOutput;
    std::vector<unsigned char> vchExcess;
    for (size_t i = 0; i < nInputs; ++i)
    {
        std::vector<unsigned char> vchOne;
        std::vector<unsigned char> vchSum;
        if (!Ed25519ScalarAdd(DigestBytes(vNotes[i]->spend.mask),
                              DigestBytes(vFinal[i].pseudoOutMaskDelta), vchOne) ||
            (i > 0 && !Ed25519ScalarAdd(vchInputMask, vchOne, vchSum)))
        {
            error = "shaped vote excess mask accumulation failed";
            return false;
        }
        vchInputMask.swap(i > 0 ? vchSum : vchOne);
    }
    if (!Ed25519ScalarNeg(DigestBytes(outputMask), vchNegatedOutput) ||
        !Ed25519ScalarAdd(vchInputMask, vchNegatedOutput, vchExcess) ||
        vchExcess.size() != 32)
    {
        error = "shaped vote excess mask accumulation failed";
        return false;
    }
    PrivacyVNextDigest excessMask;
    std::memcpy(excessMask.data(), &vchExcess[0], 32);

    std::vector<PrivacyVNextDigest> vPseudoOuts;
    for (size_t i = 0; i < nInputs; ++i)
        vPseudoOuts.push_back(vFinal[i].pseudoOut);
    std::vector<PrivacyVNextValueOutput> vOutputs(1);
    vOutputs[0].nAmount = nReissueAmount;
    vOutputs[0].mask = outputMask;
    PrivacyVNextValueProof valueProof;
    if (!ProvePrivacyVNextValue(vPseudoOuts, vOutputs, nTransparentValueBalance, nFee,
                                signingHash, CollateralScalar(0x65), excessMask,
                                valueProof, error))
        return false;
    if (valueProof.vOutputCommitments.size() != 1 ||
        valueProof.vOutputCommitments[0] != reissue.leaf.commitment)
    {
        error = "shaped vote value proof does not open the reissue commitment";
        return false;
    }

    // Stake-floor range proof over the output commitment shifted down by the floor and the
    // value entering. A reissue below the shift leaves the section empty.
    std::vector<unsigned char> vchFloorProof;
    if (nTransparentValueBalance >= 0)
    {
        const uint64_t nShift = (uint64_t)iv5::NOTE_VOTE_MIN_WEIGHT +
                                (uint64_t)nTransparentValueBalance;
        if (nReissueAmount >= nShift)
        {
            PrivacyVNextDigest floorCommitment;
            floorCommitment.fill(0);
            // fProveUnshifted proves over C rather than C - shift*H, so it satisfies no floor.
            const uint64_t nProved =
                fProveUnshifted ? nReissueAmount : nReissueAmount - nShift;
            if (!ProvePrivacyVNextRange(nProved, outputMask,
                                        CollateralScalar(0x66), floorCommitment,
                                        vchFloorProof, error))
                return false;
        }
    }

    std::vector<unsigned char> payload = prefix;
    PutSection(payload, vchMembership);
    PutSection(payload, valueProof.vchRangeProof);
    PutSection(payload, std::vector<unsigned char>(valueProof.balanceProof.begin(),
                                                   valueProof.balanceProof.end()));
    PutSection(payload, vchFloorProof);
    PutSection(payload, std::vector<unsigned char>());   // no disclosures
    vchPayloadOut.swap(payload);
    keyImageOut = vFinal[0].keyImage;
    reissueOut = reissue.leaf;
    return true;
}

// The carrier chain: a main branch through H_E to the end of the inclusion window, and a
// sibling branch that opens its own H_E on the same parent, so a vote naming the sibling
// passes every rule but ancestry.
struct VoteChain
{
    CSyntheticChain chain;
    CBlockIndex* pParent;           // H_E - 1, shared by both branches
    CBlockIndex* pBoundary;         // main H_E
    CBlockIndex* pTip;              // main H_E + FINALITY_NOTE_VOTE_INCLUSION_WINDOW
    CBlockIndex* pSiblingBoundary;  // sibling H_E
    CBlockIndex* pSiblingTip;       // sibling H_E + 3

    explicit VoteChain(unsigned int nTag) : chain(nTag)
    {
        pParent = chain.Linear(BoundaryHeight() - 1);
        BOOST_REQUIRE(pParent != NULL);
        pBoundary = chain.Extend(pParent, 1);
        BOOST_REQUIRE(pBoundary != NULL);
        pTip = chain.Extend(pBoundary, FINALITY_NOTE_VOTE_INCLUSION_WINDOW);
        BOOST_REQUIRE(pTip != NULL);
        pSiblingBoundary = chain.Extend(pParent, 1);
        BOOST_REQUIRE(pSiblingBoundary != NULL);
        pSiblingTip = chain.Extend(pSiblingBoundary, 3);
        BOOST_REQUIRE(pSiblingTip != NULL);
    }

    // The main branch's block at nHeight.
    const CBlockIndex* At(int nHeight) const
    {
        const CBlockIndex* p =
            GetFinalityAncestorOnChain(pTip, nHeight, FINALITY_ANCESTOR_MAX_WALK);
        BOOST_REQUIRE(p != NULL);
        return p;
    }
};

// Epoch state E-1 as the epoch build leaves it for a chain whose H_E is pBoundary,
// carrying the tree the note was proven against.
CEpochState AnchorRecord(const FundedNote& note, const CBlockIndex* pBoundary)
{
    CEpochState s;
    s.nEpoch = kEpoch - 1;
    s.nHeightStart = GetEpochBoundaryHeight(kEpoch - 1, 0);
    s.nHeightEnd = pBoundary->nHeight - 1;
    s.hashBoundaryBlock = pBoundary->pprev->GetBlockHash();
    s.nSerVersion = EPOCHSTATE_SER_VERSION;
    s.vchVNextRoot = DigestBytes(note.finalizedRoot);
    s.nVNextTreeSize = note.nTreeSize;
    s.vchVNextParameterDigest = DigestBytes(ContractDigest());
    return s;
}

// One epoch number's record for the length of a case, put back exactly at the end: the
// prior record if there was one, else erased.
struct ScopedEpochRecord
{
    CTxDB& txdb;
    int nEpoch;
    bool fHadPrior;
    CEpochState prior;

    ScopedEpochRecord(CTxDB& txdbIn, int nEpochIn)
        : txdb(txdbIn), nEpoch(nEpochIn), fHadPrior(false)
    {
        if (txdb.ProbeEpochState(nEpoch) == TXDB_READ_FOUND)
        {
            fHadPrior = true;
            // A record this build cannot decode would be lost by the restore below.
            BOOST_REQUIRE(txdb.ReadEpochState(nEpoch, prior));
        }
    }
    ScopedEpochRecord(CTxDB& txdbIn, int nEpochIn, const CEpochState& install)
        : txdb(txdbIn), nEpoch(nEpochIn), fHadPrior(false)
    {
        if (txdb.ProbeEpochState(nEpoch) == TXDB_READ_FOUND)
        {
            fHadPrior = true;
            BOOST_REQUIRE(txdb.ReadEpochState(nEpoch, prior));
        }
        Set(install);
    }
    void Set(const CEpochState& s) { BOOST_REQUIRE(txdb.WriteEpochState(nEpoch, s)); }
    void Remove() { BOOST_REQUIRE(txdb.EraseEpochState(nEpoch)); }
    ~ScopedEpochRecord()
    {
        if (fHadPrior)
            txdb.WriteEpochState(nEpoch, prior);
        else
            txdb.EraseEpochState(nEpoch);
    }
};

// Spent-key entries a case may write, erased when it ends.
struct ScopedSpentKeys
{
    CTxDB& txdb;
    std::vector<uint256> vKeys;

    explicit ScopedSpentKeys(CTxDB& txdbIn) : txdb(txdbIn) {}
    void Track(const PrivacyVNextDigest& keyImage) { vKeys.push_back(AsUint256(keyImage)); }
    ~ScopedSpentKeys()
    {
        for (size_t i = 0; i < vKeys.size(); ++i)
            txdb.ErasePrivacyVNextNullifier(vKeys[i]);
    }
};

// A vote cast by one note for one named block, decoded into the effects consensus judges.
struct BuiltVote
{
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    PrivacyVNextOutputLeaf reissue;
    PrivacyVNextStateEffects effects;
    CTransaction tx;
};

void CastVote(const FundedNote& note, const PrivacyVNextDigest& namedHash,
              int nNamedHeight, uint32_t nTime, BuiltVote& out)
{
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, ContractDigest(), kVoteNote, 0, 0, namedHash,
                            (uint32_t)nNamedHeight, out.payload, out.keyImage,
                            out.reissue, error),
        error);
    const PrivacyVNextPayloadValidation extracted =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          out.payload, out.effects);
    BOOST_REQUIRE_MESSAGE(extracted.IsValid(), extracted.strError);
    BOOST_REQUIRE(out.effects.HasVoteBoundary());
    BOOST_REQUIRE_EQUAL(out.effects.keyImages.size(), 1U);
    out.tx = CarryingTx(out.payload, nTime);
}

void CastVote(const FundedNote& note, const CBlockIndex* pNamed, uint32_t nTime,
              BuiltVote& out)
{
    CastVote(note, BlockDigest(pNamed), pNamed->nHeight, nTime, out);
}

void Fund(CTxDB& txdb, unsigned char nSeed, FundedNote& note)
{
    std::string error;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, nSeed, kVoteNote, note, error), error);
}

struct ContextVerdict
{
    bool fOK;
    bool fLocalFailure;
    bool fUnavailable;
    std::string strError;
};

// The vote judged where ConnectBlock judges it: in the block at nHeight of the chain
// pTip heads.
ContextVerdict JudgeVote(CTxDB& txdb, const CBlockIndex* pTip, int nHeight,
                         const PrivacyVNextStateEffects& effects)
{
    ContextVerdict v;
    v.fLocalFailure = false;
    v.fUnavailable = false;
    v.fOK = ValidatePrivacyVNextNoteVoteContext(txdb, pTip, nHeight, effects,
                                                v.fLocalFailure, v.fUnavailable,
                                                v.strError);
    return v;
}

ContextVerdict JudgeVote(CTxDB& txdb, const VoteChain& chain, int nHeight,
                         const PrivacyVNextStateEffects& effects)
{
    return JudgeVote(txdb, chain.At(nHeight), nHeight, effects);
}

bool Mentions(const std::string& strError, const char* what)
{
    return strError.find(what) != std::string::npos;
}

int SpentStatus(CTxDB& txdb, const PrivacyVNextDigest& keyImage,
                CPrivacyVNextNullifierSpent& record)
{
    return (int)txdb.ReadPrivacyVNextNullifierStatus(AsUint256(keyImage), record);
}

int Connect(CTxDB& txdb, const BuiltVote& vote, int nHeight, bool fJustCheck,
            std::set<uint256>& setBlock, std::string& error)
{
    return (int)ConnectPrivacyVNextSpentKeys(txdb, vote.tx, vote.effects, nHeight,
                                             fJustCheck, setBlock, error);
}

int Disconnect(CTxDB& txdb, const BuiltVote& vote, int nHeight, std::string& error)
{
    return (int)DisconnectPrivacyVNextSpentKeys(txdb, vote.tx, vote.effects, nHeight,
                                                error);
}

} // namespace

BOOST_AUTO_TEST_SUITE(note_vote_connect_tests)

// Positive control: in window, on its own chain, anchored to E-1, the vote passes the
// validator and the tx-level entry, and its key image is indexed with carrier and height.
// fJustCheck writes nothing.
BOOST_AUTO_TEST_CASE(a_vote_in_its_window_connects_and_consumes_its_note)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E760100U);
    const int nBoundary = BoundaryHeight();

    FundedNote note;
    Fund(txdb, 0x11, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500000101, vote);
    ScopedEpochRecord anchor(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));
    ScopedSpentKeys spent(txdb);
    spent.Track(vote.keyImage);

    BOOST_CHECK_EQUAL((int)vote.effects.nVoteBoundaryHeight, nBoundary);
    BOOST_CHECK(vote.effects.keyImages[0] == vote.keyImage);

    const int nConnect = nBoundary + 1;
    const ContextVerdict v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    BOOST_CHECK(!v.fLocalFailure);
    BOOST_CHECK(!v.fUnavailable);

    std::string error;
    BOOST_CHECK_MESSAGE(CheckPrivacyVNextFinalizedAnchor(txdb, chain.At(nConnect),
                                                         nConnect, vote.tx, error),
                        error);
    BOOST_CHECK_MESSAGE(CheckPrivacyVNextNoteVoteCarrier(vote.tx, vote.effects, error),
                        error);
    BOOST_CHECK(IsPrivacyVNextNoteVoteShape(vote.tx));

    CPrivacyVNextNullifierSpent record;
    BOOST_REQUIRE_EQUAL(SpentStatus(txdb, vote.keyImage, record), (int)TXDB_READ_NOT_FOUND);

    std::set<uint256> setBlock;
    BOOST_CHECK_EQUAL(Connect(txdb, vote, nConnect, true, setBlock, error),
                      (int)PRIVACY_VNEXT_SPEND_OK);
    BOOST_CHECK_EQUAL(SpentStatus(txdb, vote.keyImage, record), (int)TXDB_READ_NOT_FOUND);

    setBlock.clear();
    BOOST_REQUIRE_EQUAL(Connect(txdb, vote, nConnect, false, setBlock, error),
                        (int)PRIVACY_VNEXT_SPEND_OK);
    BOOST_REQUIRE_EQUAL(SpentStatus(txdb, vote.keyImage, record), (int)TXDB_READ_FOUND);
    BOOST_CHECK(record.txnHash == vote.tx.GetHash());
    BOOST_CHECK_EQUAL(record.nIndex, 0U);
    BOOST_CHECK_EQUAL(record.nHeight, nConnect);
    BOOST_CHECK_EQUAL(setBlock.count(AsUint256(vote.keyImage)), 1U);
}

// A second vote of the same note is a double spend: refused by the block's set in the
// same block and by the index in a later one.
BOOST_AUTO_TEST_CASE(a_second_vote_of_one_note_is_refused_as_spent)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E760200U);
    const int nBoundary = BoundaryHeight();

    FundedNote note;
    Fund(txdb, 0x13, note);
    BuiltVote first;
    CastVote(note, chain.pBoundary, 1500000201, first);
    BuiltVote second;
    CastVote(note, chain.pBoundary, 1500000202, second);
    ScopedEpochRecord anchor(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));
    ScopedSpentKeys spent(txdb);
    spent.Track(first.keyImage);

    BOOST_REQUIRE(second.keyImage == first.keyImage);
    BOOST_REQUIRE(second.tx.GetHash() != first.tx.GetHash());

    std::string error;
    std::set<uint256> setBlock;
    BOOST_REQUIRE_EQUAL(Connect(txdb, first, nBoundary + 1, false, setBlock, error),
                        (int)PRIVACY_VNEXT_SPEND_OK);

    // Same block: the block's set refuses it before the index is read.
    BOOST_CHECK_EQUAL(Connect(txdb, second, nBoundary + 1, false, setBlock, error),
                      (int)PRIVACY_VNEXT_SPEND_INVALID);
    BOOST_CHECK_MESSAGE(Mentions(error, "duplicate"), error);

    // A later block of the window: the context still passes, the index refuses.
    const ContextVerdict v = JudgeVote(txdb, chain, nBoundary + 2, second.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    std::set<uint256> setLater;
    BOOST_CHECK_EQUAL(Connect(txdb, second, nBoundary + 2, false, setLater, error),
                      (int)PRIVACY_VNEXT_SPEND_INVALID);
    BOOST_CHECK_MESSAGE(Mentions(error, "already consumed"), error);
    // fJustCheck answers the same.
    setLater.clear();
    BOOST_CHECK_EQUAL(Connect(txdb, second, nBoundary + 2, true, setLater, error),
                      (int)PRIVACY_VNEXT_SPEND_INVALID);

    // The record still names the first carrier.
    CPrivacyVNextNullifierSpent record;
    BOOST_REQUIRE_EQUAL(SpentStatus(txdb, first.keyImage, record), (int)TXDB_READ_FOUND);
    BOOST_CHECK(record.txnHash == first.tx.GetHash());
    BOOST_CHECK_EQUAL(record.nHeight, nBoundary + 1);
}

// R1 of the note lane: an epoch-E note vote connects at heights in
// [H_E, H_E + FINALITY_NOTE_VOTE_INCLUSION_WINDOW) and nowhere else. Each refusal here is
// the window's, since every other rule holds on the main branch at those heights.
BOOST_AUTO_TEST_CASE(a_vote_connects_only_inside_its_inclusion_window)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E760300U);
    const int nFirst = BoundaryHeight();
    const int nLast = nFirst + FINALITY_NOTE_VOTE_INCLUSION_WINDOW - 1;
    BOOST_REQUIRE(FINALITY_NOTE_VOTE_INCLUSION_WINDOW > FINALITY_VOTE_INCLUSION_WINDOW);

    FundedNote note;
    Fund(txdb, 0x15, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500000301, vote);
    ScopedEpochRecord anchor(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));

    ContextVerdict v = JudgeVote(txdb, chain, nFirst, vote.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    v = JudgeVote(txdb, chain, nLast, vote.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    // Past the transparent lane's window, still inside the note lane's.
    v = JudgeVote(txdb, chain, nFirst + FINALITY_VOTE_INCLUSION_WINDOW, vote.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);

    v = JudgeVote(txdb, chain, nLast + 1, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);
    BOOST_CHECK(!v.fLocalFailure);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "inclusion window"), v.strError);

    // Below the boundary the window closes it before ancestry can.
    v = JudgeVote(txdb, chain, nFirst - 1, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "inclusion window"), v.strError);

    // The transaction-level entry agrees at both edges.
    std::string error;
    BOOST_CHECK(CheckPrivacyVNextFinalizedAnchor(txdb, chain.At(nLast), nLast, vote.tx,
                                                 error));
    BOOST_CHECK(!CheckPrivacyVNextFinalizedAnchor(txdb, chain.At(nLast + 1), nLast + 1,
                                                  vote.tx, error));

    // A vote is judged only in a chain context.
    v = JudgeVote(txdb, chain.pTip, -1, vote.effects);
    BOOST_CHECK(!v.fOK);
}

// Presence in the block index is not membership of the carrier's chain; only ancestry
// separates the sibling's H_E from the main branch's.
BOOST_AUTO_TEST_CASE(a_vote_naming_a_sibling_boundary_is_refused_on_the_main_branch)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E760400U);
    const int nBoundary = BoundaryHeight();

    FundedNote note;
    Fund(txdb, 0x17, note);
    BuiltVote onMain;
    CastVote(note, chain.pBoundary, 1500000401, onMain);
    BuiltVote onSibling;
    CastVote(note, chain.pSiblingBoundary, 1500000402, onSibling);
    // The identity pin is the shared parent, so it holds on both branches.
    ScopedEpochRecord anchor(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));
    BOOST_REQUIRE(chain.pSiblingBoundary->pprev == chain.pBoundary->pprev);
    BOOST_REQUIRE(chain.pSiblingBoundary->nHeight == nBoundary);
    BOOST_REQUIRE(chain.pSiblingBoundary->IsProofOfWork());

    ContextVerdict v = JudgeVote(txdb, chain, nBoundary + 2, onSibling.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);
    BOOST_CHECK(!v.fLocalFailure);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "not an ancestor"), v.strError);

    // The same vote on its own branch connects; the main branch's vote does not.
    v = JudgeVote(txdb, chain.pSiblingTip, nBoundary + 3, onSibling.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    v = JudgeVote(txdb, chain.pSiblingTip, nBoundary + 3, onMain.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "not an ancestor"), v.strError);
    v = JudgeVote(txdb, chain, nBoundary + 2, onMain.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);

    // The transaction-level entry agrees.
    std::string error;
    BOOST_CHECK(!CheckPrivacyVNextFinalizedAnchor(txdb, chain.At(nBoundary + 2),
                                                  nBoundary + 2, onSibling.tx, error));
    BOOST_CHECK(CheckPrivacyVNextFinalizedAnchor(txdb, chain.pSiblingTip, nBoundary + 3,
                                                 onSibling.tx, error));

    // A block no node indexed is a verdict in a chain context, never local state.
    BuiltVote unknown;
    CastVote(note, CollateralDigest(0x7e), nBoundary, 1500000403, unknown);
    v = JudgeVote(txdb, chain, nBoundary + 2, unknown.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);
    BOOST_CHECK(!v.fLocalFailure);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "unknown"), v.strError);

    // A block that opens no epoch.
    BuiltVote offBoundary;
    CastVote(note, chain.At(nBoundary + 1), 1500000404, offBoundary);
    v = JudgeVote(txdb, chain, nBoundary + 2, offBoundary.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "opens no post-DAG epoch"), v.strError);

    // A proof-of-stake boundary.
    chain.pSiblingBoundary->nFlags |= CBlockIndex::BLOCK_PROOF_OF_STAKE;
    v = JudgeVote(txdb, chain.pSiblingTip, nBoundary + 3, onSibling.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "proof-of-work"), v.strError);
    chain.pSiblingBoundary->nFlags &= ~CBlockIndex::BLOCK_PROOF_OF_STAKE;
    v = JudgeVote(txdb, chain.pSiblingTip, nBoundary + 3, onSibling.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);

    // With no carrier chain the vote is refused.
    v = JudgeVote(txdb, (const CBlockIndex*)NULL, nBoundary + 2, onMain.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fLocalFailure);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "no carrier chain"), v.strError);
}

// Disconnecting the carrier erases exactly what connecting it wrote: the record at the
// carrier's height and no other, after which the note votes again in another block.
BOOST_AUTO_TEST_CASE(a_disconnect_erases_the_spent_entry_and_frees_the_note)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E760500U);
    const int nBoundary = BoundaryHeight();

    FundedNote note;
    Fund(txdb, 0x19, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500000501, vote);
    ScopedEpochRecord anchor(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));
    ScopedSpentKeys spent(txdb);
    spent.Track(vote.keyImage);

    std::string error;
    std::set<uint256> setBlock;
    BOOST_REQUIRE_EQUAL(Connect(txdb, vote, nBoundary + 1, false, setBlock, error),
                        (int)PRIVACY_VNEXT_SPEND_OK);
    CPrivacyVNextNullifierSpent record;
    BOOST_REQUIRE_EQUAL(SpentStatus(txdb, vote.keyImage, record), (int)TXDB_READ_FOUND);

    // A disconnect at another height finds a record this block did not write and
    // changes nothing.
    BOOST_CHECK_EQUAL(Disconnect(txdb, vote, nBoundary + 2, error),
                      (int)PRIVACY_VNEXT_UNDO_MISMATCH);
    BOOST_CHECK_EQUAL(SpentStatus(txdb, vote.keyImage, record), (int)TXDB_READ_FOUND);
    BOOST_CHECK_EQUAL(record.nHeight, nBoundary + 1);

    // Another carrier of the same key image at the same height is not the writer.
    BuiltVote other;
    CastVote(note, chain.pBoundary, 1500000502, other);
    BOOST_REQUIRE(other.keyImage == vote.keyImage);
    BOOST_CHECK_EQUAL(Disconnect(txdb, other, nBoundary + 1, error),
                      (int)PRIVACY_VNEXT_UNDO_MISMATCH);
    BOOST_CHECK_EQUAL(SpentStatus(txdb, vote.keyImage, record), (int)TXDB_READ_FOUND);

    // The carrier's own disconnect erases it.
    BOOST_CHECK_EQUAL(Disconnect(txdb, vote, nBoundary + 1, error),
                      (int)PRIVACY_VNEXT_UNDO_OK);
    BOOST_CHECK_EQUAL(SpentStatus(txdb, vote.keyImage, record), (int)TXDB_READ_NOT_FOUND);

    // A second undo has nothing to erase.
    BOOST_CHECK_EQUAL(Disconnect(txdb, vote, nBoundary + 1, error),
                      (int)PRIVACY_VNEXT_UNDO_MISMATCH);

    // The note is spendable again: the vote connects in another block of the window.
    std::set<uint256> setLater;
    BOOST_CHECK_EQUAL(Connect(txdb, vote, nBoundary + 3, false, setLater, error),
                      (int)PRIVACY_VNEXT_SPEND_OK);
    BOOST_REQUIRE_EQUAL(SpentStatus(txdb, vote.keyImage, record), (int)TXDB_READ_FOUND);
    BOOST_CHECK_EQUAL(record.nHeight, nBoundary + 3);
}

// The anchor is E-1, identified by epoch number, end height and boundary block before the
// root is compared. Absent or other-branch record: local state, not a verdict. Root
// mismatch under a matching identity: a verdict.
BOOST_AUTO_TEST_CASE(a_vote_anchors_to_epoch_state_e_minus_1_by_identity_then_root)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E760600U);
    const int nBoundary = BoundaryHeight();
    const int nConnect = nBoundary + 1;

    FundedNote note;
    Fund(txdb, 0x1b, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500000601, vote);
    const CEpochState good = AnchorRecord(note, chain.pBoundary);
    ScopedEpochRecord anchor(txdb, kEpoch - 1);
    ScopedEpochRecord older(txdb, kEpoch - 2);

    // No record: retried, never scored.
    anchor.Remove();
    ContextVerdict v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(v.fUnavailable);
    BOOST_CHECK(!v.fLocalFailure);

    // A matching root under another branch's boundary block: not this chain's record.
    CEpochState otherBranch = good;
    otherBranch.hashBoundaryBlock = chain.At(nBoundary - 2)->GetBlockHash();
    anchor.Set(otherBranch);
    v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(v.fUnavailable);
    BOOST_CHECK(!v.fLocalFailure);

    // The record's own epoch number and end height are part of its identity.
    CEpochState misnumbered = good;
    misnumbered.nEpoch = kEpoch - 2;
    anchor.Set(misnumbered);
    v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(v.fUnavailable);
    CEpochState misended = good;
    misended.nHeightEnd = nBoundary;
    anchor.Set(misended);
    v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(v.fUnavailable);

    // Identity holds, root differs: a verdict. The matching root filed under E-2 does
    // not stand in.
    CEpochState asOlder = good;
    asOlder.nEpoch = kEpoch - 2;
    asOlder.nHeightStart = GetEpochBoundaryHeight(kEpoch - 2, 0);
    asOlder.nHeightEnd = GetEpochBoundaryHeight(kEpoch - 1, 0) - 1;
    asOlder.hashBoundaryBlock = chain.At(asOlder.nHeightEnd)->GetBlockHash();
    older.Set(asOlder);
    CEpochState wrongRoot = good;
    wrongRoot.vchVNextRoot[0] ^= 0x01;
    anchor.Set(wrongRoot);
    v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);
    BOOST_CHECK(!v.fLocalFailure);
    BOOST_CHECK_MESSAGE(Mentions(v.strError, "not anchored"), v.strError);

    CEpochState wrongSize = good;
    wrongSize.nVNextTreeSize += 1;
    anchor.Set(wrongSize);
    v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);

    CEpochState wrongDigest = good;
    wrongDigest.vchVNextParameterDigest[0] ^= 0x01;
    anchor.Set(wrongDigest);
    v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);

    // A record written before the pool carries no root to anchor to.
    CEpochState preIV5 = good;
    preIV5.nSerVersion = EPOCHSTATE_SER_VERSION_V3;
    anchor.Set(preIV5);
    v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK(!v.fOK);
    BOOST_CHECK(!v.fUnavailable);
    BOOST_CHECK(!v.fLocalFailure);

    anchor.Set(good);
    v = JudgeVote(txdb, chain, nConnect, vote.effects);
    BOOST_CHECK_MESSAGE(v.fOK, v.strError);
}

// The lane is closed until its fork height, judged on the context height, and the gate
// reads the decoded effects rather than the declared operation byte.
BOOST_AUTO_TEST_CASE(the_lane_is_closed_below_its_fork_height)
{
    CTxDB txdb("r+");
    VoteChain chain(0x6E760700U);
    const int nBoundary = BoundaryHeight();

    FundedNote note;
    Fund(txdb, 0x1d, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500000701, vote);
    ScopedEpochRecord anchor(txdb, kEpoch - 1, AnchorRecord(note, chain.pBoundary));

    {
        ScopedNoteVoteHeight unset(PRIVACY_VNEXT_HEIGHT_UNSET);
        const ContextVerdict v = JudgeVote(txdb, chain, nBoundary + 2, vote.effects);
        BOOST_CHECK(!v.fOK);
        BOOST_CHECK(!v.fUnavailable);
        BOOST_CHECK(!v.fLocalFailure);
        BOOST_CHECK_MESSAGE(Mentions(v.strError, "not active"), v.strError);
        std::string error;
        BOOST_CHECK(!CheckPrivacyVNextFinalizedAnchor(txdb, chain.At(nBoundary + 2),
                                                      nBoundary + 2, vote.tx, error));
    }
    {
        ScopedNoteVoteHeight late(nBoundary + 3);
        ContextVerdict v = JudgeVote(txdb, chain, nBoundary + 2, vote.effects);
        BOOST_CHECK(!v.fOK);
        BOOST_CHECK_MESSAGE(Mentions(v.strError, "not active"), v.strError);
        v = JudgeVote(txdb, chain, nBoundary + 3, vote.effects);
        BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    }
    {
        ScopedNoteVoteHeight open(0);
        const ContextVerdict v = JudgeVote(txdb, chain, nBoundary + 2, vote.effects);
        BOOST_CHECK_MESSAGE(v.fOK, v.strError);
    }
}


// The stake floor is enforced only by the payload verifier. Both arms pass every other
// rule, so the floor statement is the only thing left to reject.
BOOST_AUTO_TEST_CASE(the_stake_floor_is_enforced_by_the_payload_verifier)
{
    CTxDB txdb("r+");
    std::string error;

    // One satoshi under the floor: no in-range opening, so the floor section is empty.
    {
        FundedNote under;
        BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xB1, kVoteNote - 1, under, error), error);
        std::vector<unsigned char> payload;
        PrivacyVNextDigest keyImage;
        PrivacyVNextOutputLeaf reissue;
        BOOST_REQUIRE_MESSAGE(
            BuildShapedNoteVote(under, ContractDigest(), kVoteNote - 1, 0, 0,
                                ContractDigest(), 6000, payload, keyImage, reissue,
                                error),
            error);
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
        BOOST_CHECK_MESSAGE(!validation.IsValid(),
                            "a note under the stake floor must not validate");
    }

    // At the floor, but proven over the unshifted commitment: well formed, refused by the
    // floor statement.
    {
        FundedNote atFloor;
        BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xB2, kVoteNote, atFloor, error), error);
        std::vector<unsigned char> payload;
        PrivacyVNextDigest keyImage;
        PrivacyVNextOutputLeaf reissue;
        BOOST_REQUIRE_MESSAGE(
            BuildShapedNoteVote(atFloor, ContractDigest(), kVoteNote, 0, 0,
                                ContractDigest(), 6000, payload, keyImage, reissue,
                                error, true /* fProveUnshifted */),
            error);
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
        BOOST_CHECK_MESSAGE(!validation.IsValid(),
                            "a range proof over the unshifted commitment satisfies no floor");
    }

    // The control: at the floor, shifted correctly, the same shape validates.
    {
        FundedNote good;
        BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xB3, kVoteNote, good, error), error);
        std::vector<unsigned char> payload;
        PrivacyVNextDigest keyImage;
        PrivacyVNextOutputLeaf reissue;
        BOOST_REQUIRE_MESSAGE(
            BuildShapedNoteVote(good, ContractDigest(), kVoteNote, 0, 0,
                                ContractDigest(), 6000, payload, keyImage, reissue,
                                error),
            error);
        PrivacyVNextStateEffects effects;
        const PrivacyVNextPayloadValidation validation =
            ExtractPrivacyVNextPayloadEffects(
                INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, effects);
        BOOST_CHECK_MESSAGE(validation.IsValid(), validation.strError);
    }
}


// The tally record is derived from the vote payload, not a script. The four fields
// asserted are all the tally reads; connect and disconnect share this function.
BOOST_AUTO_TEST_CASE(the_extractor_derives_a_record_from_an_op_10_payload)
{
    CTxDB txdb("r+");
    std::string error;
    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xC1, kVoteNote, note, error), error);

    const uint32_t nBoundaryHeight = 6000;
    PrivacyVNextDigest boundary = ContractDigest();
    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    PrivacyVNextOutputLeaf reissue;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, ContractDigest(), kVoteNote, 0, 0, boundary,
                            nBoundaryHeight, payload, keyImage, reissue, error),
        error);

    CBlock block;
    block.vtx.push_back(CTransaction());              // coinbase placeholder
    block.vtx.push_back(CarryingTx(payload, 1000));

    // Unset on every value network, so the source yields nothing until a height is set.
    {
        ScopedNoteVoteHeight off(PRIVACY_VNEXT_HEIGHT_UNSET);
        std::vector<CNoteFinalityVote> vNone;
        FinalityEnvelopeDecodeResult failure = FINALITY_ENVELOPE_INVALID;
        BOOST_CHECK(ExtractNoteFinalityVotesFromBlockForHeight(block, 6100, vNone,
                                                               &failure));
        BOOST_CHECK(vNone.empty());
    }

    ScopedNoteVoteHeight fork(0);
    std::vector<CNoteFinalityVote> vVotes;
    FinalityEnvelopeDecodeResult failure = FINALITY_ENVELOPE_INVALID;
    BOOST_REQUIRE(ExtractNoteFinalityVotesFromBlockForHeight(block, 6100, vVotes,
                                                             &failure));
    BOOST_REQUIRE_EQUAL(vVotes.size(), 1U);
    const CNoteFinalityVote& vote = vVotes[0];

    // The boundary it names, and the height that fixes its epoch.
    uint256 hashBoundary = 0;
    memcpy(hashBoundary.begin(), boundary.data(), boundary.size());
    BOOST_CHECK(vote.hashBlock == hashBoundary);
    BOOST_CHECK_EQUAL(vote.nHeight, (int)nBoundaryHeight);
    BOOST_CHECK_EQUAL(vote.nEpoch, GetEpochForHeight((int)nBoundaryHeight));

    // The tag is the payload's key image.
    BOOST_REQUIRE_EQUAL(vote.vchTag.size(), (size_t)FINALITY_NOTE_POINT_SIZE);
    BOOST_CHECK(memcmp(&vote.vchTag[0], keyImage.data(), keyImage.size()) == 0);
    BOOST_CHECK_EQUAL(vote.nVersion, FINALITY_NOTE_VOTE_VERSION);

    // The record must round-trip through the tracker's persistence.
    BOOST_CHECK(vote.IsValidBasic(&error));

    // A block with no vote-shaped transaction yields nothing rather than failing.
    CBlock plain;
    plain.vtx.push_back(CTransaction());
    std::vector<CNoteFinalityVote> vEmpty;
    BOOST_CHECK(ExtractNoteFinalityVotesFromBlockForHeight(plain, 6100, vEmpty,
                                                           &failure));
    BOOST_CHECK(vEmpty.empty());

    // A vote-shaped tx whose payload yields no record invalidates the block.
    CBlock corrupt;
    corrupt.vtx.push_back(CTransaction());
    std::vector<unsigned char> mangled = payload;
    mangled.resize(mangled.size() / 2);
    corrupt.vtx.push_back(CarryingTx(mangled, 1000));
    if (IsPrivacyVNextNoteVoteShape(corrupt.vtx[1]))
    {
        std::vector<CNoteFinalityVote> vBad;
        FinalityEnvelopeDecodeResult badFailure = FINALITY_ENVELOPE_NO_MATCH;
        BOOST_CHECK(!ExtractNoteFinalityVotesFromBlockForHeight(corrupt, 6100, vBad,
                                                                &badFailure));
        BOOST_CHECK(vBad.empty());
        BOOST_CHECK_EQUAL(badFailure, FINALITY_ENVELOPE_INVALID);
    }
}

// A vote is carried by its payload alone, and the per-block and per-window caps count
// what a block adds against what the window already holds.
BOOST_AUTO_TEST_CASE(a_vote_rides_bare_and_the_caps_hold)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    VoteChain chain(0x6E760800U);

    FundedNote note;
    Fund(txdb, 0x1f, note);
    BuiltVote vote;
    CastVote(note, chain.pBoundary, 1500000801, vote);

    std::string error;
    BOOST_CHECK(CheckPrivacyVNextNoteVoteCarrier(vote.tx, vote.effects, error));

    CTransaction withInput = vote.tx;
    withInput.vin.push_back(CTxIn(COutPoint(uint256(1), 0)));
    BOOST_CHECK(!CheckPrivacyVNextNoteVoteCarrier(withInput, vote.effects, error));
    BOOST_CHECK(!IsPrivacyVNextNoteVoteShape(withInput));

    CTransaction withOutput = vote.tx;
    withOutput.vout.push_back(CTxOut(1, CScript()));
    BOOST_CHECK(!CheckPrivacyVNextNoteVoteCarrier(withOutput, vote.effects, error));
    BOOST_CHECK(!IsPrivacyVNextNoteVoteShape(withOutput));

    // The rule is a vote's alone: any other payload may carry a transparent side.
    PrivacyVNextStateEffects transfer;
    BOOST_CHECK(CheckPrivacyVNextNoteVoteCarrier(withInput, transfer, error));

    CBlock block;
    block.vtx.push_back(vote.tx);
    block.vtx.push_back(withInput);
    block.vtx.push_back(CTransaction());
    BOOST_CHECK_EQUAL(CountPrivacyVNextNoteVoteShapes(block), 1U);

    const unsigned int nBlockMax = FINALITY_MAX_BLOCK_NOTE_VOTES;
    const unsigned int nWindowMax = FINALITY_MAX_EPOCH_NOTE_VOTES;
    BOOST_CHECK(CheckPrivacyVNextNoteVoteCaps(nBlockMax, 0, error));
    BOOST_CHECK(!CheckPrivacyVNextNoteVoteCaps(nBlockMax + 1, 0, error));
    BOOST_CHECK(CheckPrivacyVNextNoteVoteCaps(1, nWindowMax - 1, error));
    BOOST_CHECK(!CheckPrivacyVNextNoteVoteCaps(1, nWindowMax, error));
    BOOST_CHECK(!CheckPrivacyVNextNoteVoteCaps(2, nWindowMax - 1, error));
    BOOST_CHECK(!CheckPrivacyVNextNoteVoteCaps(0, nWindowMax + 1, error));
    BOOST_CHECK(CheckPrivacyVNextNoteVoteCaps(0, nWindowMax, error));
}

// Validity of a payload by both decoders: the verifying one and the proof-free one the
// vote extractor reads.
void CheckPayloadVerdict(const std::vector<unsigned char>& payload, bool fExpectValid,
                         const char* what)
{
    PrivacyVNextStateEffects effects;
    const PrivacyVNextPayloadValidation verified =
        ExtractPrivacyVNextPayloadEffects(INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION,
                                          payload, effects);
    BOOST_CHECK_MESSAGE(verified.IsValid() == fExpectValid,
                        std::string(what) + " (verifying): " + verified.strError);
    PrivacyVNextStateEffects assumed;
    const PrivacyVNextPayloadValidation unverified =
        ExtractPrivacyVNextPayloadEffectsAssumeValid(
            INNOVA_PRIVACY_VNEXT_TRANSACTION_VERSION, payload, assumed);
    BOOST_CHECK_MESSAGE(unverified.IsValid() == fExpectValid,
                        std::string(what) + " (assume-valid): " + unverified.strError);
}

// The extractor's verdict on a block carrying one payload.
bool ExtractFromCarrier(const std::vector<unsigned char>& payload,
                        std::vector<CNoteFinalityVote>& vVotes,
                        FinalityEnvelopeDecodeResult& failure)
{
    CBlock block;
    block.vtx.push_back(CTransaction());
    block.vtx.push_back(CarryingTx(payload, 1000));
    BOOST_REQUIRE(IsPrivacyVNextNoteVoteShape(block.vtx[1]));
    failure = FINALITY_ENVELOPE_NO_MATCH;
    return ExtractNoteFinalityVotesFromBlockForHeight(block, 6100, vVotes, &failure);
}

// A vote spends exactly one note; a two-note vote is refused by the payload shape rule.
BOOST_AUTO_TEST_CASE(a_note_vote_with_two_inputs_is_refused_by_the_payload_validator)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    std::string error;
    std::vector<unsigned char> vSeeds;
    vSeeds.push_back(0xD1);
    vSeeds.push_back(0xD5);
    FundedNote first;
    FundedNote second;
    std::vector<FundedNote*> vNotes;
    vNotes.push_back(&first);
    vNotes.push_back(&second);
    BOOST_REQUIRE_MESSAGE(FundNotes(txdb, vSeeds, kVoteNote, vNotes, error), error);

    // The control: one of the same notes, same tree, validates.
    {
        std::vector<unsigned char> payload;
        PrivacyVNextDigest keyImage;
        PrivacyVNextOutputLeaf reissue;
        BOOST_REQUIRE_MESSAGE(
            BuildShapedNoteVote(first, ContractDigest(), kVoteNote, 0, 0,
                                ContractDigest(), 6000, payload, keyImage, reissue,
                                error),
            error);
        CheckPayloadVerdict(payload, true, "one-input vote");
    }

    std::vector<unsigned char> payload;
    PrivacyVNextDigest keyImage;
    PrivacyVNextOutputLeaf reissue;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(first, ContractDigest(), 2 * kVoteNote, 0, 0,
                            ContractDigest(), 6000, payload, keyImage, reissue, error,
                            false, &second),
        error);
    CheckPayloadVerdict(payload, false, "two-input vote");

    std::vector<CNoteFinalityVote> vVotes;
    FinalityEnvelopeDecodeResult failure;
    BOOST_CHECK(!ExtractFromCarrier(payload, vVotes, failure));
    BOOST_CHECK(vVotes.empty());
    BOOST_CHECK_EQUAL(failure, FINALITY_ENVELOPE_INVALID);
}

// The record fields IsValidBasic checks are fixed before the record is built: a zero
// boundary hash and a key image that is not a prime-order point are refused by the
// decoder, and a boundary height past the height type by the extractor.
BOOST_AUTO_TEST_CASE(a_vote_record_field_is_refused_before_the_record_is_built)
{
    ScopedNoteVoteHeight fork(0);
    CTxDB txdb("r+");
    std::string error;
    FundedNote note;
    BOOST_REQUIRE_MESSAGE(FundNote(txdb, 0xD9, kVoteNote, note, error), error);

    std::vector<unsigned char> good;
    PrivacyVNextDigest keyImage;
    PrivacyVNextOutputLeaf reissue;
    BOOST_REQUIRE_MESSAGE(
        BuildShapedNoteVote(note, ContractDigest(), kVoteNote, 0, 0, ContractDigest(),
                            6000, good, keyImage, reissue, error),
        error);
    CheckPayloadVerdict(good, true, "control vote");

    // A zero boundary hash, proven over as asked.
    {
        PrivacyVNextDigest zero;
        zero.fill(0);
        std::vector<unsigned char> payload;
        PrivacyVNextDigest ki;
        PrivacyVNextOutputLeaf leaf;
        BOOST_REQUIRE_MESSAGE(
            BuildShapedNoteVote(note, ContractDigest(), kVoteNote, 0, 0, zero, 6000,
                                payload, ki, leaf, error),
            error);
        CheckPayloadVerdict(payload, false, "zero boundary hash");
    }

    // The published key image replaced by the all-zero encoding (a small-order point)
    // and by the identity. The proof-free decoder is the one the extractor reads.
    std::vector<unsigned char>::iterator at =
        std::search(good.begin(), good.end(), keyImage.begin(), keyImage.end());
    BOOST_REQUIRE(at != good.end());
    const size_t nOffset = at - good.begin();
    {
        std::vector<unsigned char> payload = good;
        std::fill(payload.begin() + nOffset, payload.begin() + nOffset + 32, 0);
        CheckPayloadVerdict(payload, false, "zero key image");
    }
    {
        std::vector<unsigned char> payload = good;
        std::fill(payload.begin() + nOffset, payload.begin() + nOffset + 32, 0);
        payload[nOffset] = 1;
        CheckPayloadVerdict(payload, false, "identity key image");
    }

    // A boundary height the height type cannot hold: the payload does not judge it, the
    // extractor refuses it.
    {
        std::vector<unsigned char> payload;
        PrivacyVNextDigest ki;
        PrivacyVNextOutputLeaf leaf;
        const uint32_t nWide = (uint32_t)std::numeric_limits<int>::max() + 1U;
        BOOST_REQUIRE_MESSAGE(
            BuildShapedNoteVote(note, ContractDigest(), kVoteNote, 0, 0,
                                ContractDigest(), nWide, payload, ki, leaf, error),
            error);
        CheckPayloadVerdict(payload, true, "wide boundary height");
        std::vector<CNoteFinalityVote> vVotes;
        FinalityEnvelopeDecodeResult failure;
        BOOST_CHECK(!ExtractFromCarrier(payload, vVotes, failure));
        BOOST_CHECK(vVotes.empty());
        BOOST_CHECK_EQUAL(failure, FINALITY_ENVELOPE_INVALID);
    }

    // The control yields its record.
    std::vector<CNoteFinalityVote> vVotes;
    FinalityEnvelopeDecodeResult failure;
    BOOST_CHECK(ExtractFromCarrier(good, vVotes, failure));
    BOOST_CHECK_EQUAL(vVotes.size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
