// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_PRIVACY_VNEXT_FFI_H
#define INN_PRIVACY_VNEXT_FFI_H

#include <stdint.h>
#include <array>
#include <string>
#include <vector>

struct PrivacyVNextAbiInfo
{
    bool fLinked;
    uint32_t nAbiVersion;
    uint32_t nTransactionVersion;
    uint32_t nConsensusActive;
    uint32_t nTreeLayers;
    uint32_t nMaxInputs;
    uint32_t nMaxOutputs;
    uint32_t nMaxPayloadBytes;
    uint32_t nPayloadSchema;
    uint32_t nImplementedCapabilities;
    uint32_t nConsensusCapabilities;
    std::string strAbiSha256;
    std::string strParameterDigest;
    std::string strProvenanceDigest;
    std::string strUpstreamRevision;
    std::string strError;

    PrivacyVNextAbiInfo();
};

// Reads and cross-checks the statically linked Rust ABI. A false result is a
// local fail-closed condition and must never be attributed to peer input.
bool LoadPrivacyVNextAbiInfo(PrivacyVNextAbiInfo& info);

struct PrivacyVNextEpochSeed
{
    std::vector<unsigned char> vchTreeState;
    std::vector<unsigned char> vchRoot;
    std::vector<unsigned char> vchNullifierState;
    std::vector<unsigned char> vchNullifierRoot;
    std::vector<unsigned char> vchParameterDigest;
    uint64_t nTreeSize;
    uint64_t nNullifierCount;

    PrivacyVNextEpochSeed() : nTreeSize(0), nNullifierCount(0) {}
};

// Builds the canonical empty eight-layer accumulator and reads its parameter
// digest from the linked Rust implementation. Failure is local and fail closed.
bool LoadPrivacyVNextEpochSeed(PrivacyVNextEpochSeed& seed,
                               std::string& error);

// Recomputes root and size from one persisted Rust frontier. This is used by
// restart and write-time checks so corrupted local state is never peer blame.
bool DecodePrivacyVNextTreeState(
    const std::vector<unsigned char>& state,
    std::vector<unsigned char>& root,
    uint64_t& treeSize,
    std::string& error);

bool DecodePrivacyVNextNullifierState(
    const std::vector<unsigned char>& state,
    std::vector<unsigned char>& root,
    uint64_t& nullifierCount,
    std::string& error);

// Outcome of judging a payload. `fLocalFailure` is only for node-local failures
// (allocation, stream) and never for anything payload-derived: consumers shut down on
// it. A contained verifier panic is a deterministic reject.
struct PrivacyVNextPayloadValidation
{
    int32_t nResult;
    bool fLocalFailure;
    std::string strError;

    PrivacyVNextPayloadValidation()
        : nResult(6), fLocalFailure(true) {}
    bool IsValid() const { return nResult == 0; }
};

// The chain id a payload must declare for this node to accept it; every validation
// request carries it. Fixed for the life of the process.
uint8_t PrivacyVNextLocalNetworkId();
void PrivacyVNextLocalGenesis(unsigned char out[32]);

// Validates outer-version binding and canonical payload shape. Proof
// verification remains a separate contextual ABI operation.
PrivacyVNextPayloadValidation ValidatePrivacyVNextPayload(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload);

typedef std::array<unsigned char, 32> PrivacyVNextDigest;

struct PrivacyVNextOutputLeaf
{
    PrivacyVNextDigest owner;
    PrivacyVNextDigest nullifierBase;
    PrivacyVNextDigest commitment;
};

struct PrivacyVNextStateEffects
{
    PrivacyVNextDigest finalizedRoot;
    uint64_t nFinalizedTreeSize;
    PrivacyVNextDigest parameterDigest;
    // Signed value crossing the transparent boundary: positive enters the pool.
    int64_t nTransparentValueBalance;
    uint64_t nFee;
    // What the payload committed its transaction's transparent side to, checked by
    // consensus against GetPrivacyVNextTransparentBinding of the carrying transaction.
    PrivacyVNextDigest transparentBinding;
    std::vector<PrivacyVNextDigest> keyImages;
    std::vector<PrivacyVNextOutputLeaf> outputLeaves;
    // Key images a collateral attestation published without spending. Must never reach
    // the spent-key index, or a live collateral note would read as consumed.
    std::vector<PrivacyVNextDigest> attestationKeyImages;
    // What an attestation bound its off-chain node context to; zero otherwise.
    PrivacyVNextDigest registrationContext;

    PrivacyVNextStateEffects()
        : nFinalizedTreeSize(0), nTransparentValueBalance(0), nFee(0)
    {
        finalizedRoot.fill(0);
        parameterDigest.fill(0);
        transparentBinding.fill(0);
        registrationContext.fill(0);
    }

    // What this transaction adds to, or takes from, the pool. Every operation obeys the
    // same identity: the value that crossed the boundary, less the fee the miner takes.
    int64_t PoolDelta() const
    {
        return nTransparentValueBalance - static_cast<int64_t>(nFee);
    }
};

bool ApplyPrivacyVNextOutputLeaves(
    const std::vector<unsigned char>& currentState,
    const std::vector<PrivacyVNextOutputLeaf>& leaves,
    std::vector<unsigned char>& nextState,
    std::vector<unsigned char>& nextRoot,
    uint64_t& nextSize,
    std::string& error);

// One per-level node an append created or changed.
struct PrivacyVNextTreeNode
{
    uint8_t nLevel;
    uint64_t nIndex;
    PrivacyVNextDigest point;

    PrivacyVNextTreeNode() : nLevel(0), nIndex(0) { point.fill(0); }
};

// Apply output leaves and additionally report the nodes the append touched, so a caller
// keeping a tree store can persist them.
bool ExtendPrivacyVNextOutputLeaves(
    const std::vector<unsigned char>& currentState,
    const std::vector<PrivacyVNextOutputLeaf>& leaves,
    std::vector<unsigned char>& nextState,
    std::vector<unsigned char>& nextRoot,
    uint64_t& nextSize,
    std::vector<PrivacyVNextTreeNode>& nodes,
    std::string& error);

bool ApplyPrivacyVNextNullifiers(
    const std::vector<unsigned char>& currentState,
    const std::vector<PrivacyVNextDigest>& keyImages,
    std::vector<unsigned char>& nextState,
    std::vector<unsigned char>& nextRoot,
    uint64_t& nextCount,
    std::string& error);

// Drop every memoized payload verdict. Required wherever the verify-once cache is
// cleared, so entries from an abandoned chain cannot be carried into a new one.
void ClearPrivacyVNextEffectsCache();

// Validate payloads concurrently to prefill the effects cache; results are discarded
// and the sequential validator still decides. Pointers must outlive the call;
// `nThreads` of zero picks a count from the machine.
void WarmPrivacyVNextEffectsCache(
    const std::vector<std::pair<uint32_t, const std::vector<unsigned char>*> >& vPayloads,
    int nThreads);

// Rust performs complete payload/proof validation before returning this frame.
// A malformed frame after successful validation is local state failure.
PrivacyVNextPayloadValidation ExtractPrivacyVNextPayloadEffects(
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    PrivacyVNextStateEffects& effects);

struct PrivacyVNextDerivedKeys
{
    uint8_t nNetwork;
    uint8_t nAddressType;
    uint32_t nIndex;
    PrivacyVNextDigest spendSecret;
    PrivacyVNextDigest viewSecret;
    PrivacyVNextDigest outgoingViewSecret;
    PrivacyVNextDigest nullifierSecret;
    PrivacyVNextDigest stakingSecret;
    PrivacyVNextDigest spendPublic;
    PrivacyVNextDigest viewPublic;

    PrivacyVNextDerivedKeys();
    ~PrivacyVNextDerivedKeys();
    void Clear();

private:
    PrivacyVNextDerivedKeys(const PrivacyVNextDerivedKeys&) = delete;
    PrivacyVNextDerivedKeys& operator=(const PrivacyVNextDerivedKeys&) = delete;
};

struct PrivacyVNextAddressComponents
{
    uint8_t nNetwork;
    uint8_t nAddressType;
    PrivacyVNextDigest spendPublic;
    PrivacyVNextDigest viewPublic;

    PrivacyVNextAddressComponents()
        : nNetwork(0), nAddressType(0)
    {
        spendPublic.fill(0);
        viewPublic.fill(0);
    }
};

// These helpers expose the strict Rust-owned IV5 derivation and address codec
// to C++ wallet code. They do not persist secrets or activate consensus.
bool DerivePrivacyVNextKeys(
    const PrivacyVNextDigest& seed,
    const PrivacyVNextDigest& genesis,
    uint32_t index,
    uint8_t network,
    uint8_t addressType,
    PrivacyVNextDerivedKeys& keys,
    std::string& error);

bool EncodePrivacyVNextAddress(
    const PrivacyVNextAddressComponents& components,
    std::string& address,
    std::string& error);

bool DecodePrivacyVNextAddress(
    const std::string& address,
    uint8_t expectedNetwork,
    PrivacyVNextAddressComponents& components,
    std::string& error);

static const uint8_t PRIVACY_VNEXT_SCAN_FULL = 0;
static const uint8_t PRIVACY_VNEXT_SCAN_VIEW_ONLY = 1;
static const uint8_t PRIVACY_VNEXT_SCAN_OUTGOING = 2;

// The public part of one IV5 output, as it appears on chain. The leaf's I point is
// derived from O by the scanner, so it is not carried here.
//
// Two ephemeral keys: noteEphemeral keys the ciphertext and tweakEphemeral fixes the
// address tweak. A receiver disclosure opens the second one's shared point, so the first
// is what keeps the note closed to everyone but its owner.
struct PrivacyVNextEncryptedNote
{
    uint32_t nOutputIndex;
    PrivacyVNextDigest genesis;
    PrivacyVNextDigest leafO;
    PrivacyVNextDigest leafC;
    PrivacyVNextDigest noteEphemeral;
    PrivacyVNextDigest tweakEphemeral;
    std::vector<unsigned char> vchCiphertext;

    PrivacyVNextEncryptedNote()
        : nOutputIndex(0)
    {
        genesis.fill(0);
        leafO.fill(0);
        leafC.fill(0);
        noteEphemeral.fill(0);
        tweakEphemeral.fill(0);
    }
};

// A view-only scan leaves spendSecret and keyImage zero: it recovers the amount,
// the recipient and the commitment openings without the authority to spend.
struct PrivacyVNextScannedNote
{
    uint8_t nScanKind;
    uint8_t nNetwork;
    uint8_t nAddressType;
    uint32_t nOutputIndex;
    uint64_t nAmount;
    PrivacyVNextDigest recipientSpend;
    PrivacyVNextDigest recipientView;
    PrivacyVNextDigest spendSecret;
    PrivacyVNextDigest y;
    PrivacyVNextDigest mask;
    PrivacyVNextDigest keyImage;

    PrivacyVNextScannedNote();
    ~PrivacyVNextScannedNote();
    void Clear();

private:
    PrivacyVNextScannedNote(const PrivacyVNextScannedNote&) = delete;
    PrivacyVNextScannedNote& operator=(const PrivacyVNextScannedNote&) = delete;
};

struct PrivacyVNextValueOutput
{
    uint64_t nAmount;
    PrivacyVNextDigest mask;

    PrivacyVNextValueOutput()
        : nAmount(0)
    {
        mask.fill(0);
    }
};

struct PrivacyVNextValueProof
{
    std::vector<PrivacyVNextDigest> vOutputCommitments;
    std::vector<unsigned char> vchRangeProof;
    std::array<unsigned char, 64> balanceProof;

    PrivacyVNextValueProof();
    void Clear();
};

// scanSecret is the view secret for a recipient scan and the outgoing view
// secret for an outgoing one; spendMaterial is the spend secret for a full scan
// and is ignored otherwise. Both are consumed and wiped, never retained.
bool ScanPrivacyVNextNote(
    uint8_t scanKind,
    uint8_t network,
    uint8_t addressType,
    const PrivacyVNextEncryptedNote& note,
    const PrivacyVNextDigest& scanSecret,
    const PrivacyVNextDigest& spendMaterial,
    PrivacyVNextScannedNote& scanned,
    std::string& error);

// One derivation index's scanning material. A note opens for exactly one.
struct PrivacyVNextScanKey
{
    PrivacyVNextDigest scanSecret;
    PrivacyVNextDigest spendMaterial;

    PrivacyVNextScanKey()
    {
        scanSecret.fill(0);
        spendMaterial.fill(0);
    }
};

// One output this wallet owns, with the leaf it was matched against and the
// position in the caller's key list that opened it.
// Holds spend material: every field is wiped on clear and on move-from.
struct PrivacyVNextScanMatch
{
    uint16_t nKeyIndex;
    uint32_t nOutputIndex;
    PrivacyVNextOutputLeaf leaf;
    uint64_t nAmount;
    PrivacyVNextDigest recipientSpend;
    PrivacyVNextDigest recipientView;
    PrivacyVNextDigest spendSecret;
    PrivacyVNextDigest y;
    PrivacyVNextDigest mask;
    PrivacyVNextDigest keyImage;

    PrivacyVNextScanMatch();
    PrivacyVNextScanMatch(PrivacyVNextScanMatch&& other) noexcept;
    PrivacyVNextScanMatch& operator=(PrivacyVNextScanMatch&& other) noexcept;
    ~PrivacyVNextScanMatch();
    void Clear();

private:
    PrivacyVNextScanMatch(const PrivacyVNextScanMatch&) = delete;
    PrivacyVNextScanMatch& operator=(const PrivacyVNextScanMatch&) = delete;
};

// Outputs of one payload that open with the supplied material, plus its key images.
// Uses the consensus decoder and verifies no proof.
bool ScanPrivacyVNextPayload(
    uint8_t scanKind,
    uint8_t network,
    uint8_t addressType,
    uint32_t wireVersion,
    const std::vector<unsigned char>& payload,
    const std::vector<PrivacyVNextScanKey>& keys,
    std::vector<PrivacyVNextScanMatch>& matches,
    std::vector<PrivacyVNextDigest>& keyImages,
    uint8_t& nOutputCount,
    std::string& error);

// One input's membership witness: the proving-request tail that follows the
// caller's spend and commitment scalars.
struct PrivacyVNextMembershipWitness
{
    uint64_t nLeafIndex;
    std::vector<unsigned char> vchRecord;

    PrivacyVNextMembershipWitness() : nLeafIndex(0) {}
};

// One encrypted output, ready to be serialized into a payload. Distinct from
// PrivacyVNextEncryptedNote, which carries the single ciphertext a scan reads back.
struct PrivacyVNextEncryptedOutput
{
    uint32_t nOutputIndex;
    PrivacyVNextOutputLeaf leaf;        // O, I and C, in payload order
    PrivacyVNextDigest noteEphemeral;   // keys the ciphertext
    PrivacyVNextDigest tweakEphemeral;  // fixes the address tweak; disclosable
    std::vector<unsigned char> vchRecipientCiphertext;
    std::vector<unsigned char> vchOutgoingCiphertext;

    PrivacyVNextEncryptedOutput() : nOutputIndex(0)
    {
        noteEphemeral.fill(0);
        tweakEphemeral.fill(0);
    }
};

// Encrypt one output to a recipient address.
//
// `y` and `mask` are the note's openings; the caller keeps them to spend the note later.
// The leaf's I point is derived from the note's own O and never supplied. The two
// ephemeral secrets must be independently drawn and distinct: only the tweak one is ever
// opened by a disclosure.
bool EncryptPrivacyVNextNote(
    uint8_t nNetwork,
    uint8_t nAddressType,
    uint32_t nOutputIndex,
    const PrivacyVNextDigest& genesis,
    const PrivacyVNextDigest& recipientSpend,
    const PrivacyVNextDigest& recipientView,
    const PrivacyVNextDigest& outgoingSecret,
    const PrivacyVNextDigest& noteEphemeralSecret,
    const PrivacyVNextDigest& tweakEphemeralSecret,
    uint64_t nAmount,
    const PrivacyVNextDigest& y,
    const PrivacyVNextDigest& mask,
    PrivacyVNextEncryptedOutput& noteOut,
    std::string& error);

// What proving one input yields, beyond the shared proof itself.
struct PrivacyVNextSpendConstruction
{
    PrivacyVNextDigest pseudoOut;
    PrivacyVNextDigest keyImage;
    PrivacyVNextDigest pseudoOutMaskDelta;   // caller-secret; added to the note mask
    PrivacyVNextDigest senderAuthority;
    std::vector<unsigned char> vchSenderDisclosureProof;

    PrivacyVNextSpendConstruction()
    {
        pseudoOut.fill(0);
        keyImage.fill(0);
        pseudoOutMaskDelta.fill(0);
        senderAuthority.fill(0);
    }

    void Clear();
    ~PrivacyVNextSpendConstruction() { Clear(); }
};

// One input's secrets and its membership witness record.
struct PrivacyVNextSpendInput
{
    PrivacyVNextDigest spendScalar;          // x
    PrivacyVNextDigest commitmentScalar;     // y
    PrivacyVNextOutputLeaf leaf;
    std::vector<unsigned char> vchWitnessRecord;  // from the witness builder, spliced verbatim

    void Clear();
    ~PrivacyVNextSpendInput() { Clear(); }
};

// Hash a serialized payload prefix so the proofs a builder makes bind to the value
// validation will recompute. The prefix runs through the finality body and stops before
// the first proof section.
bool HashPrivacyVNextPayloadPrefix(
    uint32_t nWireVersion,
    const std::vector<unsigned char>& vchPrefix,
    PrivacyVNextDigest& hashOut,
    std::string& error);

// Exact upstream proof size for a given input count at the fixed layer depth.
bool GetPrivacyVNextProofSize(uint32_t nInputs, size_t& nSizeOut, std::string& error);

// Prove membership for every input against one finalized root.
bool ProvePrivacyVNextMembership(
    const PrivacyVNextDigest& finalizedRoot,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    const std::vector<PrivacyVNextSpendInput>& inputs,
    std::vector<PrivacyVNextSpendConstruction>& constructions,
    std::vector<unsigned char>& vchProof,
    std::string& error);

// Builds one witness per target from sibling paths a caller read out of a tree store.
// The request carries only the paths, so this serves any tree the layout allows.
bool BuildPrivacyVNextWitnessesFromPaths(
    const std::vector<unsigned char>& treeState,
    const std::vector<uint64_t>& vTargetLeafIndexes,
    const std::vector<unsigned char>& vchPaths,
    std::vector<PrivacyVNextMembershipWitness>& witnesses,
    PrivacyVNextDigest& treeRoot,
    std::string& error);

// Builds one witness per target against the supplied tree. The whole leaf set
// travels in one request, so the request bound caps the tree this can serve far
// below the structural maximum; a larger tree needs the path-carrying mode.
bool BuildPrivacyVNextWitnesses(
    const std::vector<unsigned char>& treeState,
    const std::vector<PrivacyVNextOutputLeaf>& leaves,
    const std::vector<uint64_t>& vTargetLeafIndexes,
    std::vector<PrivacyVNextMembershipWitness>& witnesses,
    PrivacyVNextDigest& treeRoot,
    std::string& error);

// Range, balance and binding proofs over one transaction's value flow. The Rust
// side verifies each before returning, so a success means the proofs check.
bool ProvePrivacyVNextValue(
    const std::vector<PrivacyVNextDigest>& vPseudoOuts,
    const std::vector<PrivacyVNextValueOutput>& vOutputs,
    int64_t nTransparentValueBalance,
    uint64_t nFee,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    const PrivacyVNextDigest& excessMask,
    PrivacyVNextValueProof& proof,
    std::string& error);

// Prove that a disclosed recipient address is the address one output actually pays.
//
// Proving membership already yields each input's sender disclosure, so only the receiver
// side needs a call of its own. The Rust side verifies the proof before returning, so a
// success means it checks against the same signing hash consensus will recompute.
// Prove one commitment opens to a fixed amount without publishing its opening.
//
// The commitment must be the re-randomized one from the same proving instance: a proof run
// against a leaf commitment names the leaf the membership proof exists to hide.
bool ProvePrivacyVNextAmountEquality(
    const PrivacyVNextDigest& commitment,
    uint64_t nAmount,
    const PrivacyVNextDigest& mask,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    std::vector<unsigned char>& vchProofOut,
    std::string& error);

bool ProvePrivacyVNextReceiverDisclosure(
    uint32_t nOutputIndex,
    const PrivacyVNextDigest& recipientSpend,
    const PrivacyVNextDigest& recipientView,
    const PrivacyVNextDigest& outputOwner,
    const PrivacyVNextDigest& tweakEphemeralPublic,
    const PrivacyVNextDigest& tweakEphemeralSecret,
    const PrivacyVNextDigest& outputY,
    const PrivacyVNextDigest& signableHash,
    const PrivacyVNextDigest& entropy,
    std::vector<unsigned char>& vchProofOut,
    std::string& error);

// One note-vote membership instance plus the witnesses its sigma is built from. The two
// scalars are secret construction material: zeroize them once the vote and share exist.
struct PrivacyVNextVoteMembership
{
    PrivacyVNextDigest oTilde;
    PrivacyVNextDigest cTilde;
    PrivacyVNextDigest rerandomizedY;
    PrivacyVNextDigest maskDelta;
    std::vector<unsigned char> vchRequest;

    PrivacyVNextVoteMembership();
};

bool ProvePrivacyVNextVoteMembership(
    const PrivacyVNextDigest& finalizedRoot,
    const PrivacyVNextDigest& entropy,
    const PrivacyVNextSpendInput& input,
    PrivacyVNextVoteMembership& membershipOut,
    std::string& error);

bool VerifyPrivacyVNextVoteMembership(
    const std::vector<unsigned char>& vchRequest,
    std::string& error);

// Prove the note-vote authorization sigma. `binding` is the caller's digest over every
// consensus field the vote must not be detachable from; the membership proof binds none.
bool ProvePrivacyVNextVoteSigma(
    uint64_t nEpoch,
    const PrivacyVNextDigest& oTilde,
    const PrivacyVNextDigest& cTilde,
    const PrivacyVNextDigest& binding,
    const PrivacyVNextDigest& x,
    const PrivacyVNextDigest& rerandomizedY,
    const PrivacyVNextDigest& entropy,
    PrivacyVNextDigest& tagOut,
    std::vector<unsigned char>& vchProofOut,
    std::string& error);

bool VerifyPrivacyVNextVoteSigma(
    uint64_t nEpoch,
    const PrivacyVNextDigest& oTilde,
    const PrivacyVNextDigest& cTilde,
    const PrivacyVNextDigest& binding,
    const PrivacyVNextDigest& tag,
    const std::vector<unsigned char>& vchProof,
    std::string& error);

// One term of an ed25519 linear combination. A generator term must leave `point` zero.
enum PrivacyVNextCombineSource
{
    PRIVACY_VNEXT_TERM_SUPPLIED = 0,
    PRIVACY_VNEXT_TERM_MONERO_H = 1,
    PRIVACY_VNEXT_TERM_ED25519_G = 2
};

struct PrivacyVNextCombineTerm
{
    uint8_t nSource;
    PrivacyVNextDigest scalar;
    PrivacyVNextDigest point;

    PrivacyVNextCombineTerm();
};

// Sum scalar*point over the terms. Chains internally, so any term count is accepted.
// The identity is a legal result and is what an empty term list produces.
bool CombinePrivacyVNextPoints(
    const std::vector<PrivacyVNextCombineTerm>& vTerms,
    PrivacyVNextDigest& pointOut,
    std::string& error);

// Range-prove one opening. `commitmentOut` is the point the proof is over, so a caller can
// require it to equal the point it derived for itself.
bool ProvePrivacyVNextRange(
    uint64_t nAmount,
    const PrivacyVNextDigest& mask,
    const PrivacyVNextDigest& entropy,
    PrivacyVNextDigest& commitmentOut,
    std::vector<unsigned char>& vchProofOut,
    std::string& error);

// Verify a range proof over a point the caller derived. Never pass a supplied point.
bool VerifyPrivacyVNextRange(
    const PrivacyVNextDigest& commitment,
    const PrivacyVNextDigest& signableHash,
    const std::vector<unsigned char>& vchProof,
    std::string& error);

#endif // INN_PRIVACY_VNEXT_FFI_H
