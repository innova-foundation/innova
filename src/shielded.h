// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_SHIELDED_H
#define INN_SHIELDED_H

#include "uint256.h"
#include "serialize.h"
#include "hash.h"
#include "zkproof.h"
#include "curvetree.h"
#include "lelantus.h"
#include "privacy_vnext/iv5_protocol.h"

#include <vector>
#include <string>
#include <stdint.h>
#include <openssl/crypto.h>
#include <boost/thread/once.hpp>

// Prototype envelopes 2000-2002, superseded by 2008. Each extends the one
// before it, so 2003-2007 still serialize their fields and the constants stay.
// Never activated on a public network; rejected off regtest.
static const int SHIELDED_TX_VERSION = 2000;

// The first disclosure mask: a 3-bit nPrivacyMode plus per-spend and per-output
// plaintext value/blind. 2008 carries the production form.
static const int SHIELDED_TX_VERSION_DSP_PROTOTYPE = 2001;

// Threshold at which a spend must prove tree membership (IsFCMP()), backed by
// the in-tree curve tree that vendored FCMP++ replaces.
static const int SHIELDED_TX_VERSION_FCMP = 2002;

static const int SHIELDED_TX_VERSION_NULLSTAKE = 2003;

static const int SHIELDED_TX_VERSION_NULLSTAKE_V2 = 2004;

static const int SHIELDED_TX_VERSION_NULLSTAKE_COLD = 2005;

// B2-e Phase 3c: a shielded send that may mint M-of-N cold-stake notes. Its outputs may carry the
// M-of-N mint extension (a cv3 leaf + a fresh value commitment Vv + an Okamoto (G,J) link), so the
// delegation set stays hidden at mint while the value is range-proven over Vv.
static const int SHIELDED_TX_VERSION_MOFN_MINT = 2006;

// B2-e Phase 3c.4: an OWNER-OVERRIDE RECLAIM of an idle M-of-N cold-stake note. The owner reveals the
// staker set + M + owner pubkey (recomputed to the note's delegation hash D), proves control of the
// owner key (the mandatory spend-auth sig with rk == ownerPubKey), and spends the cv3 note via the
// cv_plain carve-out -- but ONLY after the note has been staking-inactive for the reclaim timelock.
static const int SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM = 2007;

// Dynamic Selective Privacy: the sole production shielded envelope. A self-describing
// payload declares its operation and 3-bit disclosure mask in a fixed header (see
// privacy_vnext/iv5_protocol.h); membership is proven by vendored FCMP++.
static const int SHIELDED_TX_VERSION_DSP = 2008;
static const size_t SHIELDED_VNEXT_MAX_PAYLOAD_SIZE = 256 * 1024;

// Regtest rehearsal switch (-regtestiv5rehearsal), kept for the regtest-only
// bookkeeping it drives. Never settable off regtest.
extern bool fRegtestShieldedVNextRehearsal;

// The v2008 implementation is linked and CONSENSUS_CAPABILITIES == IMPLEMENTED_CAPABILITIES
// (checked by the FFI handshake at startup). This does not open the pool: every consensus
// site also requires IsBoundaryBActiveAtHeight.
inline bool IsShieldedVNextConsensusReady()
{
    return true;
}

// Regtest-only hold on wallet leaf-index assignment (-regtestiv5holdleafindex), to reach
// the unplaced-notes state a restart leaves behind. Wallet-side only; no consensus rule
// reads it.
extern bool fRegtestHoldPrivacyVNextLeafIndex;

inline bool IsPrivacyVNextLeafIndexAssignmentHeld()
{
    extern bool fRegTest;
    return fRegTest && fRegtestHoldPrivacyVNextLeafIndex;
}

/** vNext privacy envelope after the common tx header:
 *    0xff || "IV5P" || uint16_le(schema=1) || CompactSize(length) || payload
 *  The marker keeps it disjoint from older vectors; the bound is checked before allocation. */
class CShieldedVNextEnvelope
{
public:
    uint16_t nSchema;
    std::vector<unsigned char> vchPayload;
    bool fPresent;

    CShieldedVNextEnvelope()
    {
        SetNull();
    }

    void SetNull()
    {
        nSchema = static_cast<uint16_t>(iv5::PROTOCOL_SCHEMA);
        vchPayload.clear();
        fPresent = false;
    }

    bool IsNull() const
    {
        return !IsPresent();
    }

    bool IsPresent() const
    {
        return fPresent || !vchPayload.empty();
    }

    void SetPresent()
    {
        fPresent = true;
    }

    template<typename Stream>
    unsigned int UnserializeAfterMarkerPrefix(Stream& s, int nType,
                                              int nVersion,
                                              CSerActionUnserialize)
    {
        unsigned char markerSuffix[4];
        s.read(reinterpret_cast<char*>(markerSuffix), sizeof(markerSuffix));
        if (markerSuffix[0] != 'I' || markerSuffix[1] != 'V' ||
            markerSuffix[2] != '5' || markerSuffix[3] != 'P')
            throw std::ios_base::failure("non-canonical IV5 privacy marker");

        ::Unserialize(s, nSchema, nType, nVersion);
        if (nSchema != static_cast<uint16_t>(iv5::PROTOCOL_SCHEMA))
            throw std::ios_base::failure("unsupported IV5 privacy envelope schema");

        const uint64_t nPayloadSize = ReadCompactSize(s);
        if (nPayloadSize > SHIELDED_VNEXT_MAX_PAYLOAD_SIZE)
            throw std::ios_base::failure("IV5 privacy payload exceeds consensus limit");
        vchPayload.resize(static_cast<size_t>(nPayloadSize));
        if (nPayloadSize != 0)
            s.read(reinterpret_cast<char*>(&vchPayload[0]),
                   static_cast<int>(nPayloadSize));
        fPresent = true;
        return 4 + sizeof(nSchema) + GetSizeOfCompactSize(nPayloadSize) +
               static_cast<unsigned int>(nPayloadSize);
    }

    template<typename Stream, typename Operation>
    unsigned int UnserializeAfterMarkerPrefix(Stream&, int, int, Operation)
    {
        return 0;
    }

    IMPLEMENT_SERIALIZE
    (
        CShieldedVNextEnvelope* pthis =
            const_cast<CShieldedVNextEnvelope*>(this);
        unsigned char marker[5];
        marker[0] = 0xff;
        marker[1] = 'I';
        marker[2] = 'V';
        marker[3] = '5';
        marker[4] = 'P';
        READWRITE(FLATDATA(marker));
        if (fRead &&
            (marker[0] != 0xff || marker[1] != 'I' || marker[2] != 'V' ||
             marker[3] != '5' || marker[4] != 'P'))
            throw std::ios_base::failure("non-canonical IV5 privacy marker");

        READWRITE(nSchema);
        if (nSchema != static_cast<uint16_t>(iv5::PROTOCOL_SCHEMA))
            throw std::ios_base::failure("unsupported IV5 privacy envelope schema");

        nSerSize += ::SerReadWriteLimitedVector(
            s, vchPayload, SHIELDED_VNEXT_MAX_PAYLOAD_SIZE,
            nType, nVersion, ser_action);
        if (fRead)
            pthis->fPresent = true;
    )
};

inline bool IsLegacyShieldedTransactionVersion(int nVersion)
{
    return nVersion >= SHIELDED_TX_VERSION &&
           nVersion <= SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM;
}

// Boundary-B product contract.  These operation identifiers are independent
// from the three-bit disclosure mask below: a transfer or NullSend may select
// any applicable privacy combination without changing its operation type.
enum ShieldedVNextOperation
{
    SHIELDED_VNEXT_OPERATION_SHIELD = iv5::NOTE_SHIELD,
    SHIELDED_VNEXT_OPERATION_UNSHIELD = iv5::NOTE_UNSHIELD,
    SHIELDED_VNEXT_OPERATION_TRANSFER = iv5::NOTE_TRANSFER,
    SHIELDED_VNEXT_OPERATION_NULLSEND = iv5::NOTE_NULLSEND,
    SHIELDED_VNEXT_OPERATION_DELEGATION_CREATE = iv5::NOTE_DELEGATION_CREATE,
    SHIELDED_VNEXT_OPERATION_M_OF_N_MINT = iv5::NOTE_M_OF_N_MINT,
    SHIELDED_VNEXT_OPERATION_RECLAIM = iv5::NOTE_RECLAIM,
    SHIELDED_VNEXT_OPERATION_CONDITIONAL_MIGRATION = iv5::NOTE_CONDITIONAL_MIGRATION,
    SHIELDED_VNEXT_OPERATION_COLLATERAL_REGISTER = iv5::NOTE_COLLATERAL_REGISTER,
    SHIELDED_VNEXT_OPERATION_FINALITY_MEMBER_REGISTER =
        iv5::NOTE_FINALITY_MEMBER_REGISTER,
    SHIELDED_VNEXT_OPERATION_NONE = iv5::NOTE_OPERATION_NONE
};

// All three private-staking generations remain mandatory.  After IDAG they
// authorize finalized-epoch votes; they do not mint PoS blocks in the DAG.
enum ShieldedVNextNullStakeGeneration
{
    SHIELDED_VNEXT_NULLSTAKE_V1 = iv5::FINALITY_NULLSTAKE_V1,
    SHIELDED_VNEXT_NULLSTAKE_V2 = iv5::FINALITY_NULLSTAKE_V2,
    SHIELDED_VNEXT_NULLSTAKE_V3 = iv5::FINALITY_NULLSTAKE_V3
};

static const int SHIELDED_MERKLE_DEPTH = 32;

static const int MIN_SHIELDED_SPEND_DEPTH = 10;

static const int64_t MIN_TX_FEE_SHIELDED = 100000;

static const int MAX_SHIELDED_INPUTS = 16;
static const int MAX_SHIELDED_OUTPUTS = 16;

static const uint8_t PRIVACY_HIDE_SENDER    = iv5::DISCLOSURE_HIDE_SENDER;
static const uint8_t PRIVACY_HIDE_RECEIVER   = iv5::DISCLOSURE_HIDE_RECEIVER;
static const uint8_t PRIVACY_HIDE_AMOUNT     = iv5::DISCLOSURE_HIDE_AMOUNT;
static const uint8_t PRIVACY_MODE_MASK       = iv5::DISCLOSURE_MASK;
static const uint8_t PRIVACY_MODE_TRANSPARENT = 0x00;
static const uint8_t PRIVACY_MODE_FULL       = iv5::WALLET_DEFAULT_DISCLOSURE_MASK;
static const uint8_t SHIELDED_VNEXT_PRIVACY_MODE_COUNT = 8;
static const uint8_t SHIELDED_VNEXT_NULLSTAKE_GENERATION_COUNT = 3;
static const uint8_t SHIELDED_VNEXT_TREE_LAYERS = 8;

inline bool DSP_HideSender(uint8_t mode)   { return (mode & PRIVACY_HIDE_SENDER) != 0; }
inline bool DSP_HideReceiver(uint8_t mode) { return (mode & PRIVACY_HIDE_RECEIVER) != 0; }
inline bool DSP_HideAmount(uint8_t mode)   { return (mode & PRIVACY_HIDE_AMOUNT) != 0; }

static const size_t SHIELDED_DIVERSIFIER_SIZE = 11;
static const size_t SHIELDED_PKD_SIZE = 33;
static const size_t SHIELDED_PROOF_SIZE = 672;
static const size_t SHIELDED_EPHEMERAL_KEY_SIZE = 33;
static const size_t SHIELDED_ENC_CIPHERTEXT_SIZE = 580;
// The legacy sender-recovery plaintext is 54 bytes. ChaCha20-Poly1305 adds a
// 12-byte nonce and 16-byte tag, so every producer in versions 2000--2007 has
// always emitted 82 bytes.  The old value of 80 described no real wire object.
static const size_t SHIELDED_OUT_CIPHERTEXT_SIZE = 82;
static const size_t SHIELDED_BINDING_SIG_SIZE = 65;
// Read-side allocation caps for the vectors embedded directly in a shielded
// spend.  Serialization remains the ordinary vector encoding.
static const size_t SHIELDED_SPEND_AUTH_KEY_MAX_SIZE = 65;
static const size_t SHIELDED_SPEND_AUTH_SIG_SIZE = 65;
// Fields without a tighter shape check are bounded by the 1 MB transaction ceiling
// CheckTransaction enforces, avoiding MAX_VECTOR_SIZE-scale allocations.
static const size_t SHIELDED_TX_FIELD_MAX_WIRE_SIZE = 1000000;


class CShieldedSpendingKey
{
public:
    uint256 skSpend;
    uint256 skPrf;
    uint256 ovk;

    CShieldedSpendingKey()
    {
        skSpend = 0;
        skPrf = 0;
        ovk = 0;
    }

    ~CShieldedSpendingKey()
    {
        OPENSSL_cleanse(skSpend.begin(), 32);
        OPENSSL_cleanse(skPrf.begin(), 32);
        OPENSSL_cleanse(ovk.begin(), 32);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(skSpend);
        READWRITE(skPrf);
        READWRITE(ovk);
    )

    bool IsNull() const { return skSpend == 0; }
};

class CShieldedFullViewingKey
{
public:
    std::vector<unsigned char> vchAk;
    uint256 nk;
    uint256 ovk;

    CShieldedFullViewingKey()
    {
        nk = 0;
        ovk = 0;
    }

    ~CShieldedFullViewingKey()
    {
        if (!vchAk.empty())
            OPENSSL_cleanse(vchAk.data(), vchAk.size());
        OPENSSL_cleanse(nk.begin(), 32);
        OPENSSL_cleanse(ovk.begin(), 32);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchAk);
        READWRITE(nk);
        READWRITE(ovk);
    )
};

class CShieldedIncomingViewingKey
{
public:
    uint256 ivk;

    CShieldedIncomingViewingKey()
    {
        ivk = 0;
    }

    ~CShieldedIncomingViewingKey()
    {
        OPENSSL_cleanse(ivk.begin(), 32);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(ivk);
    )

    bool IsNull() const { return ivk == 0; }
};

class CShieldedPaymentAddress
{
public:
    std::vector<unsigned char> vchDiversifier;
    std::vector<unsigned char> vchPkD;

    CShieldedPaymentAddress()
    {
        vchDiversifier.resize(SHIELDED_DIVERSIFIER_SIZE, 0);
        vchPkD.resize(SHIELDED_PKD_SIZE, 0);
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchDiversifier);
        READWRITE(vchPkD);
    )

    bool IsNull() const
    {
        for (size_t i = 0; i < vchPkD.size(); i++)
            if (vchPkD[i] != 0) return false;
        return true;
    }

    bool operator==(const CShieldedPaymentAddress& other) const
    {
        return vchDiversifier == other.vchDiversifier && vchPkD == other.vchPkD;
    }

    bool operator<(const CShieldedPaymentAddress& other) const
    {
        if (vchDiversifier != other.vchDiversifier)
            return vchDiversifier < other.vchDiversifier;
        return vchPkD < other.vchPkD;
    }
};


class CShieldedNote
{
public:
    CShieldedPaymentAddress addr;
    int64_t nValue;
    uint256 rho;
    uint256 rcm;
    std::vector<unsigned char> vchBlind;

    CShieldedNote()
    {
        nValue = 0;
        rho = 0;
        rcm = 0;
    }

    ~CShieldedNote()
    {
        OPENSSL_cleanse(rho.begin(), 32);
        OPENSSL_cleanse(rcm.begin(), 32);
        if (!vchBlind.empty())
            OPENSSL_cleanse(vchBlind.data(), vchBlind.size());
        nValue = 0;
    }

    uint256 GetCommitment() const;

    bool GetPedersenCommitment(CPedersenCommitment& commitOut) const;

    uint256 GetNullifier(const uint256& nk) const;

    bool GenerateBlindingFactor();

    IMPLEMENT_SERIALIZE
    (
        READWRITE(addr);
        READWRITE(nValue);
        READWRITE(rho);
        READWRITE(rcm);
        READWRITE(vchBlind);
    )
};

enum ShieldedRecipientPayloadKind
{
    SHIELDED_RECIPIENT_NONE = 0,
    SHIELDED_RECIPIENT_LEGACY_NOTE,
    SHIELDED_RECIPIENT_ADDRESS
};

// Decode the public-recipient payload by exact canonical shape: early DSP producers stored
// a complete note, later ones only the address, under the same tx versions. Future
// versions never inherit this format.
bool DecodeShieldedRecipientPayload(
    int nTxVersion,
    const std::vector<unsigned char>& vchPayload,
    ShieldedRecipientPayloadKind& kindOut,
    CShieldedPaymentAddress& addressOut,
    CShieldedNote& noteOut);


class CShieldedSpendDescription
{
public:
    CPedersenCommitment cv;
    uint256 anchor;
    uint256 nullifier;
    std::vector<unsigned char> vchRk;
    CBulletproofRangeProof rangeProof;
    std::vector<unsigned char> vchSpendAuthSig;
    std::vector<unsigned char> vchLelantusProof;
    std::vector<CPedersenCommitment> vAnonSet;
    uint256 lelantusSerial;

    int64_t nPlaintextValue;
    std::vector<unsigned char> vchPlaintextBlind;

    CFCMPProof fcmpProof;
    uint256 curveTreeRoot;

    // Nullifier binding (post FORK_HEIGHT_NULLIFIER_BINDING): NF=r*G_nf and a
    // proof tying it to cv, so nullifier==NullifierTagFromPoint(vchNullifierPoint).
    std::vector<unsigned char> vchNullifierPoint;        // 33-byte compressed NF
    std::vector<unsigned char> vchNullifierBindingProof; // NULLIFIER_BINDING_PROOF_SIZE

    CShieldedSpendDescription()
    {
        anchor = 0;
        nullifier = 0;
        lelantusSerial = 0;
        nPlaintextValue = -1;
        curveTreeRoot = 0;
    }

    bool HasFCMPProof() const { return !fcmpProof.IsNull(); }
    bool HasNullifierBinding() const
    {
        return !vchNullifierPoint.empty() && !vchNullifierBindingProof.empty();
    }

    IMPLEMENT_SERIALIZE
    (
        CShieldedSpendDescription* pthis = const_cast<CShieldedSpendDescription*>(this);
        READWRITE(cv);
        READWRITE(anchor);
        READWRITE(nullifier);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchRk,
                                                 SHIELDED_SPEND_AUTH_KEY_MAX_SIZE,
                                                 nType, nVersion, ser_action);
        READWRITE(rangeProof);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchSpendAuthSig,
                                                 SHIELDED_SPEND_AUTH_SIG_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchLelantusProof,
                                                 SHIELDED_TX_FIELD_MAX_WIRE_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vAnonSet,
                                                 LELANTUS_MAX_SET_SIZE,
                                                 nType, nVersion, ser_action);
        READWRITE(lelantusSerial);

        unsigned char fHasFCMP = fcmpProof.IsNull() ? 0 : 1;
        READWRITE(fHasFCMP);
        if (fHasFCMP)
        {
            READWRITE(fcmpProof);
            READWRITE(curveTreeRoot);
        }

        unsigned char fHasNfBind = (vchNullifierPoint.empty() && vchNullifierBindingProof.empty()) ? 0 : 1;
        READWRITE(fHasNfBind);
        if (fHasNfBind)
        {
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchNullifierPoint,
                                                     NULLIFIER_POINT_SIZE,
                                                     nType, nVersion, ser_action);
            nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchNullifierBindingProof,
                                                     NULLIFIER_BINDING_PROOF_SIZE,
                                                     nType, nVersion, ser_action);
        }
    )
};

class CShieldedOutputDescription
{
public:
    CPedersenCommitment cv;
    uint256 cmu;
    std::vector<unsigned char> vchEphemeralKey;
    std::vector<unsigned char> vchEncCiphertext;
    std::vector<unsigned char> vchOutCiphertext;
    CBulletproofRangeProof rangeProof;

    int64_t nPlaintextValue;
    std::vector<unsigned char> vchPlaintextBlind;
    std::vector<unsigned char> vchRecipientScript;

    // B2-e M-of-N cold-stake mint (Phase 3c). nMofNType == 1 marks an output whose curve-tree leaf
    // cv == cv3 = value*H + blind*G + delegationHash*J hides the delegation: the value is bound by a
    // fresh 2-generator value commitment valueCommitmentVv (range-proven) plus vchMofNLink, a 97-byte
    // Okamoto (G,J) proof that (cv - Vv) in <G,J> (same value). Consensus runs the range proof + the
    // binding signature over Vv (NEVER cv); the leaf/tree/FCMP use cv. These fields are NOT in the
    // shared serializer below; they are version-gated in the CTransaction serializer + GetBindingSigHash
    // (like the DSP plaintext fields), so existing shielded versions are byte-for-byte unchanged.
    unsigned char nMofNType;
    CPedersenCommitment valueCommitmentVv;
    std::vector<unsigned char> vchMofNLink;

    CShieldedOutputDescription()
    {
        cmu = 0;
        nPlaintextValue = -1;
        nMofNType = 0;
    }

    bool IsMofNMint() const { return nMofNType == 1; }

    IMPLEMENT_SERIALIZE
    (
        CShieldedOutputDescription* pthis = const_cast<CShieldedOutputDescription*>(this);
        READWRITE(cv);
        READWRITE(cmu);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchEphemeralKey,
                                                 SHIELDED_TX_FIELD_MAX_WIRE_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchEncCiphertext,
                                                 SHIELDED_TX_FIELD_MAX_WIRE_SIZE,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vchOutCiphertext,
                                                 SHIELDED_TX_FIELD_MAX_WIRE_SIZE,
                                                 nType, nVersion, ser_action);
        READWRITE(rangeProof);
    )
};

class CShieldedBindingSig
{
public:
    CBindingSignature bindingSig;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(bindingSig);
    )

    bool IsNull() const { return bindingSig.IsNull(); }
};


class CShieldedNullifierSpent
{
public:
    uint256 txnHash;
    uint32_t nIndex;

    CShieldedNullifierSpent()
    {
        txnHash = 0;
        nIndex = 0;
    }

    CShieldedNullifierSpent(const uint256& txnHashIn, uint32_t nIndexIn)
    {
        txnHash = txnHashIn;
        nIndex = nIndexIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(txnHash);
        READWRITE(nIndex);
    )
};


// One consumed IV5 key image with its consuming block height, for height-bounded queries.
// Separate from CShieldedNullifierSpent, whose pre-IV5 records must stay decodable.
class CPrivacyVNextNullifierSpent
{
public:
    uint256 txnHash;
    uint32_t nIndex;
    int32_t nHeight;

    CPrivacyVNextNullifierSpent()
    {
        txnHash = 0;
        nIndex = 0;
        nHeight = -1;
    }

    CPrivacyVNextNullifierSpent(const uint256& txnHashIn, uint32_t nIndexIn,
                                int32_t nHeightIn)
    {
        txnHash = txnHashIn;
        nIndex = nIndexIn;
        nHeight = nHeightIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(txnHash);
        READWRITE(nIndex);
        READWRITE(nHeight);
    )
};


// One collateral attestation, keyed in txdb on the key image it published.
//
// The context digest is what the attestation bound into its signing hash, so the node
// list can hold an announcement to the identity, endpoint and payout address the chain
// already accepted, without re-reading the registering transaction for every gossip
// message. It carries no value and never reaches the spent-key index.
//
// vchMemberKey is the tally-encryption key a finality-member registration published, and
// is empty for a collateralnode-only attestation. One row for both operations, because
// they compete for one slot: a note is registered once for ever, so the collateral buys
// exactly one service and the key is what says which.
//
// The row gained that field after the operations shipped, so a record written before it
// no longer decodes and reads back as a corrupt index. That is fail-closed and asks for
// the -reindex it needs; both operations are reachable only where Boundary B is set,
// which is regtest alone.
class CPrivacyVNextCollateralAttestation
{
public:
    uint256 txnHash;
    uint256 contextDigest;
    int32_t nHeight;
    std::vector<unsigned char> vchMemberKey;

    CPrivacyVNextCollateralAttestation()
    {
        txnHash = 0;
        contextDigest = 0;
        nHeight = -1;
    }

    CPrivacyVNextCollateralAttestation(const uint256& txnHashIn,
                                       const uint256& contextDigestIn,
                                       int32_t nHeightIn)
    {
        txnHash = txnHashIn;
        contextDigest = contextDigestIn;
        nHeight = nHeightIn;
    }

    CPrivacyVNextCollateralAttestation(
        const uint256& txnHashIn,
        const uint256& contextDigestIn,
        int32_t nHeightIn,
        const std::vector<unsigned char>& vchMemberKeyIn)
    {
        txnHash = txnHashIn;
        contextDigest = contextDigestIn;
        nHeight = nHeightIn;
        vchMemberKey = vchMemberKeyIn;
    }

    // Whether this registration claims a finality-committee seat rather than only
    // proving collateral.
    bool IsFinalityMember() const
    {
        return vchMemberKey.size() == iv5::FINALITY_MEMBER_KEY_BYTES;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(txnHash);
        READWRITE(contextDigest);
        READWRITE(nHeight);
        READWRITE(vchMemberKey);
    )
};


class CIncrementalMerkleTree
{
public:
    std::vector<uint256> vLeft;
    std::vector<uint256> vRight;
    uint64_t nSize;

    CIncrementalMerkleTree()
    {
        nSize = 0;
        vLeft.resize(SHIELDED_MERKLE_DEPTH);
        vRight.resize(SHIELDED_MERKLE_DEPTH);
    }

    bool Append(const uint256& leaf);

    uint256 Root() const;

    bool GetWitness(uint64_t nPosition, std::vector<uint256>& vPathOut) const;

    // Disk snapshots are consensus inputs during connect, disconnect and
    // wallet proof construction.  Reject malformed vector lengths or an
    // impossible leaf count before any indexed access.
    bool IsValidStructure() const;

    uint64_t Size() const { return nSize; }

    IMPLEMENT_SERIALIZE
    (
        CIncrementalMerkleTree* pthis = const_cast<CIncrementalMerkleTree*>(this);
        // A valid tree has exactly SHIELDED_MERKLE_DEPTH slots per frontier vector; reject a
        // malformed length before allocating (IsValidStructure checks shape after decode).
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vLeft,
                                                 SHIELDED_MERKLE_DEPTH,
                                                 nType, nVersion, ser_action);
        nSerSize += ::SerReadWriteLimitedVector(s, pthis->vRight,
                                                 SHIELDED_MERKLE_DEPTH,
                                                 nType, nVersion, ser_action);
        READWRITE(nSize);
    )

    static uint256 HashCombine(int nDepth, const uint256& left, const uint256& right);

    static const uint256& EmptyRoot(int nDepth);

private:
    static std::vector<uint256> vEmptyRoots;
    static bool fEmptyRootsInitialized;
    static boost::once_flag emptyRootsOnceFlag;
    static void InitEmptyRoots();
};


class CShieldedMerkleWitness
{
public:
    uint64_t nPosition;
    std::vector<uint256> vPath;
    uint256 root;

    CShieldedMerkleWitness()
    {
        nPosition = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nPosition);
        READWRITE(vPath);
        READWRITE(root);
    )
};


// Nullifier binding helpers (see shielded.cpp).
bool ApplyShieldedSpendNullifier(CShieldedSpendDescription& spend,
                                 const CShieldedNote& note,
                                 const uint256& nk,
                                 bool fBindingActive);
bool FinalizeShieldedSpendBindings(std::vector<CShieldedSpendDescription>& vSpend,
                                   const std::vector<int64_t>& vValues,
                                   const std::vector<std::vector<unsigned char> >& vBlinds,
                                   const uint256& sighash,
                                   bool fBindingActive);

bool GenerateShieldedSpendingKey(CShieldedSpendingKey& skOut);

bool DeriveShieldedFullViewingKey(const CShieldedSpendingKey& sk, CShieldedFullViewingKey& fvkOut);

bool DeriveShieldedIncomingViewingKey(const CShieldedFullViewingKey& fvk, CShieldedIncomingViewingKey& ivkOut);

bool DeriveShieldedPaymentAddress(const CShieldedIncomingViewingKey& ivk,
                                   const std::vector<unsigned char>& vchDiversifier,
                                   CShieldedPaymentAddress& addrOut);

bool GenerateShieldedDiversifier(std::vector<unsigned char>& vchDiversifierOut);

bool EncryptShieldedNote(const CShieldedNote& note,
                         const CShieldedPaymentAddress& addr,
                         std::vector<unsigned char>& vchEphemeralKeyOut,
                         std::vector<unsigned char>& vchEncCiphertextOut);

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut);

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const std::vector<unsigned char>& vchPkD,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut);

bool DecryptShieldedNote(const std::vector<unsigned char>& vchEncCiphertext,
                         const std::vector<unsigned char>& vchEphemeralKey,
                         const std::vector<unsigned char>& vchPkD,
                         const std::vector<unsigned char>& vchDiversifier,
                         const CShieldedIncomingViewingKey& ivk,
                         CShieldedNote& noteOut);

bool EncryptShieldedNoteForSender(const CShieldedNote& note,
                                   const uint256& ovk,
                                   const uint256& cv,
                                   const uint256& cmu,
                                   const std::vector<unsigned char>& vchEphemeralKey,
                                   std::vector<unsigned char>& vchOutCiphertextOut);

extern int64_t nShieldedPoolValue;


class CColdStakeDelegation
{
public:
    std::vector<unsigned char> vchPkStake;
    std::vector<unsigned char> vchPkOwner;
    std::vector<unsigned char> vchSkStakeEnc;
    int64_t nDelegateAmount;
    uint256 hashOwner;
    CShieldedPaymentAddress ownerAddr;
    uint256 ownerOvk;
    std::vector<unsigned char> vchOwnerSig;

    CColdStakeDelegation()
    {
        nDelegateAmount = 0;
    }

    ~CColdStakeDelegation()
    {
        if (!vchSkStakeEnc.empty())
            OPENSSL_cleanse(vchSkStakeEnc.data(), vchSkStakeEnc.size());
        if (!vchOwnerSig.empty())
            OPENSSL_cleanse(vchOwnerSig.data(), vchOwnerSig.size());
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchPkStake);
        READWRITE(vchPkOwner);
        READWRITE(vchSkStakeEnc);
        READWRITE(nDelegateAmount);
        READWRITE(hashOwner);
        READWRITE(ownerAddr);
        READWRITE(ownerOvk);
        READWRITE(vchOwnerSig);
    )

    bool IsNull() const { return vchPkStake.empty(); }

    uint256 GetDelegationHash() const;

    bool VerifyOwnerSignature(const std::vector<unsigned char>& vchOwnerPubKey) const;
};

// B2-e M-of-N cold-stake delegation a wallet has minted, keyed by delegationHash D = SetHash(set, M, owner).
// Lets note-scanning recognize the wallet's M-of-N notes (leaf cv3 = value*H + blind*G + D*J) and lets the
// finality-vote / owner-reclaim builders reconstruct the staker set + owner. Persisted to walletdb ("mofndeleg").
class CMofNDelegation
{
public:
    uint256 delegationHash;                                   // D = SetHash(set, M, ownerPubKey)
    std::vector<std::vector<unsigned char> > vStakerSet;      // sorted, dedup, 33-byte members
    unsigned int nThresholdM;
    std::vector<unsigned char> vchPkOwner;                    // 33 bytes, = ownerSecretKey*G
    CShieldedPaymentAddress ownerAddr;                        // notes encrypted here for reclaim
    uint256 ownerOvk;

    CMofNDelegation() { nThresholdM = 0; }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(delegationHash);
        READWRITE(vStakerSet);
        READWRITE(nThresholdM);
        READWRITE(vchPkOwner);
        READWRITE(ownerAddr);
        READWRITE(ownerOvk);
    )
};

bool DeriveStakingKey(const uint256& skSpend, uint256& skStakeOut);

bool DeriveStakingPubKey(const uint256& skStake, std::vector<unsigned char>& vchPkStakeOut);


#endif // INN_SHIELDED_H
