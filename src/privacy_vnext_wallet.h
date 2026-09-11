// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_PRIVACY_VNEXT_WALLET_H
#define INN_PRIVACY_VNEXT_WALLET_H

#include "serialize.h"
#include "uint256.h"

#include <stdint.h>
#include <string>
#include <vector>

static const uint32_t PRIVACY_VNEXT_WALLET_SEED_GENERATION = 1;
static const size_t PRIVACY_VNEXT_WALLET_SEED_CIPHERTEXT_SIZE = 64;

// Wallet-local only. This record is never serialized into transactions,
// blocks, hashes, P2P messages, or consensus state.
// Matches the per-proof input bound the IV5 ABI declares.
static const size_t PRIVACY_VNEXT_MAX_SPEND_INPUTS = 16;

// Matches the key-list bound the IV5 scan request declares.
static const uint32_t PRIVACY_VNEXT_MAX_SCAN_KEYS = 1024;

// Base of the self-pay derivation range (change and shield receivers). Allocation refuses
// at PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES, so this range is never handed out.
static const uint32_t PRIVACY_VNEXT_INTERNAL_CHANGE_BASE = 0x80000000U;

// The one index self-pay used before rotation. Every scan still derives it, so a note
// this wallet paid itself under the old scheme stays findable and spendable.
static const uint32_t PRIVACY_VNEXT_INTERNAL_CHANGE_INDEX =
    PRIVACY_VNEXT_INTERNAL_CHANGE_BASE;

// Issuable indices: the scan budget less the two self-pay slots a scan carries -- the
// legacy index above, and the rotated index the payload under scan names. The scan ABI
// refuses a longer list.
static const uint32_t PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES =
    PRIVACY_VNEXT_MAX_SCAN_KEYS - 2;

// Indices a scan derives above the issued count, so a restored wallet finds notes paid to
// higher indices. A hit raises the issued count and slides the window; discovery fails
// only across a run of more than this many unused indices.
static const uint32_t PRIVACY_VNEXT_SCAN_LOOKAHEAD = 64;

static_assert(PRIVACY_VNEXT_MAX_SCAN_KEYS <= PRIVACY_VNEXT_INTERNAL_CHANGE_BASE,
              "IV5 self-pay must derive outside every issuable address index");
static_assert((size_t)PRIVACY_VNEXT_MAX_ISSUED_ADDRESSES + 2 <=
                  (size_t)PRIVACY_VNEXT_MAX_SCAN_KEYS,
              "an IV5 scan must carry every issued index and both self-pay keys");

// One IV5 output this wallet owns. Every secret here derives from the wallet
// seed, so the note carries them rather than re-deriving on every spend.
struct CPrivacyVNextWalletNote
{
    uint256 txhash;
    uint32_t nOutputIndex;
    int nHeight;
    bool fSpent;
    bool fLeafIndexKnown;
    uint64_t nAmount;
    uint64_t nLeafIndex;
    std::vector<unsigned char> vchOwner;
    std::vector<unsigned char> vchNullifierBase;
    std::vector<unsigned char> vchCommitment;
    std::vector<unsigned char> vchSpendSecret;
    std::vector<unsigned char> vchY;
    std::vector<unsigned char> vchMask;
    std::vector<unsigned char> vchKeyImage;

    CPrivacyVNextWalletNote()
        : nOutputIndex(0), nHeight(0), fSpent(false), fLeafIndexKnown(false),
          nAmount(0), nLeafIndex(0) {}

    bool IsComplete() const
    {
        return vchOwner.size() == 32 && vchNullifierBase.size() == 32 &&
               vchCommitment.size() == 32 && vchSpendSecret.size() == 32 &&
               vchY.size() == 32 && vchMask.size() == 32 &&
               vchKeyImage.size() == 32;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(txhash);
        READWRITE(nOutputIndex);
        READWRITE(nHeight);
        READWRITE(fSpent);
        READWRITE(fLeafIndexKnown);
        READWRITE(nAmount);
        READWRITE(nLeafIndex);
        READWRITE(vchOwner);
        READWRITE(vchNullifierBase);
        READWRITE(vchCommitment);
        READWRITE(vchSpendSecret);
        READWRITE(vchY);
        READWRITE(vchMask);
        READWRITE(vchKeyImage);
    )
};

// How a candidate collateral note came to exist, best first, ranked by what its funding
// tx made public. A shield ties collateral to identified coins, so it is last and never
// chosen by default.
enum PrivacyVNextNoteProvenance
{
    IV5_NOTE_SELF_TRANSFER = 0,
    IV5_NOTE_RECEIVED_TRANSFER = 1,
    IV5_NOTE_DISCLOSED_TRANSFER = 2,
    IV5_NOTE_PROVENANCE_UNKNOWN = 3,
    IV5_NOTE_SHIELD_FUNDED = 4
};

struct CPrivacyVNextCollateralCandidate
{
    CPrivacyVNextWalletNote note;
    uint256 keyImage;
    int nProvenance;
    int nAgeBlocks;

    CPrivacyVNextCollateralCandidate()
        : keyImage(0), nProvenance(IV5_NOTE_PROVENANCE_UNKNOWN), nAgeBlocks(0) {}
};

// Provenance dominates age. Oldest first within a class (weakens timing correlation),
// then (txhash, index) so a dry run and the following register pick the same note.
inline bool PrivacyVNextCollateralCandidateBetter(
    const CPrivacyVNextCollateralCandidate& a,
    const CPrivacyVNextCollateralCandidate& b)
{
    if (a.nProvenance != b.nProvenance)
        return a.nProvenance < b.nProvenance;
    if (a.note.nHeight != b.note.nHeight)
        return a.note.nHeight < b.note.nHeight;
    if (a.note.txhash != b.note.txhash)
        return a.note.txhash < b.note.txhash;
    return a.note.nOutputIndex < b.note.nOutputIndex;
}

// A collateral attestation this wallet published or is about to. Persisted so the note is
// never picked for an ordinary spend, which would permanently retire its key image for
// registration.
class CPrivacyVNextCollateralRegistration
{
public:
    uint256 keyImage;
    uint256 fundingTxHash;
    uint32_t nFundingOutputIndex;
    // Zero until the attestation is built; set once, at broadcast.
    uint256 attestationTxHash;
    // The digest the payload bound. Nothing may change the tuple behind it for this key
    // image, so it is kept alongside its components to detect later config drift.
    uint256 hashContext;
    std::vector<unsigned char> vchCollateralPubKey;
    // Wallet key the announcement is signed with, and today's transparent payee.
    uint160 announceKeyId;
    std::string strAddr;
    std::string strPoolPayout;
    int64_t nTimeCreated;

    CPrivacyVNextCollateralRegistration()
    {
        SetNull();
    }

    void SetNull()
    {
        keyImage = 0;
        fundingTxHash = 0;
        nFundingOutputIndex = 0;
        attestationTxHash = 0;
        hashContext = 0;
        vchCollateralPubKey.clear();
        announceKeyId = 0;
        strAddr.clear();
        strPoolPayout.clear();
        nTimeCreated = 0;
    }

    bool IsValid() const
    {
        return keyImage != 0 && !strAddr.empty() &&
               strPoolPayout.size() <= 128 && !vchCollateralPubKey.empty() &&
               vchCollateralPubKey.size() <= 65;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(keyImage);
        READWRITE(fundingTxHash);
        READWRITE(nFundingOutputIndex);
        READWRITE(attestationTxHash);
        READWRITE(hashContext);
        READWRITE(vchCollateralPubKey);
        READWRITE(announceKeyId);
        READWRITE(strAddr);
        READWRITE(strPoolPayout);
        READWRITE(nTimeCreated);
    )
};

// The transparent side's recovery-phrase chain. Holds no secret (keys derive from the
// shielded seed), only the path and per-chain issue counts. nExternalCount and
// nInternalCount are the NEXT index to issue; a restore raises them by discovery.
class CHDChainRecord
{
public:
    // constexpr, so taking a reference to it does not need an out-of-line definition.
    static constexpr int CURRENT_VERSION = 1;
    int nVersion;
    uint32_t nCoinType;        // the SLIP-0044 slot this chain was derived under
    uint32_t nAccount;         // the BIP-0044 account level, zero today
    uint32_t nExternalCount;   // next receive index
    uint32_t nInternalCount;   // next change index
    int64_t nCreateTime;       // when the phrase was adopted, a rescan floor

    CHDChainRecord()
    {
        SetNull();
    }

    void SetNull()
    {
        nVersion = CURRENT_VERSION;
        nCoinType = 0;
        nAccount = 0;
        nExternalCount = 0;
        nInternalCount = 0;
        nCreateTime = 0;
    }

    bool IsPresent() const { return nCreateTime != 0; }

    IMPLEMENT_SERIALIZE
    (
        CHDChainRecord* pthis = const_cast<CHDChainRecord*>(this);
        READWRITE(pthis->nVersion);
        READWRITE(pthis->nCoinType);
        READWRITE(pthis->nAccount);
        READWRITE(pthis->nExternalCount);
        READWRITE(pthis->nInternalCount);
        READWRITE(pthis->nCreateTime);
    )
};

class CPrivacyVNextSeedRecord
{
public:
    uint32_t nGeneration;
    std::vector<unsigned char> vchCryptedSeed;
    uint256 hashSeedCommitment;
    uint32_t nNextAddressIndex;

    CPrivacyVNextSeedRecord()
    {
        SetNull();
    }

    void SetNull()
    {
        nGeneration = 0;
        vchCryptedSeed.clear();
        hashSeedCommitment = 0;
        nNextAddressIndex = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nGeneration);
        nSerSize += ::SerReadWriteLimitedVector(
            s, vchCryptedSeed,
            PRIVACY_VNEXT_WALLET_SEED_CIPHERTEXT_SIZE,
            nType, nVersion, ser_action);
        READWRITE(hashSeedCommitment);
        READWRITE(nNextAddressIndex);
    )
};

#endif // INN_PRIVACY_VNEXT_WALLET_H
