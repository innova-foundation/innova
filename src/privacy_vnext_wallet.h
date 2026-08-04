// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license.

#ifndef INN_PRIVACY_VNEXT_WALLET_H
#define INN_PRIVACY_VNEXT_WALLET_H

#include "serialize.h"
#include "uint256.h"

#include <stdint.h>
#include <vector>

static const uint32_t PRIVACY_VNEXT_WALLET_SEED_GENERATION = 1;
static const size_t PRIVACY_VNEXT_WALLET_SEED_CIPHERTEXT_SIZE = 64;

// Wallet-local only. This record is never serialized into transactions,
// blocks, hashes, P2P messages, or consensus state.
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
