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
