// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef INN_LELANTUS_H
#define INN_LELANTUS_H

#include "uint256.h"
#include "serialize.h"
#include "zkproof.h"

#include <vector>
#include <stdint.h>

static const int LELANTUS_SET_SIZE = 64;
static const int LELANTUS_SET_SIZE_LOG = 6;
static const int LELANTUS_MAX_SPEND_PER_TX = 8;
static const int LELANTUS_MIN_SET_SIZE = 16;
static const int LELANTUS_GENESIS_SEED_COUNT = LELANTUS_MIN_SET_SIZE;

// Fork height for serial v2
inline int GetForkHeightSerialV2() {
    extern bool fRegTest;
    extern bool fTestNet;
    return (fRegTest || fTestNet) ? 2 : 7320000;
}
#define FORK_HEIGHT_SERIAL_V2 (GetForkHeightSerialV2())

class CAnonymitySet
{
public:
    std::vector<CPedersenCommitment> vCommitments;
    uint256 blockHashSeed;
    int nBlockHeight;

    CAnonymitySet()
    {
        nBlockHeight = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vCommitments);
        READWRITE(blockHashSeed);
        READWRITE(nBlockHeight);
    )

    int Size() const { return (int)vCommitments.size(); }

    int FindIndex(const CPedersenCommitment& commit) const;

    const CPedersenCommitment& At(int index) const { return vCommitments[index]; }
};


class CLelantusProof
{
public:
    std::vector<unsigned char> vchProof;
    uint256 serialNumber;
    CPedersenCommitment valueCommitment;   // prover-side only

    CLelantusProof() {}

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vchProof);
        READWRITE(serialNumber);
    )

    bool IsNull() const { return vchProof.empty(); }
    size_t GetSize() const { return vchProof.size(); }
};


class CLelantusJoinSplit
{
public:
    std::vector<CLelantusProof> vProofs;
    CAnonymitySet anonymitySet;
    int64_t nValueBalance;

    CLelantusJoinSplit()
    {
        nValueBalance = 0;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(vProofs);
        READWRITE(anonymitySet);
        READWRITE(nValueBalance);
    )
};


bool BuildAnonymitySet(const CPedersenCommitment& realCommit,
                        const std::vector<CPedersenCommitment>& vAllCommitments,
                        const uint256& blockHashSeed,
                        int nBlockHeight,
                        CAnonymitySet& setOut);

bool SelectDecoys(const std::vector<CPedersenCommitment>& vPool,
                   int nCount,
                   const uint256& seed,
                   std::vector<int>& vIndicesOut,
                   int nExcludeIdx = -1);


bool CreateLelantusProof(const CAnonymitySet& anonSet,
                          int nRealIndex,
                          int64_t nValue,
                          const std::vector<unsigned char>& vchBlind,
                          const uint256& serialNumber,
                          CLelantusProof& proofOut);

bool VerifyLelantusProof(const CAnonymitySet& anonSet,
                          const CLelantusProof& proof,
                          const CPedersenCommitment& spendCv);

bool BatchVerifyLelantusProofs(const CAnonymitySet& anonSet,
                                const std::vector<CLelantusProof>& vProofs,
                                const std::vector<CPedersenCommitment>& vSpendCvs);

uint256 ComputeLelantusSerial(const uint256& skSpend,
                               const uint256& rho,
                               const CPedersenCommitment& commitment,
                               int64_t nOutputIndex = -1);


#endif // INN_LELANTUS_H
