// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CHECKPOINT_H
#define  BITCOIN_CHECKPOINT_H

#include <map>
#include "net.h"
#include "util.h"

class uint256;
class CBlockIndex;

/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;
    // Returns true if block passes checkpoint checks
    bool CheckHardened(int nHeight, const uint256& hash);

    // Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate();

    // True when pindex is at or below the last checkpoint on a chain that matches it: by ancestry
    // once that checkpoint is indexed, otherwise through every checkpoint at or below pindex.
    bool IsCheckpointedAncestor(const MapCheckpoints& checkpoints,
                                const std::map<uint256, CBlockIndex*>& mapIndex,
                                const CBlockIndex* pindex);
    bool IsCheckpointedAncestor(const CBlockIndex* pindex);

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex);

    extern MapCheckpoints mapCheckpoints;
    extern MapCheckpoints mapCheckpointsTestnet;

    bool CheckSync(const uint256& hashBlock, const CBlockIndex* pindexPrev);
    const CBlockIndex* AutoSelectSyncCheckpoint();

}

#endif
