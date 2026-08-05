// Copyright (c) 2026 The Innova developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_PRIVACY_VNEXT_STORE_H
#define INNOVA_PRIVACY_VNEXT_STORE_H

#include <string>
#include <vector>

#include "privacy_vnext_ffi.h"

class CTxDB;
struct CEpochState;

// Node-local index of the finalized IV5 tree: leaves and per-level node hashes, so a
// membership witness is read by leaf index. Derived state; the epoch root is authoritative.

// Append one epoch's output leaves, in the order the epoch state fixes.
//
// `treeState` is the frontier the store is currently at, and is advanced in place.
bool GrowPrivacyVNextTreeStore(CTxDB& txdb,
                               const std::vector<PrivacyVNextOutputLeaf>& leaves,
                               std::vector<unsigned char>& treeState,
                               std::string& strErrorOut);

// Drop every leaf at or past `nNewSize` and restore the levels above them, rehashing one
// node per level from children the store holds.
bool TrimPrivacyVNextTreeStore(CTxDB& txdb, uint64_t nNewSize,
                               const std::vector<unsigned char>& treeState,
                               std::string& strErrorOut);

// Bring the store in line with the persisted epoch chain through `nThroughEpoch`.
// Idempotent; a failure must be logged and retried, never fail block processing.
bool SyncPrivacyVNextTreeStore(CTxDB& txdb, int nThroughEpoch,
                               std::string& strErrorOut);

// Collect one epoch's output leaves in the order the epoch state fixes.
bool CollectPrivacyVNextEpochLeaves(const CEpochState& state,
                                    std::vector<PrivacyVNextOutputLeaf>& vLeavesOut,
                                    std::string& strErrorOut);

// Read the sibling path for each target, framed as a path-mode witness request tail.
bool ReadPrivacyVNextTreePaths(CTxDB& txdb, uint64_t nTreeSize,
                               const std::vector<uint64_t>& vTargetLeafIndexes,
                               std::vector<unsigned char>& vchPathsOut,
                               std::string& strErrorOut);

// How many leaves the store currently holds.
bool ReadPrivacyVNextTreeStoreSize(CTxDB& txdb, uint64_t& nSizeOut);

#endif // INNOVA_PRIVACY_VNEXT_STORE_H
