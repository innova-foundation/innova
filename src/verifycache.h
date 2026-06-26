// Copyright (c) 2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef INNOVA_VERIFYCACHE_H
#define INNOVA_VERIFYCACHE_H

#include "uint256.h"

// Process-wide memoization of *successful* zero-knowledge proof verifications.
//
// The wrapped verifiers (NullStake kernel V2/V3, FCMP membership, nullifier
// binding) are pure functions of their serialized arguments, so a success
// observed once -- e.g. when a finality vote is first verified at P2P relay --
// is soundly reusable everywhere the same proof is re-verified: the miner block
// template, and the two CheckVote passes inside one ConnectBlock. This turns the
// per-epoch-boundary 2N x (~30s on a 1-vCPU box) verification stall into N
// relay-time verifies spread across the epoch plus near-free cache hits at
// connect.
//
// Only successes are cached. A failed verification falls through to a full
// re-verify every time, so a peer flooding invalid proofs (each with distinct
// bytes) can neither change a result nor evict good entries with junk keys.
// Keys are a domain-separated hash of the exact verifier arguments, so a cache
// hit can never flip a verdict -- it only skips recomputation.
//
// All entry points are thread-safe (verifiers run on the message and miner
// threads, and on the RPC thread via mempool accept).

// Domain separators so identical argument bytes for different verifiers cannot
// collide on a single cache key.
enum VerifyCacheDomain
{
    VERIFYCACHE_NULLSTAKE_V2   = 1,
    VERIFYCACHE_NULLSTAKE_V3   = 2,
    VERIFYCACHE_FCMP           = 3,
    VERIFYCACHE_NULLIFIER_BIND = 4
};

// True if the verify-once cache is enabled (-verifycache, default on).
bool VerifyProofCacheEnabled();

// Return true if this key was previously recorded as a successful verification.
bool VerifyProofCacheCheck(const uint256& key);

// Record a successful verification for this key.
void VerifyProofCacheStore(const uint256& key);

// Drop all cached entries (test/diagnostic use only).
void VerifyProofCacheClear();

#endif // INNOVA_VERIFYCACHE_H
