# Innova Consensus

This document describes the consensus rules of Innova (INN) as implemented in the
v5.0.0.0 source tree. It covers the hybrid Proof-of-Work / Proof-of-Stake base
layer, the v5 IDAG block-ordering layer, epoch finality with the M-of-N tally
committee, and the height-gated fork-activation schedule. Function and constant
references point at the current code so the prose can be checked against it.

All heights and constants below are the mainnet values unless noted. Regtest and
testnet activate the same rules at low heights (see the `GetForkHeight*` helpers
in `main.h`) so the full stack can be exercised end to end.

---

## 1. Base layer: PoW / PoS hybrid

Innova is a Tribus-algorithm Proof-of-Work / Proof-of-Stake hybrid, in the
Bitcoin / PPCoin / Denarius 0.x C++ lineage. Below the DAG fork the chain is a
linear best-chain of alternating PoW and PoS blocks; above it (see section 3) PoS
minting is disabled and the DAG ordering layer takes over block sequencing.

### 1.1 Proof of Work — Tribus

The PoW hash is `Tribus`, a three-round chained hash of the 80-byte block header:
JH-512 -> Keccak-512 -> ECHO-512, truncated to 256 bits
(`Tribus()` in `hashblock.h`, invoked by `CBlock::GetPoWHash()` in `main.h`). A
PoW block is valid when `CheckProofOfWork(GetPoWHash(), nBits)` holds against the
compact difficulty target.

Block reward is `GetProofOfWorkReward(nHeight, nFees)` in `main.cpp`. Emission is
a piecewise, height-tiered schedule: a launch/premine block, an instamine-guard
window up to `FAIR_LAUNCH_BLOCK`, an early ramp, a long zero-reward stretch
(`ZERO_POW_BLOCK` to block 2,000,000), the post-hack restart, and repeating
250,000-block cycles that step the per-block subsidy up and down (0.01–1.0 INN)
to periodically release the equivalent of one collateralnode, tailing to a
terminal 0.0001 INN/block beyond block 10,000,000. The function takes `nHeight`
explicitly (not `pindexBest`) so non-tip blocks validate to the correct reward.
The post-DAG scaling applied at the end of this function is described in
section 6.

### 1.2 Proof of Stake — kernel

PoS follows the PPCoin kernel model. The kernel hash and target are computed in
`CheckStakeKernelHash()` (`kernel.cpp`):

- **Age gate.** The staked output must satisfy `nStakeMinAge` (mainnet
  `10 * 60 * 60` = 10 hours; `main.cpp`). Above `FORK_HEIGHT_TIGHTER_DRIFT` a
  hard maximum age of 90 days is enforced, rejecting over-aged coins.
- **Coin-day weight.** `GetWeight(nTimeTxPrev, nTimeTx)` in `kernel.cpp` returns
  `nIntervalEnd - nIntervalBeginning - nStakeMinAge`, clamped at `nStakeMaxAge`.
- **Kernel hash.** `Hash(nStakeModifier || nTimeBlockFrom || nTxPrevOffset ||
  txPrev.nTime || prevout.n || nTimeTx)`. The stake modifier is a moving,
  entropy-mixed value produced by `ComputeNextStakeModifier()` /
  `GetKernelStakeModifier()`, so kernels cannot be precomputed far ahead.
- **Target test.** The proof passes when
  `hash * COIN * 86400 <= value * weight * targetPerCoinDay`. The comparison is
  cross-multiplied (rather than dividing to a coin-day weight first) to avoid
  integer-division precision loss for small-value inputs.

`CheckProofOfStake()` (`kernel.cpp`) wraps the kernel check for the coinstake
transaction and also dispatches the private NullStake coinstake variants (V1 / V2
/ V3-cold) to their ZK verifiers when the coinstake carries a NullStake kernel
proof instead of a transparent input.

Stake reward is `GetProofOfStakeReward(nCoinAge, nFees)` in `main.cpp`, paying
`COIN_YEAR_REWARD` = 6% per annum on coin-age (coin-days), i.e.
`nCoinAge/365 * 0.06 + remainder`.

### 1.3 Block spacing

`nTargetSpacing` initializes to 15 seconds (`main.cpp`). The effective per-height
target is returned by `GetTargetSpacingForHeight(nHeight)` (`main.h`):

- **Pre-DAG:** 15 seconds.
- **Post-DAG (`nHeight >= FORK_HEIGHT_DAG`):** 1 second.
- **Regtest:** always 1 second.

`nCoinbaseMaturity` is 65 on mainnet.

---

## 2. IDAG — the v5 DAG block-ordering layer

From `FORK_HEIGHT_DAG` onward, Innova runs the IDAG layer (`dag.cpp` / `dag.h`,
`CDAGManager g_dagManager`). Blocks form a directed acyclic graph rather than a
strict chain: each block commits to up to `MAX_DAG_PARENTS` = 32 parents (one
primary parent plus up to 31 merge parents within `DAG_MERGE_DEPTH` = 64 blocks
of the primary). Parents are committed in a coinbase `OP_RETURN` tagged `"IDAG"`,
written and read by `BuildDAGParentScript()` / `ExtractDAGParents()` (`dag.cpp`).

### 2.1 Coloring and ordering

Each block carries `CBlockDAGData` (`dag.h`): its parents, children, a blue/red
color bit, a cumulative blue-set trust score (`nDAGScore`), a linear-order index,
and the DAGKNIGHT-inferred `k`.

- **GHOSTDAG (pre-DAGKNIGHT).** `ColorBlock()` colors a block blue if its
  anticone relative to the selected blue set is within the tolerance
  `GHOSTDAG_K` = 18. `ComputeDAGScore()` sums `GetBlockTrust()` over the blue
  past-set.
- **DAGKNIGHT (from `FORK_HEIGHT_DAGKNIGHT`).** `ColorBlockDAGKnight()` replaces
  the fixed `k` with an adaptive one inferred per block from the local DAG
  neighborhood (`InferLocalK()`), clamped to `[DAGKNIGHT_K_FLOOR,
  DAGKNIGHT_K_CEILING]` = [3, 32] and smoothed by an EMA. Pairwise order between
  two blocks is decided by supporting mass (`SupportingMass()` /
  `CompareBlockOrder()`), with a confidence floor `DAGKNIGHT_MIN_CONFIDENCE`.

The canonical best tip is `SelectBestDAGTip()` (highest blue-set score), and
`GetDAGLinearOrder(hashTip)` yields the deterministic linear ordering from a tip
back toward genesis. Crucially, `GetDAGLinearOrder` is **anchor-pure**: it is a
function only of the selected-parent chain, the committed `vDAGParents`, and the
coloring — never of node-local live state — which is what lets epoch state be
recomputed identically on every node after a reorg.

DAG data older than `DAG_PRUNE_DEPTH` = 100,000 blocks (~28h at 1s) is pruned by
`PruneDAGData()`, preserving epoch boundary blocks.

---

## 3. PoS minting disabled post-DAG; stake repurposed for finality voting

Above `FORK_HEIGHT_DAG`, stake no longer produces blocks. Two enforcement points:

- **Template.** `CreateNewBlock()` (`miner.cpp`) returns `NULL` for any
  proof-of-stake template at post-DAG height — no coinstake blocks are built.
- **Staking thread.** `StakeMiner()` (`miner.cpp`) stops minting after the DAG
  fork and instead produces **transparent finality votes**: stakers put their
  stake weight to work voting on epoch finality rather than sealing blocks.

Post-DAG, blocks are Proof-of-Work only, and finality votes / tally shares /
tally certificates are carried inside PoW blocks. `ConnectBlock()` (`main.cpp`)
rejects finality votes, shares, and certificates that appear anywhere but a
post-DAG PoW block.

---

## 4. Epoch finality (`finality.cpp` / `finality.h`)

From `FORK_HEIGHT_FINALITY`, Innova runs an epoch-based finality gadget layered
on top of the DAG. Stake weight votes for a winning block per epoch; when a
supermajority is reached the epoch (and the history behind it) becomes final and
reorgs below the finalized height are rejected.

### 4.1 Epochs

Epoch length is height-dependent (`GetEpochInterval()` in `finality.h`):
`FINALITY_EPOCH_INTERVAL_PRE_DAG` = 60 blocks pre-DAG, and
`FINALITY_EPOCH_INTERVAL_POST_DAG` = 300 blocks post-DAG (5 minutes at 1s
blocks). `GetEpochForHeight()` / `GetEpochStartHeight()` translate between height
and epoch across the spacing change.

At each epoch boundary the DAG manager freezes a `CEpochState` (`dag.h`) for the
completed epoch: the DAG-ordered block set, the shielded curve-tree root, the
nullifier root, a digest of the finality votes embedded in that epoch's blocks
(`hashVoteSetRoot`), the finality certificate hash, the tier, and a deterministic
running-max finalized height (`nFinalizedHeightAsOf`). `ComputeEpochState()` is a
**pure function of a canonical anchor block** (post `FORK_HEIGHT_EPOCH_STATE_V2`),
recomputed from the new best tip on reorg, so every node freezes identical epoch
roots — the fix for the earlier split where epoch state derived from the
node-local live tip.

### 4.2 Votes

A finality vote (`CFinalityVote`) names an epoch, the block it votes for, a stake
weight, a reward, and a stake proof. Votes come in three proof modes
(`FinalityProofMode`):

- `FINALITY_PROOF_TRANSPARENT` (0) — backed by an ordinary UTXO used as a stake
  proof; weight and reward are in the clear. This is the compatibility path the
  post-DAG staking thread emits.
- `FINALITY_PROOF_NULLSTAKE_V2` (2) — private, ZK NullStake stake proof.
- `FINALITY_PROOF_NULLSTAKE_V3_COLD` (3) — private cold-stake / M-of-N proof;
  weight and reward are hidden and settled only through the tally certificate.

Vote validity is bounded in time and position: a vote must land within
`FINALITY_VOTE_INCLUSION_WINDOW` = 24 blocks after its epoch boundary, per-block
inclusion is capped at `FINALITY_MAX_BLOCK_VOTES` = 32, and an epoch needs at
least `FINALITY_MIN_VOTERS` = 2 unique voters. Private votes carry a note- and
epoch-bound nullifier, so a note votes at most once per epoch.

Vote reward is `GetFinalityVoteReward(nVoteWeight, nEpochInterval)`
(`finality.cpp`), which reproduces the legacy 6%/yr PoS curve on the coin-age a
voter's stake accrues over one epoch — stake earns from finality participation
what it used to earn from minting.

### 4.3 Tally, thresholds, and tiers

Votes are aggregated per candidate block. The winning block's weight versus the
total active weight determines the epoch's tier (`FinalityDetermineTier()` in
`finality.cpp`):

| Tier | Enum | Condition |
|------|------|-----------|
| None | `FINALITY_NONE` (0) | below the tentative threshold or too few voters |
| Tentative | `FINALITY_TENTATIVE` (1) | winning weight >= 1/3 of active weight |
| Soft | `FINALITY_SOFT` (2) | winning weight >= 1/2 of active weight |
| Hard | `FINALITY_HARD` (3) | winning weight >= 2/3 of active weight (`FINALITY_THRESHOLD_NUM/DEN`) |

Binding finality (the point below which reorgs are refused) requires
`FINALITY_CONFIRMATION_EPOCHS` = 3 consecutive HARD epochs, a propagation-safety
margin tracked per epoch by `nConsecutiveHardCount`. Transparent tallies are
checked directly against the 1/3, 1/2, and 2/3 thresholds in `finality.cpp`.

Private (NullStake) votes are never counted in the clear. Their aggregate weight
and reward budget are proven inside a **tally certificate**
(`CFinalityTallyCertificate`), which asserts, without revealing individual
weights, that the hidden winning/active weights meet the claimed tier and that
the private reward budget equals `GetFinalityVoteReward` of the hidden active
weight. The certificate must cover **exactly** the epoch-E votes connected within
the inclusion window (coverage equality against `hashVoteSetRoot`), so a producer
cannot drop connected votes or certify a minority block.

### 4.4 The M-of-N tally committee

The private tally is administered by a bounded committee (up to
`FINALITY_MAX_TALLY_COMMITTEE` = 64 members) with an M-of-N threshold. Members
publish encrypted committee aggregate evaluations (tally shares,
`CFinalityTallyShare`), which combine into the certificate; the certificate binds
the committee-set hash and threshold for its epoch.

From `FORK_HEIGHT_TALLY_GOVERNANCE` (D2), the committee becomes a **consensus
trust root**: a v3 tally certificate must carry at least M detached signatures
from the canonical committee for its epoch (strictly ascending signer indices),
verified by `CheckTallyCertificateCommitteeSignatures()` /
`VerifyMofNCommitteeSignatures()`. The canonical committee for an epoch is
resolved by `GetCanonicalFinalityCommittee()`, pinned at startup by
`PinFinalityCommitteeConstants()`. The committee **rotates itself**: a
`CFinalityCommitteeRotation` authorized by >= M signatures from the *current*
committee installs a new set and threshold, chained by `hashPrevCommitteeSet`,
with no central key — verified by `CheckFinalityCommitteeRotation()`. On mainnet
the committee-signature requirement co-activates with the DAG fork (the first
height a private certificate can exist) so no window exists where private certs
are accepted without M-of-N authorization.

---

## 5. Fork-activation schedule (height-gated flag days)

All v5 upgrades are pure height gates: a rule activates when block height reaches
its fork height, with no signaling. Because activation is a flag day, the
upgraded binary must be deployed to the whole network before the height is
reached. Each gate is a `GetForkHeight*()` helper (`main.h`, plus
`GetForkHeightFCMP()` in `curvetree.h`) that returns a low height on
regtest/testnet and the mainnet height below.

| Fork | Helper / macro | Mainnet height | What it activates |
|------|----------------|----------------|-------------------|
| Cold staking (P2CS) | `FORK_HEIGHT_COLD_STAKING` | 7,800,000 | cold-staking scripts; also the CN-payment / tighter-drift base hardening |
| Shielded | `FORK_HEIGHT_SHIELDED` | 7,810,000 | shielded (zk) transactions; nullifier-binding is born here |
| RingSig deprecation | `FORK_HEIGHT_RINGSIG_DEPRECATION` | 7,815,000 | rejects legacy `ANON_TXN_VERSION` ring-sig txns |
| DSP (Dynamic Selective Privacy) | `FORK_HEIGHT_DSP` | 7,815,000 | 3-bit `nPrivacyMode` field in `SHIELDED_TX_VERSION_DSP` |
| NullSend / CoinJoin | `FORK_HEIGHT_NULLSEND` (`= FORK_HEIGHT_CJOIN`) | 7,820,000 | NullSend CoinJoin-style mixing |
| FCMP++ | `FORK_HEIGHT_FCMP` (`= FORK_HEIGHT_FCMP_VALIDATION`) | 7,820,000 | FCMP++ curve-tree membership proofs |
| NullStake V1 | `FORK_HEIGHT_NULLSTAKE` | 7,825,000 | private staking via ZK kernel proofs |
| NullStake V2 | `FORK_HEIGHT_NULLSTAKE_V2` | 7,830,000 | V2 ZK kernel (hides kernel params); kernel-pinning born here |
| NullStake V3 | `FORK_HEIGHT_NULLSTAKE_V3` | 7,835,000 | private cold staking |
| Chaumian CoinJoin | `FORK_HEIGHT_CHAUMIAN_CJ` | 7,840,000 | blind-signature CoinJoin/NullSend upgrade |
| POEM | `FORK_HEIGHT_POEM` | 7,940,000 | POEM entropy weighting |
| Finality | `FORK_HEIGHT_FINALITY` | 7,945,000 | PoS epoch finality gadget |
| DAG | `FORK_HEIGHT_DAG` | 7,950,000 | IDAG ordering, 1s blocks, PoS-minting disabled, reward /15; co-activates epoch-state (`EPOCH_ROOT_FCMP`, `VOTESET_ROOT`, `EPOCH_STATE_V2`) and tally governance |
| DAGKnight | `FORK_HEIGHT_DAGKNIGHT` | 8,000,000 | adaptive-`k` DAGKNIGHT ordering (replaces GHOSTDAG) |
| NullStake deleg-set / reclaim / B2-c | `FORK_HEIGHT_NULLSTAKE_DELEGSET` / `_RECLAIM` / `_NULLSTAKE_B2C` | 8,060,000 | M-of-N shielded cold staking (public-signer and ZK-hidden-signer tiers), owner-override reclaim |

Several sibling gates are pinned to `FORK_HEIGHT_DAG` deliberately:
`FORK_HEIGHT_EPOCH_ROOT_FCMP` (FCMP spends bind to the last finalized epoch
curve-tree snapshot), `FORK_HEIGHT_VOTESET_ROOT` (per-epoch vote-set
accumulator), `FORK_HEIGHT_EPOCH_STATE_V2` (deterministic reorg-safe epoch
anchor), and `FORK_HEIGHT_TALLY_GOVERNANCE` (M-of-N committee authorization).
`FORK_HEIGHT_NULLIFIER_BINDING` and `FORK_HEIGHT_KERNEL_PINNING`, by contrast,
are anchored to the shielded / NullStake-V2 forks respectively — they must be
enforced from the first height their target objects can exist, to avoid a window
of unbound nullifiers (supply inflation) or unpinned kernel inputs (coin-age
forgery / metadata leakage).

---

## 6. Post-DAG reward scaling (emission-rate continuity)

The `GetProofOfWorkReward()` tier table encodes the intended per-block emission
at the pre-DAG 15-second cadence. Post-DAG blocks arrive 15x faster (1s), so the
same per-block subsidy would be a ~15x inflation spike and would exhaust the
schedule ~15x faster in wall-clock time.

To keep the emission **rate** continuous across the DAG fork,
`GetProofOfWorkReward()` scales every post-DAG subsidy by the block-spacing
ratio (`main.cpp`):

```
static const int64_t PRE_DAG_TARGET_SPACING = 15; // seconds
if (nHeight >= FORK_HEIGHT_DAG)
    nSubsidy = nSubsidy * GetTargetSpacingForHeight(nHeight) / PRE_DAG_TARGET_SPACING;
```

With `GetTargetSpacingForHeight` returning 1 post-DAG, this is a divide-by-15.
Two deliberate details: the pre-DAG reference is a compile-time constant (not the
mutable `nTargetSpacing` global), so the consensus divisor can never be perturbed
by runtime state; and the post-DAG spacing is read from
`GetTargetSpacingForHeight`, so if the 1s block time is ever re-tuned the ratio
self-corrects. `PRE_DAG_TARGET_SPACING` must be kept in sync with the initial
value of `nTargetSpacing`.

---

## 7. Reference — key functions and constants

- **PoW hash:** `Tribus()` (`hashblock.h`), `CBlock::GetPoWHash()` (`main.h`).
- **PoW reward:** `GetProofOfWorkReward()` (`main.cpp`).
- **PoS kernel:** `CheckStakeKernelHash()`, `CheckProofOfStake()`,
  `ComputeNextStakeModifier()`, `GetKernelStakeModifier()`, `GetWeight()`
  (`kernel.cpp`); `nStakeMinAge`, `nStakeMaxAge`, `nCoinbaseMaturity`
  (`main.cpp`).
- **PoS reward:** `GetProofOfStakeReward()`, `COIN_YEAR_REWARD` (`main.cpp` /
  `main.h`).
- **Block spacing:** `GetTargetSpacingForHeight()`, `nTargetSpacing` (`main.h` /
  `main.cpp`).
- **DAG:** `CDAGManager`, `SelectBestDAGTip()`, `GetDAGLinearOrder()`,
  `ColorBlock()` / `ColorBlockDAGKnight()`, `ComputeEpochState()`,
  `GetDeterministicFinalizedHeight()`, `CEpochState`, `CBlockDAGData` (`dag.h` /
  `dag.cpp`).
- **Finality:** `GetEpochInterval()`, `FinalityDetermineTier()`,
  `GetFinalityVoteReward()`, `CFinalityVote`, `CFinalityTallyCertificate`,
  `CFinalityCommitteeRotation`, `GetCanonicalFinalityCommittee()`,
  `CheckTallyCertificateCommitteeSignatures()`,
  `CheckFinalityCommitteeRotation()` (`finality.h` / `finality.cpp`); tier and
  epoch constants at the top of `finality.h`.
- **Fork gates:** `GetForkHeight*()` (`main.h`), `GetForkHeightFCMP()`
  (`curvetree.h`).