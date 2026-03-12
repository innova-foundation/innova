# Innova Improvement Proposals (IIPs)

**Version 1.0 -- February 2026**

---

## Overview

Innova Improvement Proposals (IIPs) are the formal specification mechanism for protocol changes, privacy innovations, and consensus upgrades to the Innova network. Each IIP documents a self-contained protocol change with its motivation, specification, security analysis, and activation parameters.

IIPs follow the convention established by Bitcoin Improvement Proposals (BIPs), Ethereum Improvement Proposals (EIPs), and Zcash Improvement Proposals (ZIPs).

---

## IIP Categories

| Category | Description |
|----------|-------------|
| **Consensus** | Changes to block validation, transaction format, or consensus rules |
| **Privacy** | Cryptographic privacy innovations and proof systems |
| **Network** | P2P protocol changes, relay mechanisms, peer management |
| **Application** | Higher-level services built on the protocol (IDNS, Hyperfile) |

## IIP Status Values

| Status | Meaning |
|--------|---------|
| **Draft** | Under development, not yet proposed for activation |
| **Proposed** | Complete specification, pending activation |
| **Active** | Activated on mainnet at the specified fork height |
| **Superseded** | Replaced by a newer IIP |
| **Deprecated** | No longer recommended for use |

---

## IIP Index

### Consensus

| IIP | Title | Category | Status | Fork Height | TX Version |
|-----|-------|----------|--------|-------------|------------|
| [IIP-0001](#iip-0001-cold-staking-p2cs) | Cold Staking (P2CS) | Consensus | Active | 7,100,000 | 1 |
| [IIP-0003](#iip-0003-ring-signature-deprecation) | Ring Signature Deprecation | Consensus | Active | 8,500,000 | 1000 |

### Privacy

| IIP | Title | Category | Status | Fork Height | TX Version |
|-----|-------|----------|--------|-------------|------------|
| [IIP-0002](#iip-0002-shielded-transactions) | Shielded Transactions | Privacy | Active | 8,000,000 | 2000 |
| [IIP-0004](#iip-0004-dynamic-selective-privacy) | Dynamic Selective Privacy (DSP) | Privacy | Active | 8,600,000 | 2001 |
| [IIP-0005](#iip-0005-confidential-coinjoin) | Confidential CoinJoin | Privacy | Active | 8,700,000 | 2000 |
| [IIP-0006](#iip-0006-fcmp-full-chain-membership-proofs) | FCMP++ Full-Chain Membership Proofs | Privacy | Active | 9,000,000 | 2002 |
| [IIP-0007](#iip-0007-silent-payments-and-silent-shielding) | Silent Payments + Silent Shielding | Privacy | Active | 8,000,000 | 2000 |
| [IIP-0009](#iip-0009-nullstake-v1) | NullStake V1 (ZK Private Staking) | Privacy | Active | 9,500,000 | 2003 |
| [IIP-0010](#iip-0010-nullstake-v2) | NullStake V2 (ZK Kernel Privacy) | Privacy | Proposed | 10,000,000 | 2004 |

### Network

| IIP | Title | Category | Status | Fork Height | TX Version |
|-----|-------|----------|--------|-------------|------------|
| [IIP-0008](#iip-0008-dandelion-network-privacy) | Dandelion++ Network Privacy | Network | Active | 8,000,000 | -- |

---

## IIP Specifications

### IIP-0001: Cold Staking (P2CS)

| Field | Value |
|-------|-------|
| **IIP** | 0001 |
| **Title** | Cold Staking via Pay-to-Cold-Staking Scripts |
| **Category** | Consensus |
| **Status** | Active |
| **Fork Height** | 7,100,000 (mainnet) |
| **Author** | 0xcircuitbreaker |

**Abstract**: Introduces Pay-to-Cold-Staking (P2CS) scripts that separate spending authority from staking authority. A P2CS output has two key hashes: the `staker` key can produce coinstake transactions, while only the `owner` key can create spending transactions. This enables hardware wallet cold staking where the spending key never touches an online machine.

**Key Parameters**:
- Script format: `OP_DUP OP_HASH160 <staker_hash> OP_EQUALVERIFY OP_CHECKSIG OP_ELSE OP_DUP OP_HASH160 <owner_hash> OP_EQUALVERIFY OP_CHECKSIG OP_ENDIF`
- Self-delegation prohibited (staker != owner)
- Revocation via owner key spending with `nLockTime` enforcement

**References**: See `src/script.cpp` (P2CS validation), `src/wallet.cpp` (cold staking creation)

---

### IIP-0002: Shielded Transactions

| Field | Value |
|-------|-------|
| **IIP** | 0002 |
| **Title** | Shielded Transactions with Pedersen Commitments and Bulletproof Range Proofs |
| **Category** | Privacy |
| **Status** | Active |
| **Fork Height** | 8,000,000 (mainnet) |
| **TX Version** | `SHIELDED_TX_VERSION = 2000` |
| **Author** | 0xcircuitbreaker |

**Abstract**: Introduces the shielded transaction pool with Pedersen commitments for confidential amounts, Bulletproof range proofs for value validity, Schnorr binding signatures for value balance, and HMAC-SHA256 nullifiers for double-spend prevention. The shielded pool operates alongside the transparent UTXO set with explicit shield/unshield operations.

**Key Parameters**:
- Max shielded inputs/outputs: 16
- Merkle tree depth: 32 (2^32 capacity)
- Range proof: 672 bytes (64-bit Bulletproof)
- Binding signature: 65 bytes (Schnorr, domain-separated)
- Minimum fee: 0.001 INN
- Minimum spend depth: 10 confirmations
- Note encryption: ChaCha20-Poly1305 AEAD

**Cryptographic Primitives**:
- Pedersen commitments: `C = v * H + r * G` on secp256k1
- Bulletproof range proofs [BBB+18]
- Domain-separated Schnorr signatures (`Innova_BindingSig_v2`, `Innova_SpendAuth_v1`)
- HMAC-SHA256 nullifiers: `nf = HMAC-SHA256(nk, rho)`

**References**: See `src/shielded.h/cpp`, `src/zkproof.h/cpp`. Full specification in *Innova Privacy Protocol* whitepaper, Sections 3-4.

---

### IIP-0003: Ring Signature Deprecation

| Field | Value |
|-------|-------|
| **IIP** | 0003 |
| **Title** | Deprecation of Legacy Ring Signatures |
| **Category** | Consensus |
| **Status** | Active |
| **Fork Height** | 8,500,000 (mainnet) |
| **TX Version** | `1000` (rejected after fork) |
| **Author** | 0xcircuitbreaker |

**Abstract**: Disables legacy ring signature transactions (TX version 1000) in favor of the superior privacy guarantees provided by IIP-0002 (Shielded Transactions) and IIP-0006 (FCMP++). Ring signatures with a fixed ring size of 16 provided limited anonymity; the shielded pool with Lelantus (N=64) and FCMP++ (full chain) provide strictly stronger guarantees.

---

### IIP-0004: Dynamic Selective Privacy

| Field | Value |
|-------|-------|
| **IIP** | 0004 |
| **Title** | Dynamic Selective Privacy (DSP) |
| **Category** | Privacy |
| **Status** | Active |
| **Fork Height** | 8,600,000 (mainnet) |
| **TX Version** | `SHIELDED_TX_VERSION_DSP = 2001` |
| **Author** | 0xcircuitbreaker |

**Abstract**: Introduces a 3-bit `nPrivacyMode` field in shielded transactions enabling 8 distinct privacy configurations. Each bit independently controls one privacy dimension: sender identity (Lelantus/FCMP++ proof), receiver identity (encrypted output), and transaction amount (Pedersen commitment + range proof). This enables regulatory compliance use cases while maintaining full privacy as the default.

**Privacy Modes**:

| Mode | Bits | Sender | Receiver | Amount |
|------|------|--------|----------|--------|
| 0 | `000` | Public | Public | Public |
| 1 | `001` | Hidden | Public | Public |
| 2 | `010` | Public | Hidden | Public |
| 3 | `011` | Hidden | Hidden | Public |
| 4 | `100` | Public | Public | Hidden |
| 5 | `101` | Hidden | Public | Hidden |
| 6 | `110` | Public | Hidden | Hidden |
| 7 | `111` | Hidden | Hidden | Hidden |

**Constants**:
- `PRIVACY_HIDE_SENDER = 0x01`
- `PRIVACY_HIDE_RECEIVER = 0x02`
- `PRIVACY_HIDE_AMOUNT = 0x04`
- `PRIVACY_MODE_MASK = 0x07`

**References**: See `src/shielded.h` (DSP constants), `src/main.cpp` (consensus validation), `src/rpcshielded.cpp` (RPC interface).

---

### IIP-0005: Confidential CoinJoin

| Field | Value |
|-------|-------|
| **IIP** | 0005 |
| **Title** | Confidential CoinJoin with MuSig Blind Aggregation |
| **Category** | Privacy |
| **Status** | Active |
| **Fork Height** | 8,700,000 (mainnet) |
| **Author** | 0xcircuitbreaker |

**Abstract**: Enables multi-party shielded CoinJoin transactions where participants collaboratively construct a shielded transaction with aggregated binding signatures. The protocol uses MuSig partial blind aggregation so that no single participant learns the values of other participants' inputs or outputs.

**References**: See `src/shieldedcoinjoin.h/cpp`.

---

### IIP-0006: FCMP++ Full-Chain Membership Proofs

| Field | Value |
|-------|-------|
| **IIP** | 0006 |
| **Title** | Full-Chain Membership Proofs via Dual-Curve Trees |
| **Category** | Privacy |
| **Status** | Active |
| **Fork Height** | 9,000,000 (mainnet) |
| **TX Version** | `SHIELDED_TX_VERSION_FCMP = 2002` |
| **Author** | 0xcircuitbreaker |

**Abstract**: Extends the anonymity set from Lelantus's fixed N=64 to the *entire shielded UTXO set* using Curve Trees -- a Merkle-like structure built over two alternating elliptic curves (secp256k1 at even depths, Ed25519 at odd depths). The dual-curve construction enables efficient recursive proof composition with Inner Product Arguments (IPA).

**Key Parameters**:
- Branching factor (arity): 256
- Maximum depth: 8
- Maximum leaves: 256^8 ~ 1.8 x 10^19
- Proof size: <= 4,096 bytes
- Proof verification: O(d * 256) EC operations across two curves
- Hybrid upgrade: Both Lelantus and FCMP++ proofs accepted during transition

**Novel Contribution**: Hybrid FCMP++/Lelantus upgrade path with deterministic fallback -- the first smooth transition from fixed-size to full-chain anonymity sets.

**References**: See `src/curvetree.h/cpp` (tree construction), `src/ipa.h/cpp` (inner product argument), `src/ed25519_zk.h/cpp` (Ed25519 operations). Based on Campanelli et al. [LS23].

---

### IIP-0007: Silent Payments and Silent Shielding

| Field | Value |
|-------|-------|
| **IIP** | 0007 |
| **Title** | Silent Payments (BIP-352 Adaptation) with Silent Shielding |
| **Category** | Privacy |
| **Status** | Active |
| **Fork Height** | 8,000,000 (mainnet) |
| **Author** | 0xcircuitbreaker |

**Abstract**: Adapts BIP-352 Silent Payments for Innova, enabling recipients to publish a single static address `(B_scan, B_spend)` that senders use to derive unique one-time output keys via ECDH. Introduces **Silent Shielding** -- the first protocol combining BIP-352 stealth addressing with a ZK shielded pool in a single atomic transaction.

**Silent Shielding Protocol**:
1. Sender derives output key `P` via standard Silent Payment ECDH
2. Sender derives shielded address from `P`: `diversifier = SHA256("Innova_SilentShield_d" || P)[0:11]`
3. Sender creates shielded output addressed to derived address
4. Output enters shielded pool, protected by all privacy mechanisms

**Novel Contribution**: First protocol combining BIP-352 with a ZK shielded pool, eliminating the two-step "send then shield" pattern that leaks timing information.

**References**: See `src/silentpayments.h/cpp`. Based on Rubin and Josibake [RJ23].

---

### IIP-0008: Dandelion++ Network Privacy

| Field | Value |
|-------|-------|
| **IIP** | 0008 |
| **Title** | Dandelion++ Network-Layer Transaction Privacy |
| **Category** | Network |
| **Status** | Active |
| **Fork Height** | 8,000,000 (mainnet) |
| **Author** | 0xcircuitbreaker |

**Abstract**: Implements the Dandelion++ two-phase relay protocol to prevent IP-to-transaction linking. Transactions first propagate through a private "stem" phase (forwarded to exactly one peer per hop), then transition to a public "fluff" phase (standard gossip broadcast). Shielded transactions receive mandatory stem phase for enhanced privacy.

**Key Parameters**:
- Fluff probability: 50% per hop (`DANDELION_FLUFF_PROBABILITY = 0.5`)
- Stem timeout: 30 +/- 15 seconds (cryptographically randomized)
- Epoch duration: 600 seconds
- Stem peers per epoch: 2 (Fisher-Yates shuffle with `RAND_bytes`)
- Maximum stem hops: 10
- Shielded transactions: Mandatory full stem (fluff overridden to 0%)

**References**: See `src/dandelion.h/cpp`. Based on Fanti et al. [FGKM18].

---

### IIP-0009: NullStake V1

| Field | Value |
|-------|-------|
| **IIP** | 0009 |
| **Title** | NullStake V1: Zero-Knowledge Private Staking via Sigma Protocol |
| **Category** | Privacy |
| **Status** | Active |
| **Fork Height** | 9,500,000 (mainnet) |
| **TX Version** | `SHIELDED_TX_VERSION_ZARCANUM = 2003` |
| **Author** | 0xcircuitbreaker |

**Abstract**: Enables shielded UTXOs to participate in Proof-of-Stake consensus without revealing stake amount, identity, or which UTXO is being staked. Uses a Sigma protocol to prove the kernel hash inequality `H_kernel < target * weight * value` in zero knowledge, with a Bulletproof range proof that the excess is non-negative and a Schnorr binding signature linking to the on-chain Pedersen commitment.

**Kernel Hash**: `PedersenHash(nStakeModifier || nBlockTimeFrom || nTxPrevOffset || nTxTimePrev || nVoutN || nTimeTx)`

**Proof Components**:
- Sigma proof of kernel equation knowledge
- Bulletproof range proof (excess >= 0)
- Schnorr binding signature (commitment linking)
- Proof size: ~946 bytes

**Limitation**: V1 exposes `nBlockTimeFrom`, `nTxPrevOffset`, `nTxTimePrev`, and `nVoutN` as public fields, leaking UTXO identity. Resolved by IIP-0010.

**References**: See `src/zarcanum.h/cpp` (proof creation/verification), `src/kernel.cpp` (kernel hash). Internal codename: "Zarcanum."

---

### IIP-0010: NullStake V2

| Field | Value |
|-------|-------|
| **IIP** | 0010 |
| **Title** | NullStake V2: ZK Kernel Privacy via Poseidon2 + Bulletproof Arithmetic Circuits |
| **Category** | Privacy |
| **Status** | Proposed |
| **Fork Height** | 10,000,000 (mainnet) |
| **TX Version** | `SHIELDED_TX_VERSION_ZARCANUM_V2 = 2004` |
| **Supersedes** | IIP-0009 (V1 remains valid below fork height) |
| **Author** | 0xcircuitbreaker |

**Abstract**: Resolves the UTXO identity leakage of IIP-0009 by moving all four UTXO-identifying kernel parameters (`nBlockTimeFrom`, `nTxPrevOffset`, `nTxTimePrev`, `nVoutN`) inside a Bulletproof Arithmetic Circuit proof. Replaces SHA256-based kernel hashing with Poseidon2, a ZK-friendly algebraic hash function optimized for R1CS circuits.

**Poseidon2 Hash Parameters**:
- State width: t = 7 (rate 6, capacity 1)
- Full rounds: R_F = 8
- Partial rounds: R_P = 57
- S-box: x^5 over secp256k1 scalar field
- Round constants: SHAKE-256 XOF with domain `"Innova_Poseidon2_RC_secp256k1_t7_RF8_RP57"`
- MDS: 7x7 Cauchy matrix

**R1CS Circuit** (500 constraints, padded to 512):

| Component | Constraints |
|-----------|------------|
| Poseidon2 hash | 339 |
| weight * value | 1 |
| excess in [0, 2^64) | 64 |
| weight in [0, 2^32) | 32 |
| value in [0, 2^64) | 64 |

**Public Inputs**: `nStakeModifier`, `nTimeTx`, `nBits`, `cv` (Pedersen commitment)

**Private Witnesses**: `nBlockTimeFrom`, `nTxPrevOffset`, `nTxTimePrev`, `nVoutN`, value, blinding, weight

**Proof Size**: ~1,018 bytes (8 EC points + 3 scalars + IPA for n=512 + 64-byte linking Schnorr)

**Security**:
- Anti-grinding: `nStakeModifier` and `nTimeTx` remain public (10-second grinding window preserved)
- Weight privacy: Coin age proven in-range but not revealed
- Poseidon2: 128-bit algebraic security
- Fiat-Shamir non-malleability

**References**: See `src/poseidon2.h/cpp` (hash function), `src/bulletproof_ac.h/cpp` (R1CS circuit + AC prover/verifier), `src/zarcanum.h/cpp` (V2 proof integration). Based on Grassi et al. [GLRRSW23] and Bunz et al. [BBB+18].

---

## IIP Numbering Convention

- **IIP-0001 to IIP-0099**: Core consensus and privacy protocol changes
- **IIP-0100 to IIP-0199**: Network protocol changes
- **IIP-0200 to IIP-0299**: Application layer (IDNS, Hyperfile, etc.)
- **IIP-0300+**: Reserved for future categories

## Document Conventions

Each IIP specification should include:
1. **Header table**: IIP number, title, category, status, fork height, TX version, author
2. **Abstract**: One-paragraph summary
3. **Motivation**: Why this change is needed
4. **Specification**: Technical details with exact parameters
5. **Security Analysis**: Cryptographic assumptions and attack resistance
6. **Backward Compatibility**: Impact on existing functionality
7. **References**: Academic papers, source code files, related IIPs

---

*This document is maintained alongside the Innova codebase. For the full technical specification of each IIP, see the [Innova Whitepaper](INNOVA_WHITEPAPER.md) and [Innova Privacy Protocol](INNOVA_PRIVACY_WHITEPAPER.md).*
