# Innova Privacy Architecture

This document describes Innova's optional privacy stack: the shielded value
pool, the zero-knowledge proof systems that protect it, the private-staking
layer, and the network-level and address-level features that reduce metadata
leakage. These are standard privacy-coin components, comparable to those found
in Zcash, Monero, Firo, and Dash. Each section states what a feature does, the
key source files, and how it fits into the wider system.

Privacy in Innova is *opt-in*. Transparent UTXO transactions remain the default;
a sender chooses privacy per transaction through a mode mask
(`PRIVACY_HIDE_SENDER`, `PRIVACY_HIDE_RECEIVER`, `PRIVACY_HIDE_AMOUNT`, or the
combined `PRIVACY_MODE_FULL`), defined in `shielded.h`. Most features are gated
by consensus fork heights so that older nodes remain valid until a coordinated
activation.

---

## 1. Overview and layering

The stack is organized in layers, from cryptographic primitives up to
user-facing features:

| Layer | Purpose | Files |
| --- | --- | --- |
| Field / hash primitives | Poseidon2 permutation over the proof field | `poseidon2.*` |
| Commitment primitives | Pedersen commitments, blinding, binding signatures | `zkproof.*` |
| Range proofs | Bulletproof range proofs; arithmetic-circuit (R1CS) proofs | `zkproof.*`, `bulletproof_ac.*` |
| Inner-product argument | Logarithmic-size IPA backing the circuit proofs | `ipa.*` |
| Membership proofs | Curve-tree (FCMP++) set membership across two curves | `curvetree.*`, `ed25519_zk.*`, `ipa.*` |
| Legacy anonymity set | Lelantus one-of-many spend proofs | `lelantus.*` |
| Shielded pool | Notes, commitments, nullifiers, spend/output descriptions | `shielded.*`, `zkproof.*` |
| Private staking | NullStake shielded coinstake / finality voting | `nullstake.*`, `bulletproof_ac.*` |
| Mixing | NullSend CoinJoin-style multi-party sessions | `nullsend.*` |
| Addressing | Stealth addresses, silent payments | `stealth.*`, `silentpayments.*` |
| Propagation | Dandelion++ transaction relay | `dandelion.*` |

The rest of this document treats each of these in turn, roughly bottom-up so
that later sections can refer back to the primitives.

---

## 2. Cryptographic primitives

### 2.1 Poseidon2 hash — `poseidon2.*`

Poseidon2 is an algebraic (arithmetization-friendly) hash function whose
permutation is cheap to express inside a zero-knowledge circuit, unlike SHA-256.
Innova uses it wherever a value must be hashed *and* proven in zero knowledge —
most importantly the stake-kernel hash that NullStake proves knowledge of.

`poseidon2.h` fixes the instance parameters: state width `t = 7`, absorption
rate `6`, eight full rounds (`RF`) plus 57 partial rounds (`RP`), and an
`x^5` S-box. `CPoseidon2Params` lazily generates the round constants, MDS matrix,
and internal diagonal; `Poseidon2Permute` runs the permutation and
`Poseidon2Hash` provides a fixed six-input sponge. The module also exposes the
prime-field arithmetic (`FieldAdd`, `FieldMul`, `FieldPow5`, `FieldInv`,
`FieldReduce`, …) that both Poseidon2 and the circuit builder rely on.

`Poseidon2KernelHash` computes the Proof-of-Stake kernel hash from the stake
modifier and the input/output timing fields, giving a hash the staking circuit
can reproduce internally.

### 2.2 Pedersen commitments and binding signatures — `zkproof.*`

`zkproof.*` is the commitment and value-conservation core. `CZKContext` holds
the three nothing-up-my-sleeve generators used throughout the pool:

- `G` — blinding-factor generator,
- `H` — value generator,
- `J` — an independent generator for the M-of-N delegation term (Section 6).

A Pedersen commitment (`CPedersenCommitment`, 33-byte compressed point) is
`value*H + blind*G`; it perfectly hides the value while binding it. The module
provides `CreatePedersenCommitment`, homomorphic `AddCommitments` /
`SubtractCommitments`, and `VerifyCommitmentBalance`, which checks that inputs,
outputs, and fee sum to zero across the commitment homomorphism.

A **binding signature** (`CBindingSignature`, `CreateBindingSignature` /
`VerifyBindingSignature`) proves that the sum of input blinds equals the sum of
output blinds for a given value balance, tying the whole transaction's
commitments to its signature hash without revealing any individual blind. A
MuSig-style multi-party variant (`GenerateMuSigNonce`, `AggregateNoncePoints`,
`ComputeMuSigChallenge`, `CreatePartialBindingSig`, `AggregatePartialSigs`,
`AggregatePartialSigsRLC`) lets several NullSend participants jointly produce one
binding signature.

Two further pieces live here:

- **Nullifier binding** (`ComputeNullifierPoint`, `CreateNullifierBindingProof`,
  `VerifyNullifierBindingProof`): ties a spend's nullifier to the value
  commitment of the note being spent so a nullifier cannot be forged
  independently of the note. Activated at `FORK_HEIGHT_NULLIFIER_BINDING`.
- **Spend-authorization signatures** (`CreateSpendAuthSignature`,
  `VerifySpendAuthSignature`) over a re-randomized key `rk`, proving control of
  the note's spend key.

Symmetric encryption for note ciphertexts uses ChaCha20-Poly1305
(`ChaCha20Poly1305Encrypt` / `Decrypt`).

### 2.3 Inner-product argument — `ipa.*`

The IPA is the logarithmic-size building block underneath both the range proofs
and the curve-tree membership proofs. `CreateIPAProof` / `VerifyIPAProof` reduce
an inner-product relation of length `n` to `log n` rounds, emitting one `L` and
one `R` point per round plus two final scalars (`CIPAProof`). A Fiat-Shamir
transcript (`CIPATranscript`, domain `"Innova_IPA_v1"`) makes it
non-interactive.

The module is curve-generic (`EIPACurveType` selects secp256k1 or ed25519) and
supplies the low-level scalar/point arithmetic for both. On top of the raw
argument it builds path-membership proofs: `CPathIPAProof` /
`CreatePathIPAProof` / `VerifyPathIPAProof` prove that a leaf commitment sits at
a given position under a root, and `CreateFCMPProofV5` / `…V6` assemble the
full membership proof (single-curve V5; cross-curve V6, Section 5).

---

## 3. Range proofs

### 3.1 Bulletproof range proofs — `zkproof.*`

Every shielded value commitment must be proven to lie in a valid, non-negative
range (no inflation via negative values or overflow). `CBulletproofRangeProof`
(`CreateBulletproofRangeProof`, `VerifyBulletproofRangeProof`,
`BatchVerifyBulletproofRangeProofs`) provides standard Bulletproof range proofs
over a `CPedersenCommitment`. Batch verification amortizes the cost across the
inputs and outputs of a transaction. Each shielded spend and output description
carries one (`shielded.h`).

### 3.2 Arithmetic-circuit (R1CS) proofs — `bulletproof_ac.*`

Beyond simple ranges, NullStake needs to prove a *relation* — that a hidden
staked value satisfies the kernel-difficulty inequality — inside zero knowledge.
`bulletproof_ac.*` implements a Bulletproofs-style arithmetic-circuit proof
system over a rank-1 constraint system (R1CS):

- `CR1CSCircuit` expresses multiplication gates and linear constraints with
  sparse weight matrices (`WL`, `WR`, `WO`, `WV`) and pads to a power of two for
  the IPA. `CSparseEntry` is one weight.
- `CR1CSWitness` holds the assignment (`aL`, `aR`, `aO`, committed values, and
  blinds).
- `CBulletproofACProof` is the on-wire proof (commitments `AI`, `AO`, `S`, the
  `T` polynomial commitments, the scalars `tauX`, `mu`, `tHat`, and an embedded
  `CIPAProof`). `CreateBulletproofACProof` / `VerifyBulletproofACProof`
  produce and check it.

The circuit builders `BuildNullStakeV2Circuit` and `BuildNullStakeV3Circuit`
(with `AssignNullStakeV2Witness` / `…V3Witness`) encode the stake-kernel
comparison — and, for V3, the delegation binding — directly as constraints, so
the prover demonstrates kernel satisfaction without revealing the staked amount.
Constraint and proof-size caps (`BPAC_MAX_CONSTRAINTS`, `BPAC_MAX_PROOF_SIZE`,
and V3 equivalents) bound verifier work for DoS resistance.

---

## 4. Legacy anonymity set — Lelantus — `lelantus.*`

Lelantus provides a one-of-many (spend-from-a-set) proof: it hides *which*
commitment in an anonymity set is being spent, breaking the link between a
spend and the output that funded it. `CAnonymitySet` is a set of
`CPedersenCommitment`s seeded from a block hash at a given height;
`BuildAnonymitySet` and `SelectDecoys` assemble it (deterministic decoy
selection from the pool), and `CLelantusProof` / `CreateLelantusProof` /
`VerifyLelantusProof` (with `BatchVerifyLelantusProofs`) prove and check
membership plus a fresh serial number (`ComputeLelantusSerial`) that prevents
double-spends.

Sizing is fixed in `lelantus.h` (`LELANTUS_SET_SIZE = 64`, up to 8 spends per
tx, minimum set size 16). Lelantus is the earlier-generation membership system;
`CShieldedSpendDescription` still carries a Lelantus proof and anon-set fields,
but from `FORK_HEIGHT_FCMP` onward the curve-tree FCMP++ proof (Section 5) is
the primary membership mechanism. A serial-format upgrade is gated at
`FORK_HEIGHT_SERIAL_V2` (`GetForkHeightSerialV2`).

---

## 5. FCMP++ membership — `curvetree.*`, `ipa.*`, `ed25519_zk.*`

FCMP++ ("Full-Chain Membership Proofs") lets a spend prove that its note is one
of *all* notes ever added to the pool, without a bounded decoy set and without
revealing which one — a much larger anonymity set than Lelantus. It is Innova's
current membership proof.

### 5.1 The curve tree — `curvetree.*`

`CCurveTree` is a Merkle-like accumulator of every note's value commitment
(`InsertLeaf`), but instead of a plain hash it uses an **alternating-curve**
construction: even levels are secp256k1 points, odd levels ed25519 points
(`CCurveTreeNode::GetCurveAtDepth`), with arity 256 and max depth 8. Each
parent node commits to its children as a curve point (`HashCurveTreeChildren`),
so a path from leaf to `GetRoot()` can be proven with an algebraic argument
rather than a hash preimage. The alternating curves let each layer's proof be
expressed efficiently on the curve where the child points live.

`CFCMPProof` is the membership proof; its version byte selects the construction
(`FCMP_PROOF_VERSION_*`): legacy, blinded, encrypted, IPA-based (V5, current
default via `FCMP_PROOF_VERSION_CURRENT`), and cross-curve (V6).
`CreateFCMPProof` / `VerifyFCMPProof` / `BatchVerifyFCMPProofs` build and check
proofs against a root node. A spend embeds its `fcmpProof` and the
`curveTreeRoot` it was built against (`CShieldedSpendDescription`), so consensus
can confirm the note existed under a known historical root.

### 5.2 ed25519 backend — `ed25519_zk.*`

`ed25519_zk.*` supplies the constant-time ed25519 group and scalar arithmetic
the odd tree layers need: scalar add/mul/inverse/negate/reduce, point
add/negate, single- and double-scalar multiplication, base-point multiplication,
hash-to-point (`Ed25519HashToPoint`), Pedersen commitments over ed25519, and
torsion-safe encode/decode. `curvetree.*` re-exports thin wrappers
(`Ed25519PointFromBytes` with torsion rejection, `Ed25519ScalarMult`, etc.) so
the tree code stays curve-agnostic.

### 5.3 Cross-curve proofs — `ipa.*`

The V6 cross-curve proof (`CCrossCurveFCMPProof`, `CCrossCurveLayerProof`,
`CreateFCMPProofV6` / `VerifyFCMPProofV6`) proves each tree layer on its own
curve and binds adjacent layers with a re-randomization commitment plus a
binding proof, so a single membership statement traverses both curves. The
per-layer engine is the IPA of Section 2.3.

FCMP++ activation is gated at `FORK_HEIGHT_FCMP` (`GetForkHeightFCMP`).

---

## 6. Shielded pool — `shielded.*`

The shielded pool is the value layer that binds all of the above together. It
follows the note/commitment/nullifier model familiar from Zcash Sapling.

### 6.1 Keys and addresses

A key tree is derived from a `CShieldedSpendingKey` (spend key, PRF key, outgoing
viewing key): `DeriveShieldedFullViewingKey` →
`DeriveShieldedIncomingViewingKey` → `DeriveShieldedPaymentAddress`. The full
viewing key can detect and decrypt notes; the incoming viewing key can only
recognize incoming payments; the spending key authorizes spends. Payment
addresses (`CShieldedPaymentAddress`) combine an 11-byte diversifier with a
diversified transmission key `pkD`, so one wallet can present many unlinkable
addresses (`GenerateShieldedDiversifier`).

### 6.2 Notes, commitments, nullifiers

A `CShieldedNote` is `(address, value, rho, rcm, blind)`. `GetCommitment`
produces the note commitment inserted into both the incremental Merkle tree
(`CIncrementalMerkleTree`, depth 32) and the curve tree; `GetNullifier(nk)`
derives the note's nullifier via `PRF_nf`. Spending a note publishes its
nullifier, which is recorded in the spent set (`CShieldedNullifierSpent`) so it
can never be spent twice, while the note commitment itself reveals nothing about
which output is being consumed.

### 6.3 Spend and output descriptions

- `CShieldedSpendDescription` carries the value commitment `cv`, the tree
  `anchor`/`curveTreeRoot`, the `nullifier`, the re-randomized key `rk` and
  spend-auth signature, a range proof, and the membership proof — either a
  Lelantus proof (`vchLelantusProof` + `vAnonSet`) or an FCMP proof
  (`fcmpProof`), plus optional nullifier-binding fields.
- `CShieldedOutputDescription` carries `cv`, the note commitment `cmu`, an
  ephemeral key, the encrypted note ciphertext (`EncryptShieldedNote` /
  `DecryptShieldedNote`, for the recipient) and an out-ciphertext
  (`EncryptShieldedNoteForSender`, recoverable with the outgoing viewing key),
  and a range proof.

Value conservation across a shielded transaction is enforced by the binding
signature (`CShieldedBindingSig`) over the value balance. Transaction versions
`SHIELDED_TX_VERSION` (2000) through `SHIELDED_TX_VERSION_NULLSTAKE_RECLAIM`
(2007) select the feature set (base, DSP mode mask, FCMP, the NullStake
variants, the M-of-N mint, and the owner-override reclaim). The global
`nShieldedPoolValue` tracks the transparent value that has entered the pool.

### 6.4 Cold staking and M-of-N delegation

`CColdStakeDelegation` lets an owner delegate staking authority (an encrypted
staking key) to a hot node while retaining spend control — the hot key can stake
but not spend. `CMofNDelegation` generalizes this to an M-of-N staker set: the
delegation hash `D = SetHash(set, M, ownerPubKey)` becomes the `J`-coefficient
of a three-generator leaf commitment `cv3 = value*H + blind*G + D*J`, hiding the
delegation set while still binding it. `DeriveStakingKey` /
`DeriveStakingPubKey` derive the staking subkey. This delegation machinery is
the bridge into NullStake (Section 7).

---

## 7. NullStake — private staking (internal codename "Zarcanum") — `nullstake.*`

NullStake is Innova's private Proof-of-Stake layer: it lets a shielded note
participate in staking / finality voting without revealing the staked amount or
linking the staker to a transparent UTXO. The internal codename is "Zarcanum",
after the hidden-amount staking construction of the same lineage. It reuses the
shielded note (Section 6), the FCMP membership proof (Section 5), and the
arithmetic-circuit proof (Section 3.2).

### 7.1 Kernel proof

The core statement is: *"I know a note in the curve tree whose hidden value
satisfies the stake-kernel difficulty target at this time."* Three proof
generations exist:

- **V1 `CNullStakeKernelProof`** — a sigma-protocol proof over a weighted
  commitment plus the kernel timing fields; `PedersenKernelHash` /
  `CheckShieldedStakeKernelHash`.
- **V2 `CNullStakeKernelProofV2`** — replaces the sigma proof with a
  Bulletproof arithmetic-circuit proof (`BuildNullStakeV2Circuit`) over a value
  commitment plus a link proof tying the circuit's committed value to the note.
- **V3 `CNullStakeKernelProofV3`** — the current form. It adds the delegation
  hash and staker/owner public keys, so the circuit proves kernel satisfaction
  *and* delegation binding (`BuildNullStakeV3Circuit`,
  `CheckShieldedStakeKernelHashV3`).

`CShieldedCoinstake` packages the shielded stake input, the return-to-self
output, the reward output, and the kernel proof for a staking transaction.

Because PoS block minting is disabled post-DAG, a satisfied stake kernel is
repurposed as a **finality vote**: the same NullStake proof authorizes a node's
vote in the epoch-finality committee rather than minting a block.

### 7.2 M-of-N authorization tiers

For a delegated (M-of-N) note, V3 must additionally prove that at least `M` of
the `N` set members authorized the stake. Two tiers exist, selected by
`nAuthMode`:

- **B2-e — public half-aggregated signers (`NULLSTAKE_AUTHMODE_HALFAGG`).**
  Each of `M` members signs the stake digest with its own key; the `s`-scalars
  are summed into one aggregate while the `M` `R`-points are kept, and
  verification checks a single Schnorr relation
  (`SignHalfAggStakeShare`, `AggregatePartialSigsRLC`,
  `VerifyHalfAggStakeSignature` in `zkproof.*`;
  `ComputeNullStakeV3DelegationSetHash`, `VerifyNullStakeMofNAuthorization`,
  `ComputeNullStakeMofNStakeDigest` in `bulletproof_ac.*`). Signer identities
  are public. `CreateNullStakeMofNKernelProofV3` builds it.
- **B2-c — hidden signers (`NULLSTAKE_AUTHMODE_B2C_HIDDEN`).** A ring-DLEQ
  construction (`CNullStakeMofNHiddenAuthProof`,
  `CNullStakeMofNHiddenAuthRingSlotProof`,
  `CreateNullStakeMofNHiddenAuthProof` / `VerifyNullStakeMofNHiddenAuthProof`,
  built by `CreateNullStakeB2CHiddenKernelProofV3`) hides *which* `M` of the `N`
  members signed, at a larger proof size. `EstimateNullStakeB2CHiddenAuthBPACBudget`
  sizes the alternative in-circuit variant. Each tier requires the other tier's
  authorization material to be empty.

Set-size and signer caps (`MAX_NULLSTAKE_MOFN_MEMBERS`,
`MAX_NULLSTAKE_MOFN_SIGNERS` in `zkproof.h`; auth-blob caps in `nullstake.h`) are
enforced before any expensive elliptic-curve work.

### 7.3 Delegation-binding commitment and the cv_plain carve-out

The three-generator commitment `cv3 = value*H + blind*G + delegationHash*J`
(`CreateNullStakeMofNCommitment`) hides the delegation set inside the leaf. The
existing two-generator machinery (range proof, kernel link, nullifier binding)
runs on the *derived* plain commitment `cv_plain = cv3 - delegationHash*J`
(`NullStakeMofNDeriveValueCommitment`), while the FCMP membership proof runs on
`cv3`; a wrong delegation hash yields a `cv_plain` the range proof rejects.
`NullStakeMofNReconstructLeaf` rebuilds `cv3` from a `J`-free value commitment
carried on a private finality vote, so the `J` term never needs to be persisted
in a tally artifact.

At **mint** (tx version 2006), an output may carry a fresh two-generator value
commitment `Vv` (range-proven) plus an Okamoto `(G,J)` link proof
(`CreateNullStakeMofNMintLink` / `VerifyNullStakeMofNMintLink`,
`NULLSTAKE_MOFN_MINTLINK_SIZE = 97`) proving `cv3` and `Vv` carry the same value
— so the value is range-bound while the delegation stays hidden at mint time.

An **owner-override reclaim** (tx version 2007, `CNullStakeReclaimAuth`) lets the
owner recover an idle delegated note after a staking-inactivity timelock: the
owner reveals the set, `M`, and owner pubkey, consensus recomputes
`SetHash(set, M, owner)` and requires it to equal the note's delegation hash, and
the reclaim's mandatory spend-auth signature must use `rk == ownerPubKey`.

Because private-finality validation must anchor deterministically (a node-local
finalized-height anchor would let the same block be valid on some nodes and
invalid on others), NullStake V3 vote/cert validation uses a deterministic
anchor; this is a consensus-critical property of the layer.

---

## 8. NullSend — CoinJoin-style mixing — `nullsend.*`

NullSend is a multi-party mixing protocol (CoinJoin-style): several participants
combine shielded spends and outputs into one transaction so that no external
observer can match a given input to a given output. It coordinates over the P2P
network via `ProcessMessageNullSend`.

A session (`CNullSendSession`, pooled in `CNullSendPool`, driven by the local
`CNullSendClient`) advances through a small state machine: participants announce
via a `CNullSendQueue`, register inputs (`CNullSendInputReg`) and outputs
(`CNullSendOutputReg`), commit and reveal nonces
(`CNullSendNonceCommit` → `CNullSendChallenge` → `CNullSendPartialSig`) to
jointly build the transaction's aggregated binding signature, and finally
broadcast the assembled transaction (`CNullSendBroadcastTx`). Pool sizes run
from `NULLSEND_MIN_PARTICIPANTS` (2) to `NULLSEND_MAX_PARTICIPANTS` (16).

To stop the coordinator from linking a participant's registered input to its
registered output, output registration uses a **Chaumian blind-signature
credential**: the participant blinds a credential, the session RSA-blind-signs it
(`GenerateSessionRSAKey`, `BlindSign`, `NULLSEND_RSA_BITS = 2048`), and the
participant later submits its outputs anonymously with the unblinded credential
(`BlindOutputCredential`, `UnblindSignature`, `SubmitOutputsAnonymously`,
`AssembleTransactionChaumian`). The RSA scheme is hardened against the textbook
multiplicative malleability of naive blind signatures. Per-spend nullifier
binding proofs are carried in the partial-sig messages once
`FORK_HEIGHT_NULLIFIER_BINDING` is active, and the Chaumian path itself is gated
at `FORK_HEIGHT_CHAUMIAN_CJ`. Locally owned sessions (`fLocalOwned`) refuse
remote registration so a self-mix cannot be displaced. `ThreadNullSend` runs the
background timeouts and state advancement.

Because NullSend operates on shielded spend/output descriptions (Section 6), the
mixed value stays inside the shielded pool throughout.

---

## 9. Addressing features

### 9.1 Stealth addresses — `stealth.*`

Stealth addresses let a recipient publish one reusable address while every
payment lands on a fresh, unlinkable one-time output key. `CStealthAddress`
holds a scan pubkey and a spend pubkey (optionally with a prefix bitfield for
lightweight scanning and up to `MAX_STEALTH_NARRATION_SIZE` bytes of narration).
The sender derives a shared secret from an ephemeral key and the recipient's
scan key (`StealthSecret`); the recipient recovers the one-time secret with its
scan and spend secrets (`StealthSecretSpend`, `StealthSharedToSecretSpend`). This
is the older Shadowcoin-derived stealth scheme and predates the diversified
shielded addresses of Section 6.1.

### 9.2 Silent payments — `silentpayments.*`

Silent payments (BIP-352-style) give a reusable static address with *no*
on-chain per-payment metadata and no interaction: the sender derives each output
key from an ECDH shared secret between the transaction's input keys and the
recipient's scan key, tweaked per output index. `CSilentPaymentAddress`
(scan + spend pubkeys, 66 bytes), `CSilentPaymentKey` (scan + spend secrets),
and `CSilentPaymentOutput` are the objects; `ComputeInputPubKeySum` /
`ComputeInputPrivKeySum` form the shared-secret inputs, `ComputeTweak`
(tagged hash `"Innova/silentpayment/tweak"`, rejecting a zero tweak per BIP-352)
derives the per-output tweak, and `DeriveSilentPaymentOutput` /
`DeriveSilentPaymentSpendKey` / `ScanForSilentPayments` produce and detect
outputs. `DeriveSilentShieldedAddress` bridges a silent-payment output into a
shielded diversified address, letting the two systems interoperate.

---

## 10. Dandelion++ propagation — `dandelion.*`

Even a perfectly private transaction leaks metadata if the network can see which
node first broadcast it. Dandelion++ mitigates this by splitting relay into two
phases:

- **Stem phase (`DANDELION_STEM`)** — the transaction is forwarded privately
  along a short randomized line of relays (`DANDELION_STEM_PEERS = 2`,
  `DANDELION_MAX_STEM_HOPS = 10`), so its true origin is hidden among the stem.
- **Fluff phase (`DANDELION_FLUFF`)** — after a randomized per-node timeout
  (`DANDELION_STEM_TIMEOUT_BASE ± JITTER`) or with `DANDELION_FLUFF_PROBABILITY`
  (0.1) at each hop, the transaction diffuses normally to the whole network.

`CDandelionRouter` picks per-epoch stem peers (`UpdateEpoch`,
`DANDELION_EPOCH_DURATION = 600s`, `GetStemPeer`, `OnStemPeerDisconnect`);
`CDandelionState` tracks each transaction's phase (`CDandelionTxState`,
`AddTransaction`, `TransitionToFluff`, `CheckStemTimeouts`) and flags shielded
transactions so they can be handled consistently. The two globals
`dandelionRouter` and `dandelionState` are the entry points from the P2P relay
code. Dandelion++ is orthogonal to the cryptographic layers — it protects the
*origin* metadata that the proofs cannot.

---

## 11. How it fits together

A fully private Innova payment typically composes several of these layers at
once:

1. The recipient is reached via a shielded diversified address, a stealth
   address, or a silent-payment address (Sections 6.1, 9).
2. The output is a shielded note: a Pedersen value commitment with a Bulletproof
   range proof, its commitment inserted into the incremental Merkle tree and the
   curve tree (Sections 2.2, 3.1, 5, 6).
3. Spending it publishes a nullifier and an FCMP++ membership proof over the
   curve tree (or a Lelantus proof), with value conservation enforced by the
   binding signature (Sections 2.2, 4, 5, 6).
4. If the value is staked, a NullStake kernel proof — optionally with M-of-N
   delegation — authorizes a finality vote without revealing the amount
   (Section 7).
5. Multiple participants may combine their spends via NullSend
   (Section 8), and the resulting transaction is relayed through Dandelion++ to
   obscure its origin (Section 10).

Each layer is independently fork-gated (`FORK_HEIGHT_FCMP`,
`FORK_HEIGHT_SERIAL_V2`, `FORK_HEIGHT_NULLIFIER_BINDING`,
`FORK_HEIGHT_CHAUMIAN_CJ`, and the NullStake delegation/hidden-signer gates), so
the privacy stack can be activated and upgraded through coordinated height-gated
transitions while older transaction versions remain valid.
