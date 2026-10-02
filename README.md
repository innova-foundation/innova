# Innova [INN]
Tribus Algo PoW/PoS Hybrid Cryptocurrency

![logo](docs/innova_logo_doxygen.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/innova-foundation/innova/blob/master/COPYING)

[![GitHub version](https://img.shields.io/github/release/innova-foundation/innova.svg)](https://badge.fury.io/gh/innova-foundation%2Finnova)

[![GitHub Commit Activity](https://img.shields.io/github/commit-activity/m/innova-foundation/innova)](https://github.com/innova-foundation/innova/pulse)

[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Finnova-foundation%2Finnova&count_bg=%231283C4&title_bg=%23555555&icon=&icon_color=%231283C4&title=Hits+-+Daily%2FTotal&edge_flat=false)](https://hits.seeyoufarm.com)

![Discord Online Users](https://img.shields.io/discord/391676334956347395?label=Discord&color=%230F80C1)
[![Join Discord](https://img.shields.io/badge/Discord-Chat-blue.svg?logo=discord)](https://discord.gg/mNM59znzNG)

![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/innova-foundation/innova.svg)
![GitHub repo size in bytes](https://img.shields.io/github/repo-size/innova-foundation/innova.svg)

[![Innova downloads](https://img.shields.io/github/downloads/innova-foundation/innova/total.svg?color=blue)](https://github.com/innova-foundation/innova/releases)
[![Innova latest release downloads](https://img.shields.io/github/downloads/innova-foundation/innova/latest/total?color=blue)](https://github.com/innova-foundation/innova/releases)

[![Innova Snapcraft](https://snapcraft.io/innova/badge.svg)](https://snapcraft.io/innova)

[![Github Actions](https://github.com/innova-foundation/innova/actions/workflows/build.yml/badge.svg)](https://github.com/innova-foundation/innova/actions)
[![CircleCI](https://circleci.com/gh/innova-foundation/innova.svg?style=shield)](https://app.circleci.com/pipelines/github/innova-foundation/innova)

<a href="https://x.com/Innova_Fdn"><img src="https://img.shields.io/twitter/follow/Innova_Fdn?style=social&logo=x" alt="follow on X"></a>

[Links](#links)

## Intro

Innova [INN] is an energy-efficient Proof-of-Work (Tribus algorithm, created by
carsenk) and Proof-of-Stake hybrid cryptocurrency with an optional privacy stack.

Ticker: INN

The privacy stack (shielded pool, FCMP++, NullSend, NullStake, silent shielding)
activates with the v5 hardfork. The legacy prototype transaction versions
(2000–2007) are rejected on public networks; the version-2008 envelope that
replaces them activates at Boundary B, height 8,151,540 on mainnet. Until then,
transparent transactions are the public-network path. See
[Privacy & Protocol Innovations](#privacy--protocol-innovations-iips) for the
per-feature status.

## Supported Operating Systems

* Linux 64-bit
* Windows 64-bit
* macOS 10.11+

## Install Innova with Snap on any Linux Distro

* `sudo apt install snapd`
* `sudo snap install innova`

* `innova` for running the QT
* `innova.daemon` for running innovad

## Specifications

* Total number of coins: 18,000,000 INN
* Ideal block time: ~15 seconds (pre-DAG target; ~1 second after the IDAG fork)
* Stake interest: 6% annual static inflation
* Confirmations: 10 blocks
* Maturity: 75 blocks as the wallet reports it — consensus maturity is 65 (`nCoinbaseMaturity`), plus a 10-block wallet safety margin
* Min stake age: 10 hours

* Cost of Hybrid Collateral Nodes: 25,000 INN
* Hybrid Collateral Node Reward: 65% of the current block reward
* P2P Port: 14530, Testnet Port: 15539
* RPC Port: 14531, Testnet RPC Port: 15531
* Collateral Node Port: 14539, Testnet Port: 15539

* INN Magic Number: 0xb73ff4fa
* BIP44 CoinType: 116
* Base58 Pubkey Decimal: 102
* Base58 Scriptkey Decimal: 137
* Base58 Privkey Decimal: 230

## Technology

* Hybrid PoW/PoS Collateral Nodes
* Stealth addresses — retired; existing ones keep working and their funds stay spendable, but new ones are not issued. Superseded by IV5 shielded addresses, which hide the amount and sender as well as the recipient
* Ring signatures (legacy tx version 1000) — rejected from height 0 on testnet/regtest; on mainnet valid until the v5 first gate, height 8,150,040 (IIP-0003)
* Native Optional Tor Onion Node (-nativetor=1)
* Encrypted Messaging (SecureMsg) — optional, disabled by default; enable with `smsg=1`
* Multi-Signature Addresses & TXs
* Atomic Swaps using UTXOs (BIP65 CLTV)
* SLIP-44 coin type 116 registered, so BIP39/BIP44 wallets can derive Innova keys; `innovad` has its own 24-word recovery phrase (`z_exportphrase`/`z_importphrase`) covering the shielded seed and HD-derived transparent keys
* Proof of Data (Image/Data Timestamping)
* ~15 second block times pre-DAG; ~1 second block ordering post-DAG (IDAG)
* Tribus PoW Algorithm comprising of 3 NIST5 algorithms
* Tribus PoW/PoS Hybrid
* Full decentralization
* Hyperfile - IPFS API Implementation for Decentralized File Uploads (UI and RPC)
* Name Value System supporting the IDNS for decentralized blockchain domains

### v5 Consensus Stack

What the v5 fork activates on public networks. Each is a height-gated flag day
on the mainnet ladder (see [IIP table](#privacy--protocol-innovations-iips) for
effective heights); none has activated yet on a mainnet whose tip is ~7.9M.

* IDAG — DAG block-ordering layer for high throughput (~1 second post-DAG)
* Epoch finality — weight-threshold finality gadget with soft/hard tiers
  (no committee by default), transparent-tier voting
* POEM entropy weighting
* IDNS name reset
* Cold staking (P2CS)

Already live on mainnet today, ungated: Dandelion++ transaction-origin privacy
(relay policy, on by default), silent payments, stealth addresses, Proof of Data
timestamping, and the IDNS name-value system.

### v5 Privacy Stack — activates at Boundary B

The legacy envelopes (transaction versions 2000–2007) are rejected on mainnet
and testnet at every height by `IsLegacyPrivacyPolicyDisabled()` (`main.h`). The
unified version-2008 envelope that replaces them activates at Boundary B:
height 8,151,540 on mainnet, the same height as Boundary A
(`FORK_HEIGHT_BOUNDARY_B`, `main.h`).

* Shielded pool — Pedersen commitments, Bulletproofs, and Lelantus-style proofs
* FCMP++ full-chain membership proofs (curve-tree + inner-product argument)
* NullSend — confidential CoinJoin-style transaction mixing
* NullStake — zero-knowledge private staking (V1/V2/V3)
* Silent shielding (the silent-payment/shielded-pool composition)
* Dynamic Selective Privacy — the 3-bit disclosure mask

See [docs/architecture/](docs/architecture/) for the consensus and privacy design
docs; [PRIVACY.md](docs/architecture/PRIVACY.md) and
[CONSENSUS.md](docs/architecture/CONSENSUS.md) both carry the same status caveat.

### Off-chain encrypted messaging (SecureMsg / Nyx)

Innova includes an optional off-chain encrypted messaging channel, **disabled by
default**. Enable it with `smsg=1` in `innova.conf` (or `-smsg` on the command
line) and restart; `-nosmsg` forces it off and overrides `-smsg`.

When enabled, each message is encrypted to the recipient's public key using ECDH
over secp256k1 with AES-256, authenticated with HMAC-SHA256, and carries a small
proof of work. Messages are not routed to a destination — they are flooded to the
whole network and every node stores them for 48 hours, so no relaying peer learns
who a message is for. Nothing touches the blockchain and nothing is retained
after 48 hours.

This is a long-standing part of the wallet and is **not part of Innova's v5
privacy stack**: it shares no code with FCMP++, the shielded pool, stealth
addresses, or silent payments, and it has not had an external cryptographic
review. It does not provide forward secrecy, and it decrypts with your wallet's
own keys — there is no separate messaging identity. It has no group chat or
channels; sending to several people is N independent 1:1 messages. Use it for
convenience, not for information whose disclosure would harm you.

## Privacy & Protocol Innovations (IIPs)

Innova Improvement Proposals (IIPs) formalize all protocol innovations. See [IIP_INDEX.md](docs/proposals/IIP_INDEX.md) for full specifications and the status vocabulary.

Nothing in the v5 ladder has activated on mainnet. Mainnet gate heights are not
literals in the source: every gate returns
`ShiftMainnetV5Activation(base)`, adding `MAINNET_V5_ACTIVATION_SHIFT`
(`src/v5activation.h`, currently 350,040) to its base, so the whole ladder moves
as a unit. The effective heights below are base + shift for the current shift and
are re-derived by the release preflight against a fresh mainnet tip.

| IIP | Title | Status | Mainnet activation |
|-----|-------|--------|--------------------|
| [IIP-0001](docs/proposals/IIP_INDEX.md#iip-0001-cold-staking-p2cs) | Cold Staking (P2CS) | Scheduled | height 8,150,040 |
| [IIP-0002](docs/proposals/IIP_INDEX.md#iip-0002-shielded-transactions) | Shielded Transactions (Pedersen + Bulletproofs + Lelantus) | Scheduled | height 8,151,540 |
| [IIP-0003](docs/proposals/IIP_INDEX.md#iip-0003-ring-signature-deprecation) | Ring Signature Deprecation | Scheduled | height 8,150,040 (mainnet); height 0 on testnet/regtest |
| [IIP-0004](docs/proposals/IIP_INDEX.md#iip-0004-dynamic-selective-privacy) | Dynamic Selective Privacy (8 modes) | Scheduled | height 8,151,540 |
| [IIP-0005](docs/proposals/IIP_INDEX.md#iip-0005-confidential-coinjoin) | Confidential CoinJoin | Scheduled | height 8,151,540 |
| [IIP-0006](docs/proposals/IIP_INDEX.md#iip-0006-fcmp-full-chain-membership-proofs) | FCMP++ Full-Chain Membership Proofs | Scheduled | height 8,151,540 |
| [IIP-0007](docs/proposals/IIP_INDEX.md#iip-0007-silent-payments-and-silent-shielding) | Silent Payments + Silent Shielding | Partly active | silent payments: no gate, live. Silent shielding: height 8,151,540 |
| [IIP-0008](docs/proposals/IIP_INDEX.md#iip-0008-dandelion-network-privacy) | Dandelion++ Network Privacy | Active | no fork height — relay policy, on by default |
| [IIP-0009](docs/proposals/IIP_INDEX.md#iip-0009-nullstake-v1) | NullStake V1 (ZK Private Staking) | Scheduled | height 8,151,540 |
| [IIP-0010](docs/proposals/IIP_INDEX.md#iip-0010-nullstake-v2) | NullStake V2 (Poseidon2 + Bulletproof AC) | Scheduled | height 8,151,540 |

The privacy IIPs above carry a ladder height in the source
(`FORK_HEIGHT_SHIELDED` and its siblings, `main.h`), but reaching it does not
enable them: the transaction versions they ride (2000–2007) are rejected on
mainnet and testnet at *every* height, and their production replacement is the
version-2008 envelope gated on Boundary B, height 8,151,540 on mainnet.

## Links

* [Official Website](https://innova-foundation.com/)
* [Innova on X (@Innova_Fdn)](https://x.com/Innova_Fdn)
* [Innova Discord Chat](https://discord.gg/mNM59znzNG)
* [Innova Telegram Chat](https://t.me/innova_foundation)

## installdaemon.sh

Builds and installs the Innova daemon (`innovad`) on Ubuntu 22.04, 24.04 or 26.04:
installs the build dependencies and Rust, builds the `v5.0.0.0` tag (override with
`INNOVA_REF`), copies `innovad` to `/usr/bin`, and sets up the firewall and swap.
`./installdaemon.sh update` rebuilds an existing checkout.
```bash -c "$(wget -O - https://raw.githubusercontent.com/innova-foundation/innova/master/installdaemon.sh)"```

`bootstrap.sh` replaces the chain data in `~/.innova` with the published bootstrap.

## innovaqtubuntu.sh

Builds the Innova Qt 6 wallet on Ubuntu 22.04, 24.04 or 26.04, from the `v5.0.0.0` tag
by default (override with `INNOVA_REF`).

Credits to Buzzkillb for the original script: https://github.com/buzzkillb/denarius-qt/
```bash -c "$(wget -O - https://raw.githubusercontent.com/innova-foundation/innova/master/innovaqtubuntu.sh)"```

## Development process


Developers work in their own trees, then submit pull requests when
they think their feature or bug fix is ready.

The patch will be accepted if there is broad consensus that it is a
good thing.  Developers should expect to rework and resubmit patches
if they don't match the project's coding conventions (see docs/CONTRIBUTING.md)
or are controversial.

The master branch is regularly built and tested, but is not guaranteed
to be completely stable. Tags are regularly created to indicate new
stable release versions of Innova.

Feature branches are created when there are major new features being
worked on by several people.

From time to time a pull request will become outdated. If this occurs, and
the pull is no longer automatically mergeable; a comment on the pull will
be used to issue a warning of closure. The pull will be closed 15 days
after the warning if action is not taken by the author. Pull requests closed
in this manner will have their corresponding issue labeled 'stagnant'.

Issues with no commits will be given a similar warning, and closed after
15 days from their last activity. Issues closed in this manner will be
labeled 'stale'.
