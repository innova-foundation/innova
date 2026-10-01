# Innova Documentation

Technical documentation for Innova [INN]. The project [`README.md`](../README.md)
is the landing page; this directory holds the detailed docs.

## Building & releasing

- [BUILD.md](BUILD.md) — building `innovad` and the Innova Qt wallet on Linux, macOS, and Windows
- [RELEASING.md](RELEASING.md) — the GitHub Actions release: versioning, the build and audit matrix, publication on merge to `master`
- [release-notes-v5.0.0.md](release-notes-v5.0.0.md) — v5.0.0.0: activation ladder, RPC reference, wallet migration
- [CONTRIBUTING.md](CONTRIBUTING.md) — code style, the pull-request workflow, and how to run the tests

## Architecture

- [architecture/CONSENSUS.md](architecture/CONSENSUS.md) — Tribus PoW/PoS hybrid, the IDAG DAG-ordering layer, and epoch finality (weight-threshold tiers by default, plus the optional M-of-N tally committee)
- [architecture/PRIVACY.md](architecture/PRIVACY.md) — the privacy stack: shielded pool, Lelantus, FCMP++, NullSend, NullStake, silent payments, Dandelion++
- [architecture/COLLATERALNODES.md](architecture/COLLATERALNODES.md) — collateralnodes: the 25,000 INN collateral, registration, and payments
- [architecture/IV5-PROTOCOL.md](architecture/IV5-PROTOCOL.md) — the IV5 protocol contract
- [architecture/IDNS-RENDEZVOUS.md](architecture/IDNS-RENDEZVOUS.md) — IDNS names and onion rendezvous
- [v5-finality-semantics.md](v5-finality-semantics.md) — what v5 finality guarantees and its limits
- [iv5-receiver-disclosure.md](iv5-receiver-disclosure.md) — IV5 receiver disclosure

## Protocol proposals

- [proposals/IIP_INDEX.md](proposals/IIP_INDEX.md) — index and specifications of the Innova Improvement Proposals (IIPs)

## Operations

- [IPFS_SELF_HOSTED_SETUP.md](IPFS_SELF_HOSTED_SETUP.md) — running a self-hosted IPFS gateway for Hyperfile
- [testnet audit and rollout tooling](../contrib/testnet_tools/README.md) — four-node preflight, schema-V3 activation, differential checks, and guarded traffic

## Other

- [ATTRIBUTION.md](ATTRIBUTION.md) — image/asset license attribution
- [TRANSLATION.md](TRANSLATION.md) — the Qt translation workflow
- `Doxyfile` — Doxygen configuration for the source-level API docs
