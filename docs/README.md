# Innova Documentation

Technical documentation for Innova [INN]. The project [`README.md`](../README.md)
is the landing page; this directory holds the detailed docs.

## Building & releasing

- [BUILD.md](BUILD.md) — building `innovad` and the Innova Qt wallet on Linux, macOS, and Windows
- [RELEASING.md](RELEASING.md) — the GitHub Actions release flow (tag a `v*` version → CI builds and publishes)
- [CONTRIBUTING.md](CONTRIBUTING.md) — code style, the pull-request workflow, and how to run the tests

## Architecture

- [architecture/CONSENSUS.md](architecture/CONSENSUS.md) — Tribus PoW/PoS hybrid, the IDAG DAG-ordering layer, and epoch finality with the M-of-N committee
- [architecture/PRIVACY.md](architecture/PRIVACY.md) — the privacy stack: shielded pool, Lelantus, FCMP++, NullSend, NullStake, silent payments, Dandelion++
- [architecture/COLLATERALNODES.md](architecture/COLLATERALNODES.md) — collateralnodes: the 25,000 INN collateral, registration, and payments

## Protocol proposals

- [proposals/IIP_INDEX.md](proposals/IIP_INDEX.md) — index and specifications of the Innova Improvement Proposals (IIPs)

## Operations

- [IPFS_SELF_HOSTED_SETUP.md](IPFS_SELF_HOSTED_SETUP.md) — running a self-hosted IPFS gateway for Hyperfile

## Other

- [ATTRIBUTION.md](ATTRIBUTION.md) — image/asset license attribution
- [TRANSLATION.md](TRANSLATION.md) — the Qt translation workflow
- `Doxyfile` — Doxygen configuration for the source-level API docs
