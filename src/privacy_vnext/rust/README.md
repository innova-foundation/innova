# Innova privacy-vNext Rust provenance spine

This directory pins the source and dependency inputs for Boundary B without
enabling transaction version 2008. Its exported functions report metadata and
calculate the exact serialized FCMP++ proof size for the fixed eight-layer tree.
There is deliberately no proving, verification, tree mutation, address,
transaction, or wallet API in this crate.

The canonical product contract fixes the intended shape without claiming an
activation: FCMP++ revision
`76399e58bfc7e652d900936f84b3785ea59ab4cd`, eight tree layers, 16-input and
16-output caps, a 256 KiB payload cap, disclosure modes 0 through 7, NullStake
generations 1 through 3, and the required shield, unshield, transfer, NullSend,
three NullStake/private-cold modes, public- and hidden-signer M-of-N, reclaim,
and private-finality operations. `consensus_active` is fixed to zero.

Pinned inputs:

- monero-oxide commit `76399e58bfc7e652d900936f84b3785ea59ab4cd`;
- upstream `Cargo.lock` preserved verbatim in `upstream/Cargo.lock`;
- Rust `1.94.1`, preserved verbatim in both `rust-toolchain.toml` locations;
- registry packages under `vendor/`, selected through `.cargo/config.toml`;
- all upstream tracked source and license material under `upstream/`;
- a deterministic SPDX 2.3 SBOM in `sbom.spdx.json`.

`innova_privacy_vnext_parameter_digest` is SHA-256 of the exact bytes of
`contract/iv5_protocol_v1.json`. It identifies the normative typed protocol;
it is not an activation digest and must not be interpreted as making version
2008 consensus-valid. Proving and verification remain unsupported.

`innova_privacy_vnext_fcmp_proof_size` calls the pinned upstream
`FcmpPlusPlus::proof_size` implementation. It accepts only 1 through 16 inputs
and exactly eight layers, writes one caller-owned `size_t`, and leaves that
output unchanged on any error.

Run the complete local gate with:

```sh
./check.sh
```

The gate checks exact provenance, compiles the C header, and invokes Cargo only
with `--locked --offline`. It also denies Clippy warnings. The selected Rust
toolchain must already be installed; this directory never downloads one as a
build side effect.
