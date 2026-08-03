# Releasing Innova

This document describes how Innova [INN] releases are produced. It replaces the
legacy `doc/release-process.txt`, which described a Bitcoin-era Gitian /
SourceForge flow that Innova no longer uses.

Innova releases are built and published entirely by GitHub Actions. Pushing a
version tag (`vX.Y.Z.B`) to the repository triggers the
`.github/workflows/build.yml` candidate matrix. Tag pushes never publish. After
the protected signing workflow, evidence freeze, reviews, and canary, an
operator may explicitly dispatch publication with the approved signing run ID.

Release policy requires two matching unsigned Linux builders, protected Apple
Developer ID/notarization and Windows Authenticode/RFC3161 signing evidence,
plus separate unsigned and signed package hashes. These controls are internal
engineering assurance; they are not an external security audit or a claim that
unknown defects are absent.

## Version scheme

Innova uses a four-field version, `MAJOR.MINOR.REVISION.BUILD` (for example
`5.0.0.0`). The version is defined in two places that **must** agree:

- `build.properties` — the `release-version=` field (also `snapshot-version=`
  and `candidate-version=`).
- `src/clientversion.h` — the four macros:
  - `CLIENT_VERSION_MAJOR`
  - `CLIENT_VERSION_MINOR`
  - `CLIENT_VERSION_REVISION`
  - `CLIENT_VERSION_BUILD`

The Git tag is the same version with a leading `v`: `vMAJOR.MINOR.REVISION.BUILD`
(for example `v5.0.0.0`).

### How the workflow derives the version

The `get-version` job in `build.yml` computes the version string once and
shares it with every build job:

- On a tag push (`refs/tags/v*`), the version is taken from the tag with the
  leading `v` stripped. **The tag is authoritative** — every produced artifact is
  named after it (e.g. `innova-5.0.0.0-ubuntu2404-x86_64.tar.gz`).
- On a manual `workflow_dispatch` run, the version is read from the
  `release-version=` line in `build.properties`.

Because the tag drives artifact naming on a tag build, but `clientversion.h` is
what gets compiled into the binary's reported version, a mismatch between the
tag and `clientversion.h` produces artifacts whose filename version differs from
the version the binary reports at runtime. Always bump all three (tag,
`build.properties`, `clientversion.h`) together.

## What the workflow builds

`build.yml` triggers on:

- `push` of any tag matching `v*`, and
- `workflow_dispatch` (manual run) with an optional `publish_release` boolean
  input.

On trigger it runs a 13-platform build matrix, each job depending on
`get-version`:

| Job | Runner / container | Artifacts |
| --- | --- | --- |
| `build-ubuntu-2204` | ubuntu-22.04 | daemon + Qt, `.tar.gz` |
| `build-ubuntu-2404` | ubuntu-24.04 | daemon + Qt, `.tar.gz` |
| `build-ubuntu-2604` | `ubuntu:26.04` container | daemon + Qt, `.tar.gz` |
| `build-debian-11` | `debian:11` container | daemon + Qt, `.tar.gz` |
| `build-debian-12` | `debian:12` container | daemon + Qt, `.tar.gz` |
| `build-fedora-40` | `fedora:40` container | daemon + Qt, `.tar.gz` |
| `build-fedora-41` | `fedora:41` container | daemon + Qt, `.tar.gz` |
| `build-archlinux` | `archlinux:latest` container | daemon + Qt, `.tar.gz` |
| `build-linux-arm64` | ubuntu-22.04 (cross) | daemon only, `.tar.gz` |
| `build-linux-arm64-qt` | ubuntu-22.04 + QEMU (`debian:12` arm64) | daemon + Qt, `.tar.gz` |
| `build-linux-armhf` | ubuntu-22.04 + QEMU (`debian:11` armv7) | daemon only (Raspberry Pi), `.tar.gz` |
| `build-macos-arm64` | macos-14 (Apple Silicon) | daemon + Qt `.app`, `.dmg` |
| `build-windows` | windows-latest (MSYS2 MINGW64) | fully static daemon + Qt, `.zip` |

Build notes that the workflow encodes (informational — you do not need to run
these by hand):

- The daemon builds with `USE_NATIVETOR=-` on every platform (OpenSSL 3
  compatibility); Windows additionally builds fully static with `USE_IPFS=1`.
  The armhf and arm64-qt QEMU jobs build with `USE_IPFS=-`.
- Ubuntu 26.04 links against `libdb5.3++-dev` and detects the Berkeley DB
  header/lib/suffix at build time; all other Debian/Ubuntu images use
  `libdb++-dev`.
- Each package job strips the binaries and writes a per-package
  `SHA256SUMS.txt` before archiving.

Every package job verifies its required daemon/GUI outputs and archive, then
uploads with `if-no-files-found: error`. Separate
required audit jobs perform clean Linux builds, return-type/format warning
gates, all 38 compiled test translation units, ASan and UBSan builds,
and local privacy/IDAG/finality integration tests. The same aggregate runs in
the macOS package job.

## How the release is published

The `release` job runs only when an operator explicitly dispatches the workflow
with publication enabled and supplies the completed protected signing run:

```
github.event_name == 'workflow_dispatch'
  && inputs.publish_release
  && inputs.signed_run_id != ''
```

Tag pushes build candidates but never publish them. Before the final dispatch,
run `Sign v5 Desktop Artifacts` with the immutable candidate run ID; its two
jobs require approval in `v5-release-signing` and produce separate notarized
macOS and Authenticode/RFC3161-signed Windows artifacts. The release workflow
accepts those packages only from the operator-supplied signing run ID. It
`needs:` all 13 build jobs plus
`audit-linux-clean`, both `audit-linux-sanitizers` matrix legs,
`audit-regtest`, and `release-policy`, so publication cannot bypass a failed
audit gate. The policy job also refuses release while the public-testnet
schema-V3 height is unset, the release manifest is stale or malformed, or the
manifest hashes and source binding do not match policy. The job uses the
protected `v5-release` environment: `V5_RELEASE_MANIFEST_BASE64`,
`V5_RELEASE_EVIDENCE_BASE64`, and `V5_RELEASE_GATE_EVIDENCE_BASE64` materialize
the schema-v5 candidate manifest, four-node preflight, and signed-artifact/test
gate evidence under `RUNNER_TEMP`, outside the checkout, and
`V5_PRIVATE_AUDIT_SHA256` supplies the independently reviewed audit digest.
The clean audit job exports a deterministic `git archive` of the manifested
source commit, and the policy job downloads it outside the checkout.
`V5_SPECIFICATION_TO_CODE_ATTESTATION_BASE64` and
`V5_ADVERSARIAL_COMPOSITION_ATTESTATION_BASE64` materialize the two protected
internal-review artifacts there as well.
It then:

1. Downloads every build job's artifact and the protected signing run's macOS
   and Windows packages.
2. Requires exactly one of each of the 13 named platform archives, selects the
   signed desktop packages for macOS/Windows, collects them into
   `release-assets/`, and generates an aggregate `SHA256SUMS.txt`.
3. Deletes any pre-existing GitHub release records for the tag
   `v<version>` (so re-runs replace rather than duplicate).
4. Creates the release with `softprops/action-gh-release@v2`:
   - `tag_name: v<version>`
   - `name: "Innova v<version>"`
   - `files: release-assets/*` (all per-platform archives + `SHA256SUMS.txt`)
   - `draft: false`
   - **`prerelease: true`**

> **Note — releases are currently published as pre-releases.** The workflow sets
> `prerelease: true`, so every published release is flagged as a pre-release on
> GitHub. To cut a final (non-pre) release, change `prerelease` to `false` in the
> `release` job of `build.yml`, or edit the release flag in the GitHub UI after
> the run completes.

## Cutting a release

### 1. Pre-release checklist

Before tagging, confirm:

- [ ] **Clean builds** and the complete 38-translation-unit `release-check`
  aggregate pass on Linux and macOS, including all 24 historical/legacy suites.
- [ ] Linux ASan and UBSan audit jobs pass without a sanitizer finding.
- [ ] The full local v5 integration job passes (privacy modes, NullSend smoke,
  IDAG relay/stress, 2-of-3 outage/partition/rotation/restart convergence).
- [ ] Four replacement testnet nodes pass read-only preflight at a common
  stable height/hash with mining paused, direct connectivity to the other three
  fleet identities, and the exact expected binary hash.
- [ ] `GetForkHeightEpochStateV3()` contains the preflight-calculated
  `60 + 300*k` boundary at least 900 blocks past that common height, and
  an external schema-v5 hash manifest is generated only after candidate freeze
  with the evidence hashes, private-audit hash, fork heights, privacy/Rust/Qt
  provenance, signed and unsigned artifact hashes, and commit/build hashes.
- [ ] For the final two-boundary candidate, preflight schema v6 records the
  Boundary-A height and immutable Boundary-B candidate-freeze height. The
  checker independently recomputes the first `60 + 300*k` boundary at least
  900 blocks after both inputs, and all four nodes report Boundary B configured
  at exactly that height (but inactive before it). The same evidence must bind
  disclosure modes 0–7, NullStake generations 1–3, an eight-layer full-chain
  finalized-root membership tree, finality as the post-DAG staking role, and
  the complete canonical operation set including NullSend.
- [ ] The final preflight was generated within 24 hours from a clean source
  commit, names that commit in both `candidate_commit` and
  `source_commit`, and no source/build file changed afterward. Only the
  external manifest may be newer to record the attestation metadata.
- [ ] A plain-tar `git archive` of the exact `source_commit` is retained outside
  the repository. Its SHA-256 equals manifest `source_build_sha256`; the policy
  hashes the supplied file rather than trusting a syntax-only manifest value.
- [ ] The boundary-by-boundary four-node differential gate passes for the
  release candidate.
- [ ] No candidate manifest is committed to the source repository. The external
  schema-v5 manifest contains hashes rather than artifact/audit/review/evidence
  paths and is supplied through `V5_RELEASE_MANIFEST_BASE64`.
- [ ] External release-gate evidence binds the pinned vendored FCMP++ source,
  Cargo lock/toolchain, ABI/parameter digest, selected benchmark cap, Qt
  versions, all 13 unsigned artifacts, signed macOS/Windows packages, signing
  verification, fuzz/replay/crash/performance results, and the 24-hour canary.
  Its digest is in the manifest and its protected value is supplied through
  `V5_RELEASE_GATE_EVIDENCE_BASE64`.
- [ ] The passing preflight JSON is stored outside the source repository, its
  exact SHA-256 is in the manifest, and the protected `v5-release` environment
  contains its base64 representation in `V5_RELEASE_EVIDENCE_BASE64`. The
  manifest `candidate_build_sha256`, preflight `expected_binary_sha256`, and all
  four node `binary_sha256` values are identical.
- [ ] The private audit has one unambiguous GO verdict. Its file remains outside
  the repository; only its SHA-256 is placed in the manifest and protected
  `V5_PRIVATE_AUDIT_SHA256` value.
- [ ] Two distinct internal reviewers independently returned GO: one for
  specification-to-code and one for adversarial Innova composition. Each exact
  JSON attestation is retained outside the repository and hash-pinned in the
  manifest; neither reviewer identity digest is a placeholder and the two
  identity digests differ. This is an internal control, not an external-audit
  claim.
- [ ] **Version bumped and consistent** across `build.properties`
  (`release-version`, and `snapshot-version` / `candidate-version` as
  appropriate) and the four macros in `src/clientversion.h`.
- [ ] **Changelog updated** — the new version's notes are written down (see
  "Release notes" below).
- [ ] Any consensus fork heights intended for this release are set correctly in
  `main.h` (`GetForkHeight*`). A flag-day height-gated fork must ship to the
  whole network before its activation height.
- [ ] Working tree is clean and the intended commit is on the release branch.

Create the exact source artifact outside the checkout before the reviews. The
workflow uses the same plain-tar command:

```bash
source_commit="$(git rev-parse --verify HEAD)"
git archive --format=tar --prefix=innova-v5-source/ \
  --output=/secure/private/innova-v5-source.tar "$source_commit"
```

Run the policy locally with every external artifact and the audit digest:

```bash
audit_sha256="$(shasum -a 256 '/secure/private/v5-internal-security-audit.md' | awk '{print $1}')"
python3 contrib/test/check_v5_release_policy.py \
  --manifest /secure/private/v5-release-candidate-manifest.json \
  --evidence /secure/private/v5-testnet-v3-preflight.json \
  --release-gate-evidence /secure/private/v5-release-gate-evidence.json \
  --source-artifact /secure/private/innova-v5-source.tar \
  --specification-to-code-attestation /secure/private/specification-to-code-review.json \
  --adversarial-composition-attestation /secure/private/adversarial-composition-review.json \
  --private-audit-sha256 "$audit_sha256"
```

The checker rejects the evidence, source-artifact, or review path if either its
supplied location or resolved target is inside the source tree, including
symlinks in either direction. It never accepts an audit path or reads the
private audit. Supplying its digest attests that the operator reviewed the exact
private document whose hash is pinned in the manifest. Obvious synthetic
SHA-256 values made by
repeating one nibble or byte are rejected in both the manifest and preflight
evidence; replace every placeholder with the digest of the real artifact or
observed state before running the policy. Every node height and best hash must
also equal the evidence and manifest common tip. Boundary-B arithmetic is never
trusted merely because the manifest and evidence copied the same values.

Each review attestation is an exact JSON object with schema version `2` and no
extra fields:

```json
{
  "schema_version": 2,
  "review_lane": "specification_to_code",
  "verdict": "GO",
  "reviewer_identity_sha256": "<sha256-of-reviewer-controlled-public-identity>",
  "source_commit": "<exact-manifest-source-commit>",
  "candidate_commit": "<exact-manifest-candidate-commit>",
  "source_build_sha256": "<exact-manifest-source-build-sha256>",
  "candidate_build_sha256": "<exact-manifest-candidate-build-sha256>",
  "privacy_parameter_digest": "<exact-manifest-parameter-digest>",
  "privacy_abi_sha256": "<exact-manifest-abi-sha256>",
  "upstream_gbp_external_audit": false,
  "upstream_gbp_risk_disclosed": true,
  "mainnet_activation_shift": 0,
  "mainnet_trusted_tip_hash": "<fresh-trusted-mainnet-tip-hash>"
}
```

The other artifact uses review lane `adversarial_innova_composition`. Only
materialize a `GO` artifact after that lane actually completes with GO; a
missing artifact or any other verdict is deliberately non-releasable. Use the
SHA-256 of a reviewer-controlled public identity credential (for example a
retained public signing key) as `reviewer_identity_sha256`. The checker verifies
content, digest, candidate/source binding, and reviewer separation; it does not
turn these internal attestations into cryptographic signatures or external
review.

### 2. Bump the version

Edit both files so the version matches the tag you are about to push. For a
`5.0.0.0` release:

`build.properties`
```
snapshot-version=5.0.0.0
release-version=5.0.0.0
candidate-version=5.0.0.0
```

`src/clientversion.h`
```
#define CLIENT_VERSION_MAJOR       5
#define CLIENT_VERSION_MINOR       0
#define CLIENT_VERSION_REVISION    0
#define CLIENT_VERSION_BUILD       0
```

### 3. Commit

```
git add build.properties src/clientversion.h
git commit -m "release: bump version to 5.0.0.0"
git push
```

### 4. Tag and push

The tag must be `v` + the exact version:

```
git tag v5.0.0.0
git push origin v5.0.0.0
```

Pushing the tag triggers `build.yml`. Watch the run under the repository's
Actions tab. Any skipped or failed mandatory audit job is a NO-GO. When every
build, audit, sanitizer, integration, and policy dependency succeeds, the
`release` job publishes the GitHub release (as a pre-release) with all
per-platform archives and `SHA256SUMS.txt` attached.

### 5. Verify

- Confirm the release appears under **Releases** with all expected assets.
- Spot-check that binary filenames carry the intended version.
- Verify at least one archive's checksum against the published
  `SHA256SUMS.txt`.
- Optionally toggle the release off "pre-release" once validated (see the note
  above).

## Manual runs without a tag

To exercise the matrix without cutting a tagged release, start the workflow from
the Actions tab via **Run workflow** (`workflow_dispatch`):

- Leave `publish_release` **unchecked** to build and upload artifacts only (no
  GitHub release is created). The version comes from `release-version` in
  `build.properties`.
- Check `publish_release` to also run the `release` job and publish a release
  for `v<release-version>`. Ensure `build.properties` already holds the version
  you intend to publish.

## Re-running a release

The `release` job deletes existing release records for the tag before creating
the new one, so re-running the workflow for the same tag replaces the release
and its assets rather than erroring or duplicating. To rebuild the same version,
re-run the workflow from the Actions tab, or delete and re-push the tag.
