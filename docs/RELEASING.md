# Releasing Innova

This document describes how Innova [INN] releases are produced. It replaces the
legacy Bitcoin-era Gitian / SourceForge release process, which Innova no longer
uses.

Innova releases are built and published entirely by GitHub Actions
(`.github/workflows/build.yml`, "Build & Release Innova"). The workflow runs on
every push to `master`, on push of a `v*` tag, and on manual
`workflow_dispatch`. A push to `master` or a `v*` tag auto-publishes a GitHub
release once the full build and audit matrix passes, unless the head commit
message carries `[release:none]`. There is no separate manual
signing or policy gate in front of publication; see "How the release is
published" below for what does gate it.

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

`contrib/versioning/stamp-version.sh A.B.C.D` writes the version into both of
those plus `innova-qt.pro`, `CMakeLists.txt`, and `snapcraft.yaml`. The release
workflow calls it automatically on the common path (see below), so a manual
edit is only needed when pushing an explicit tag.

The Git tag is the same version with a leading `v`: `vMAJOR.MINOR.REVISION.BUILD`
(for example `v5.0.0.0`).

### How the workflow derives the version

The `get-version` job runs `contrib/versioning/next-version.sh`, which computes
the version once and shares it with every other job:

- On a tag push (`refs/tags/v*`), the version is the tag with the leading `v`
  stripped, and the release always publishes. **The tag is authoritative** —
  every produced artifact is named after it (e.g.
  `innova-5.0.0.0-ubuntu2404-x86_64.tar.gz`). Because the tag drives artifact
  naming but `clientversion.h` is what gets compiled into the binary's
  reported version, bump `build.properties` and `src/clientversion.h` to match
  *before* pushing the tag.
- On `workflow_dispatch`, the bump level comes from the `bump` input (default
  `build`); the release publishes only if `publish_release` is checked.
- On any other push (i.e. to `master`), the bump level comes from a
  `[release:major|minor|patch|build|none]` marker in the head commit message,
  else the `DEFAULT_RELEASE_BUMP` repository variable (default `build`); the
  release publishes unless the level is `none`.

When a level is chosen (anything but a tag push), the next version is the
latest `v*` tag plus that bump — except that if `release-version` in
`build.properties` is already above the latest tag, that version is released
as-is (this is how the first release of a new line, e.g. `5.0.0.0`, happens).
Once a version is decided this way and the run will actually publish, the
script stamps it via `contrib/versioning/stamp-version.sh`, commits
`release:[change] vX [release:none]` when that changes any file, pushes that commit to the triggering
branch, tags `vX`, and pushes the tag — all before the build matrix runs, so
every build job and the eventual release reference the stamped commit. A
`workflow_dispatch` run with `publish_release` unchecked skips this stamping
entirely: it only computes a version for artifact naming and touches nothing
in the repository.

## What the workflow builds

On every trigger, 12 platform build jobs run, each depending on `get-version`:

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
| `build-linux-arm64` | ubuntu-22.04-arm | daemon only, `.tar.gz` |
| `build-linux-arm64-qt` | ubuntu-22.04-arm (`debian:12` arm64 container) | daemon + Qt, `.tar.gz` |
| `build-macos-arm64` | macos-14 (Apple Silicon) | daemon + Qt `.app`, `.dmg` |
| `build-windows` | windows-latest (MSYS2 UCRT64) | fully static daemon + Qt, `.zip` |

Build notes that the workflow encodes (informational — you do not need to run
these by hand):

- The daemon builds with `USE_NATIVETOR=-` on every platform; Windows
  additionally builds fully static with `USE_IPFS=1`.
- Ubuntu 26.04 detects the Berkeley DB header/lib/suffix at build time and
  links against whatever `libdb_cxx*`/`libdb5.3++-dev` provides; the other
  Debian/Ubuntu images use `libdb++-dev`.
- Each package job strips the binaries and writes a per-package
  `SHA256SUMS.txt` before archiving, then uploads with
  `if-no-files-found: error`.

Three more jobs are required release/audit gates, all depending on
`get-version`:

- `audit-linux-clean` — static checks (`contrib/test/v5_release_gate.sh
  --static-checks`), a clean warning-gated build and the `release-check` test
  aggregate. It also materializes an immutable `git archive` of the built
  commit as an artifact.
- `audit-linux-sanitizers` — matrix over `address` and `undefined`: a clean
  sanitizer build, two targeted `test_innova` runs
  (`range_proof_malformed_ipa_point_returns_false_without_crash`,
  `nullstake_mofn_kernel_proof_create_verify`), and the `release-check`
  aggregate.
- `audit-rust-vnext` — installs the pinned Rust `1.94.1` toolchain, restores
  `vendor/` with `CARGO_NET_OFFLINE=false cargo vendor --locked
  --versioned-dirs --sync upstream/Cargo.toml`, then runs
  `src/privacy_vnext/rust/check.sh` with `INNOVA_DIFF_STRIDE=1024` and
  optimized test builds (`CARGO_PROFILE_DEV_OPT_LEVEL=3`).

The multi-node regtest suites (`contrib/test/v5_release_gate.sh
--integration`) are timing-sensitive and run locally before a release, not on
shared CI runners.

## How the release is published

The `release` job runs whenever `get-version` reports `release == true`: on
every `master` push without `[release:none]`, on every `v*` tag push, and on a
`workflow_dispatch` run with `publish_release` checked. It `needs:` all 12
build jobs plus `audit-linux-clean`, both `audit-linux-sanitizers` matrix legs,
and `audit-rust-vnext`, so a failed or skipped required job
blocks publication.

It then:

1. Downloads every build job's artifact.
2. Rebuilds the vendored-crate archive (`cargo vendor --locked
   --versioned-dirs --sync upstream/Cargo.toml`) and packs it as
   `innova-<version>-rust-vendor.tar.zst` for air-gapped reproduction.
3. Requires exactly one of each of the 12 named platform archives, collects
   them into `release-assets/`, and generates an aggregate `SHA256SUMS.txt`.
4. If a release already exists for tag `v<version>`, deletes it only when
   `replace_existing_release` was set to that exact tag; otherwise the job
   refuses and fails rather than silently replacing a published release.
5. Creates the release with `softprops/action-gh-release@v3`:
   - `tag_name: v<version>`, `target_commitish:` the stamped commit
   - `name: "Innova v<version>"`
   - `files:` the 12 archives, `SHA256SUMS.txt`, and the rust-vendor archive
   - `draft: false`, `prerelease: false`, `make_latest: true`

Release notes come from `docs/release-notes-v<version>.md`, or
`docs/release-notes-v<A.B.C>.md` when the build field is `0`; otherwise the
body falls back to the git log since the previous tag (commits marked
`[release:none]` excluded).

Signing macOS (Developer ID + notarization) and Windows (Authenticode +
RFC3161) packages is a separate, manual workflow,
`.github/workflows/sign-v5-desktop.yml`, dispatched against a completed
build run's `candidate_run_id`. It is not a dependency of `release` and its
signed output is not substituted into the automatic release — a published
release ships the unsigned desktop packages the build jobs produced unless an
operator separately distributes the signed artifacts.

## Cutting a release

Most releases need no manual steps: merging to `master` publishes one, bumped
by `build` by default. To choose a different bump, skip a release, or release
a specific version:

- [ ] Any consensus fork heights intended for this release are set correctly in
  `main.h` (`GetForkHeight*`). A flag-day height-gated fork must ship to the
  whole network before its activation height.
- [ ] Add `[release:major]`, `[release:minor]`, `[release:patch]`,
  `[release:build]`, or `[release:none]` to the head commit message pushed to
  `master` if the default `build` bump (or a release at all) isn't wanted.
- [ ] If release notes beyond the auto-generated git log are wanted, write
  `docs/release-notes-v<version>.md` (or the `A.B.C` form when the build field
  is `0`) before the version is tagged.
- [ ] Working tree and PR are otherwise ready to ship — the workflow handles
  version stamping, tagging, and publishing itself.

### Tagging a specific version directly

```bash
# Bump build.properties and src/clientversion.h first. [release:none] keeps the
# commit push from starting a second release before the tag does.
git add build.properties src/clientversion.h
git commit -m "release:[change] v5.0.0.0 [release:none]"
git push
git tag v5.0.0.0
git push origin v5.0.0.0
```

Pushing the tag triggers `build.yml`. Watch the run under the repository's
Actions tab. When every build and audit job succeeds, the `release` job
publishes the GitHub release with all per-platform archives, `SHA256SUMS.txt`,
and the rust-vendor archive attached.

### Verify

- Confirm the release appears under **Releases** with all expected assets.
- Spot-check that binary filenames carry the intended version.
- Verify at least one archive's checksum against the published
  `SHA256SUMS.txt`.

## Manual runs without a tag

To exercise the matrix without a `master` push or a tag, start the workflow
from the Actions tab via **Run workflow** (`workflow_dispatch`):

- Leave `publish_release` **unchecked** to build and upload artifacts only; no
  commit, tag, or GitHub release is created. The version is `bump` applied to
  the latest tag (or `release-version` in `build.properties`, if that's
  already ahead of the latest tag), for artifact naming only.
- Check `publish_release` to also run the `release` job: this stamps and
  commits the version, tags it, and publishes a release for it.

## Re-running a release

If a release already exists for the target tag, the `release` job refuses to
touch it unless `replace_existing_release` is set to that exact tag (e.g.
`v5.0.0.0`); only then does it delete the existing release records before
creating the replacement. Re-dispatch the workflow with that input set, or
delete and re-push the tag.
