# Releasing Innova

This document describes how Innova [INN] releases are produced. It replaces the
legacy `doc/release-process.txt`, which described a Bitcoin-era Gitian /
SourceForge flow that Innova no longer uses.

Innova releases are built and published entirely by GitHub Actions. Pushing a
version tag (`vX.Y.Z.B`) to the repository triggers the
`.github/workflows/build.yml` workflow, which compiles the daemon and Qt wallet
across a matrix of platforms and then publishes a GitHub release with a tarball
(or `.dmg` / `.zip`) per platform plus an aggregate `SHA256SUMS.txt`.

There is no Gitian, no deterministic-build ceremony, no detached-signature
upload step, and no SourceForge. The release maintainer's job is to bump the
version, land a changelog, and push a tag.

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

Every job uploads its archive with `actions/upload-artifact`.

## How the release is published

The `release` job runs only when:

```
startsWith(github.ref, 'refs/tags/v')
  || (github.event_name == 'workflow_dispatch' && inputs.publish_release)
```

That is: it publishes automatically on a `v*` tag push, or on a manual run only
if `publish_release` was checked. It `needs:` all 13 build jobs, so it runs after
the entire matrix succeeds. It then:

1. Downloads every build job's artifact.
2. Collects all `*.tar.gz`, `*.dmg`, and `*.zip` files into `release-assets/`
   and generates an aggregate `SHA256SUMS.txt` over them.
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

- [ ] **Clean build** of the daemon and Qt wallet on at least one target
  (staging Linux; macOS cannot run `test_innova`). Consensus/finality changes
  should have their test suites green.
- [ ] **Version bumped and consistent** across `build.properties`
  (`release-version`, and `snapshot-version` / `candidate-version` as
  appropriate) and the four macros in `src/clientversion.h`.
- [ ] **Changelog updated** — the new version's notes are written down (see
  "Release notes" below).
- [ ] Any consensus fork heights intended for this release are set correctly in
  `main.cpp` (`GetForkHeight*`). A flag-day height-gated fork must ship to the
  whole network before its activation height.
- [ ] Working tree is clean and the intended commit is on the release branch.

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
Actions tab. When the matrix finishes, the `release` job publishes the GitHub
release (as a pre-release) with all per-platform archives and `SHA256SUMS.txt`
attached.

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
