# Contributing to Innova

Thanks for your interest in improving Innova (INN). Innova is an MIT-licensed,
open-source Tribus-algorithm Proof-of-Work / Proof-of-Stake hybrid chain. This
document describes the coding conventions, the branch-and-pull-request workflow,
and how to build and test the daemon and Qt wallet before you propose a change.

## Code style

Innova follows the coding conventions inherited from its Bitcoin/PPCoin/Denarius
lineage, described in `doc/coding.txt`. Please stay consistent with the
surrounding code; a diff that matches the existing style is easier to review.

### Formatting

- **ANSI / Allman brace style.** Opening braces go on their own line, aligned
  with the statement they belong to.
- **4-space indentation, no tabs.** Configure your editor to expand tabs to
  spaces.
- **No extra spaces inside parentheses.** Write `if (fReady)`, not
  `if ( fReady )`.
- **No space after a function name; one space after `if`, `for`, and `while`.**

```cpp
bool ConnectBlock(CBlock& block, int nHeight)
{
    // Comment summarising what this section of code does
    for (int i = 0; i < nHeight; i++)
    {
        // When something fails, return early
        if (!CheckSomething())
            return false;
    }

    // Success return is usually at the end
    return true;
}
```

### Naming

Variable names begin with a lowercase type prefix, then a capitalized word
(`nSomeVariable`, not `someVariable`). Common prefixes:

| Prefix | Meaning |
| ------ | ------- |
| `n`    | integer (`int`, `unsigned int`, `int64_t`, `uint64_t`, char-as-number) |
| `d`    | `double` / `float` |
| `f`    | flag (boolean) |
| `hash` | `uint256` |
| `p`    | pointer or array (one `p` per level of indirection) |
| `psz`  | pointer to a null-terminated string |
| `str`  | string object |
| `v`    | vector or similar list |
| `map`  | map or multimap |
| `set`  | set or multiset |
| `bn`   | `CBigNum` |

### Comments

Prefer clear, neutral prose that explains *why* a section of code does what it
does. Use Doxygen-style comments (`/** ... */` for blocks, `///` or `//!` for
inline members) on public functions, classes, and non-obvious consensus rules so
the documentation can be extracted and cross-referenced.

```cpp
/**
 * Validate an epoch finality certificate against the active committee.
 *
 * @param cert   the certificate to check
 * @param nEpoch the epoch the certificate claims to finalize
 * @return true if the certificate meets the 2/3 signing threshold
 */
bool VerifyFinalityCert(const CFinalityCert& cert, int nEpoch);
```

### Locking

The core is multi-threaded and protects shared state with mutexes and the
`CRITICAL_BLOCK` / `TRY_CRITICAL_BLOCK` macros. Keep lock ordering consistent to
avoid deadlocks (for example, always take `cs_main` before `cs_wallet`). You can
build with `-DDEBUG_LOCKORDER` to have lock-order inconsistencies reported in
`debug.log`. See `doc/coding.txt` for more detail.

## Git and pull-request workflow

1. **Fork and branch.** Create a topic branch off `master` with a short,
   descriptive name (for example `finality-cert-fixes` or `wallet-fee-rounding`).
   Do not commit directly to `master`.
2. **Keep commits focused.** One logical change per commit. Write commit
   messages in precise, neutral engineering language: describe the concrete
   effect of a defect and the fix (for example, "incorrect supply accounting let
   a coinstake-shaped tx bypass the value-balance check"). Prefer plain
   bug-report phrasing over dramatized wording.
3. **Open a pull request against `master`.** Explain what the change does, why it
   is needed, and how you verified it. Reference any related issues.
4. **CI must pass.** Every tagged release and pull request is built across the
   platform matrix defined in `.github/workflows/build.yml` (Ubuntu 22.04 /
   24.04 / 26.04, Debian 11 / 12, Fedora 40 / 41, Arch, linux-arm64, linux-armhf,
   macOS-arm64, and Windows via MSYS2). A pull request will not be merged until
   the build is green on all platforms.
5. **Consensus changes.** Changes to consensus code (`main.cpp`, `kernel.cpp`,
   `dag.cpp`, `finality.cpp`, and related headers) receive extra scrutiny.
   New rules that change block validity must be gated behind a fork height (see
   the `GetForkHeight*` helpers in `main.cpp`) so existing nodes are not split
   before the activation point.

## Building and testing

Innova builds with the standard makefiles under `src/`, or with the `qmake`
project files (`innova.pro`, `innova-qt.pro`) for the Qt wallet.

### Daemon (`innovad`)

```sh
cd src
make -f makefile.unix        # Linux
# make -f makefile.osx       # macOS
# make -f makefile.mingw     # Windows / MSYS2
```

The default USE flags are `USE_LEVELDB=1 USE_UPNP=1 USE_NATIVETOR=1
USE_IPFS=1`. On systems with OpenSSL 3 (including the Qt builds in CI), native
Tor is disabled with `USE_NATIVETOR=-`. On Ubuntu 26.04 the BerkeleyDB C++
headers come from `libdb5.3++-dev`; other distributions use `libdb++-dev`.

### Qt wallet (`Innova`)

```sh
qmake innova-qt.pro
make
```

### Running the test suite

The unit tests build into the `test_innova` binary and run on Linux:

```sh
cd src
make -f makefile.unix test_innova
./test_innova
```

Please run the suite and confirm it passes before opening a pull request. Add or
update tests to cover the behavior you change, especially for consensus,
staking, and wallet code.

## Architecture

For an overview of the major subsystems — the UTXO ledger, P2P networking, the
PoW/PoS hybrid consensus, the v5 IDAG DAG-ordering and epoch-finality layer, the
optional privacy features (shielded pool, NullSend, stealth addresses,
NullStake), and collateralnodes — see the design notes under
[`docs/architecture/`](architecture/). Start there before making structural
changes so your contribution fits the existing component boundaries.

## License

By contributing, you agree that your contributions are licensed under the MIT
License, the same terms as the rest of the project (see `COPYING`).