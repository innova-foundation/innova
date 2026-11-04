# 5.2.0.4 cloud integration candidate

Branch: `iv5204`. This is an integration candidate, not a validated release.

Both `nyx-v2` (`4be7a039`) and `nyx-v2-c-fixes` (`6a53de7c`) are
merged into this branch's history. Their functionality and session fixes
were already present in the candidate through equivalent or newer changes;
conflicts retain the newer pairing/reset checks, multidevice fanout and
stricter archived-session promotion rules. These merges do not remove the
separate outstanding release requirements below.

Based on `iv5-5204-noE` at `58c4ad4b`: sync rework, cache bound,
Nyx v2 and W10 reorg-depth policy. All commits on `iv5-5204-full`
are already present as patch-equivalent commits in this base; do not merge
that older cherry-picked history again. The excluded Nyx groups fix remains
outside this candidate.

Includes the uncommitted payee rework copied from `iv5-fork` at `31a57ea8`,
including transaction-bound registrations, sequence numbers, unit tests and
the fork regtest. Source worktrees were left unchanged.

## Required work before release

The completed payee re-review (`payee2-review.log`, Nov 4) found:

1. HIGH: `DisconnectBlock` requires persisted collateral state and undo,
   but bootstrap reconstructs only state. Backfill historical undo records
   so upgrading an already-synced post-fork database can reorg through
   pre-upgrade blocks. Add upgrade/reorg regression coverage.
2. MEDIUM: legacy collateral-node startup unconditionally requires
   `BroadcastCNRegistration`, including below activation at 8,790,000 and
   on testnet where activation is disabled. Gate the prerequisite so legacy
   startup works without separate confirmed fee funds and with staking-only
   unlock where it previously did. Add regression coverage.

The previous Dell result was BUILD_FAIL, SUITE_RC=127 and fail=1 for all
listed regtests. Its first compile error was protected `CTxDB::Read` access
in the W10 test. This branch exposes Read through a test-only subclass;
that change still needs compilation and runtime validation.

Build daemon and test binary; run the full unit suite, W10 fork test,
Nyx group/identity/multidevice/multipart/session tests and
`contrib/test/cn_payee_fork_test.sh`, including cross-fork and upgrade/reorg
coverage. Re-review the final payee fixes. Require BUILD_OK, SUITE_RC=0
and fail=0 on every regtest before considering release.

Do not push this candidate to master or tag a release until those checks pass.
