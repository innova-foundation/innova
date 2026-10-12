Includes everything from v5.0.0.4, which was never published. No consensus change.

- Headless CLI packages (`-cli`) for every platform, next to the Qt builds.
- Wallet rescans up to ~80x faster on large wallets, and resume after a restart.
- No more block-connection stalls on busy nodes (60 s → 6 s worst case).
- Collateral nodes stay known across restarts; nodes catching up keep their announcements.
- `getdaginfo` no longer hangs under DAGKNIGHT.
- macOS disk image starts again; sync faster with `smsg=1`.
