Includes v5.0.0.4 and v5.0.0.5, which were never published. No consensus change.

- Blocks back to ~1 s: an epoch's block order now comes from a bounded window instead of the whole DAG, removing stalls that grew every day. Identical results on all 309 mainnet epochs.
- Headless CLI packages (`-cli`) for every platform, next to the Qt builds.
- Wallet rescans up to ~80x faster on large wallets, and resume after a restart.
- Collateral nodes stay known across restarts.
- `getdaginfo` no longer hangs under DAGKNIGHT; the macOS disk image starts; faster sync with `smsg=1`.
