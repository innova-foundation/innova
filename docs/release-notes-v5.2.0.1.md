Hard fork moved to block 8,547,840 to give more time to upgrade. Everyone who installed v5.2.0.0 must upgrade to v5.2.0.1: v5.2.0.0 activates at the old height (8,472,840) and would split from the network. Free migration now runs from block 8,547,840 until block 40,083,840. Everything else in the v5.2.0.0 notes still applies.

- Qt: a private send can no longer be submitted twice; send and migrate show a readable result with a copyable transaction ID.
- Qt: clearer "transaction creation failed" hint; fee errors use your display unit; the BTC total no longer shows two currency symbols.
- Qt: staking tooltip says "staking is disabled" before "wallet is locked", shows the expected reward time correctly for small wallets, and shows weight in INN.
- `walletpassphrase` rejects a timeout of 0, negative, or over 100,000,000 seconds instead of relocking at once.
- The "unlocked for staking only" error says how to unlock for sending.
- `innova-cli` names the host and port when it cannot connect and notes RPC starts only after startup finishes.
- An unknown `-stakingmode` stops startup with an error instead of silently staking transparently; a bad `collateralnode.conf` is reported as a warning.
- `getinfo` no longer prints a stray line or returns an empty `ip` when the Tor hostname file is missing.
- Help text: `getstakinginfo` lists its fields; `z_shieldall` documents the 50-input cap; free-migration help reads its end margin from the code.
- Crash fixes: the wallet no longer aborts at launch from a static-initialization order bug, or when it cannot create its data folder; Nyx file download/upload no longer crash on failure or when the window closes mid-transfer; the block explorer no longer crashes during sync, on missing blocks, or on some transactions.
