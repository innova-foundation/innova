Qt wallet fixes and polish. No consensus change.

- Fixes a crash when startup takes longer than two minutes, and a deadlock that froze large wallets at startup.
- Busy and large wallets stay responsive: balances, exports, transaction details and notifications no longer stall the window.
- Staking, statistics and sync screens reflect v5: stake votes on finality, PoW on DAGKNIGHT, accurate sync estimates.
- Dialogs remember their size; the light theme covers chat and the emoji picker.
- `getblock` lists `dagskippedtx`, and transactions left out by a DAG race return to the mempool to be mined again.
