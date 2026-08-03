# IV5 Migration Inventory

`getv5migrationinventory true` is the read-only source of migration
classification evidence. It holds `cs_main` for one active-chain snapshot,
reads every block from genesis through the reported tip, and fails rather than
returning a partial result.

The replay independently records:

- Version-1000 anonymous outputs, canonical historical key images, created
  value, spent value, and the remaining aggregate.
- Old-format version-2000 through version-2007 transaction, spend, output, and
  pool-delta totals.
- Prototype spends accepted before nullifier-binding enforcement versus spends
  carrying a binding proof after enforcement.
- A digest of every active block and a separate digest of every migration
  source transaction.

Any remaining prototype pool with a pre-binding spend is classified
`no_go_ambiguous_prototype`. A remaining version-1000 pool requires the exact
historical-output/key-image claim path. A remaining bound prototype pool
requires the selected private adapter. Zero balances require neither verifier.

Run the RPC against trusted, fully validated mainnet and testnet datadirs, store
the complete JSON results outside the source repository, then combine them:

```sh
python3 contrib/test/v5_migration_classification.py \
  --input "$V5_MAINNET_INVENTORY" \
  --input "$V5_TESTNET_INVENTORY" \
  --output "$V5_MIGRATION_CLASSIFICATION"
```

CON-002 remains unverified until both external snapshots and their underlying
datadir/source/binary identities are signed into the immutable evidence bundle.
