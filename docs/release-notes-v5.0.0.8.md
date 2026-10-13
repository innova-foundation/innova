Mandatory for every v5 node. No consensus change.

- Fixes the halt at block 8,251,440: the first DAG prune left a GHOSTDAG-era block as the DAGKNIGHT frontier, so every new block was refused. Restarting on 5.0.0.8 rebuilds the pruned data from your block files; no resync.
