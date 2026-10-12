# Innova v5.0.0.4 release notes

v5.0.0.4 removes the block-connection stalls on busy nodes, keeps collateral nodes known
across restarts, fixes `getdaginfo` for DAGKNIGHT, speeds up wallet rescans and synced
nodes that use secure messaging, and makes the macOS download start. It changes no
consensus rule: every v5.0.0.x node accepts the same blocks.

## Who should upgrade

Everyone. Pool operators, explorers and anything that calls `getdaginfo` should upgrade
before block 8,201,240, where DAGKNIGHT ordering starts.

## Block connection no longer stalls

Building an epoch's state needs DAGKNIGHT anchor state for every block on the selected
chain. Its cache holds 8,192 entries, and once full it scanned all of them on every insert
to find entries to evict; while walking from the start of the DAG none qualified, so every
insert paid a full scan. The cache now drops half its entries in one pass. On the live pool
the longest template wait fell from 60 seconds to 6.

## Collateral nodes survive a restart

A node only learns a collateral node from its signed announcement, and it kept that list
in memory. After a restart it refused blocks paying a collateral node it no longer knew,
and while it was catching up it threw away the announcements that would have taught it.

- Each accepted announcement is now saved to `cnannounce.dat` as received, and replayed
  through the same checks (signature, collateral or attestation against the chain) after
  a restart. A node that restarted knew the collateral node again within 20 seconds.
- Announcements that arrive while the node is catching up are held and checked once it
  reaches the tip, instead of being dropped.

Nothing new is published: the file holds announcements the network already relays, and a
private (attested) collateral node stays unlinkable on chain.

## `getdaginfo` after DAGKNIGHT

Once DAGKNIGHT is active, `getdaginfo` walked the whole selected chain and could hold the
main lock indefinitely, stopping the node. It now reports anchor metrics over the most
recent 128 anchors (`anchor_order_window`) and returns in about 20 ms.

## Faster wallet rescans

A rescan read each block and recomputed its Tribus hash three times. It now checks the
stored header against the block index and the merkle root against the transactions,
which proves the same block without rehashing: about twice as fast on mainnet data. A
rescan also logs its progress and saves its position every 50,000 blocks, so stopping
the wallet mid-rescan resumes where it left off instead of starting again.

## Secure messaging sync

With `smsg=1`, scanning each block for public keys forced a disk sync per block. The key
cache is rebuilt by a rescan, so it no longer syncs per block: 78 to 111 blocks per second
on the same chain data.

## macOS

The v5.0.0.3 disk image did not start: three libraries that the bundled libraries load
(`libboost_atomic`, `libbrotlicommon`, `libsharpyuv`) were missing. The build now copies
every library the app loads into the bundle, and the release fails unless the bundled
daemon starts. The first launch still shows Apple's unidentified-developer warning; open
it with **System Settings > Privacy & Security > Open Anyway**.

## Wallet display

- The status bar no longer reports the last block as thousands of days old when the node
  is busy; it keeps the last time it read.
- The IDAG page shows GHOSTDAG's fixed k (18) before DAGKNIGHT, instead of N/A.

## Verification

- The full unit suite passes.
- DAGKNIGHT rehearsed on two isolated copies of the mainnet chain with the activation
  moved close: blocks accepted across it, both nodes on the same tip, red blocks went to
  zero, restarts worked, and `getdaginfo` answered in 20 ms.
- Measurements above are from mainnet data on the same machine, old build against new.
