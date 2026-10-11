# Innova v5.0.0.2 release notes

v5.0.0.2 lets a node recover on its own when the computer stopped unexpectedly
(power loss, a crash, a forced restart) while the node was syncing. It changes no
consensus rule: v5.0.0.0, v5.0.0.1 and v5.0.0.2 nodes accept the same blocks.

v5.0.0.1 was tagged but never published (its Windows build failed when MSYS2's Qt
moved to 6.12), so this release also carries everything from v5.0.0.1: the
`getblocktemplate` fields mining pools need after the IDAG fork
(`coinbase_required_outputs`, `coinbase_dag`, `payee_script`) and the
`sweepburnoutputs` RPC. See `docs/release-notes-v5.0.0.1.md` for those changes.

## Who should upgrade

Everyone, and especially anyone still syncing the chain. Pool operators also need
this release for the v5.0.0.1 changes. Without this release, an unexpected stop
during sync can leave a node that refuses to start with "Error loading
blkindex.dat", and the only way back was to sync again from scratch or to restore
a copy of the chain.

## The problem

While syncing, a node writes block data to disk in batches of 500 blocks, but it
records each block in its block index immediately. If the computer stops between
those two steps, the index survives and points at the newest blocks, while their
data never reached the disk. On the next start the node reads those blocks, finds
zeros or a truncated file, and stops with "Error loading blkindex.dat".

## What changed

At startup the node now checks the newest 2,000 blocks of its chain. When it finds
blocks whose data is missing or does not match the index, it starts in **repair
mode** instead of failing:

1. It connects to peers and requests exactly those blocks by hash.
2. It checks that each block matches the index (same hash and merkle root, same
   size as the slot it filled) and writes it back at its recorded position, so
   every index entry stays valid. Nothing else is downloaded again.
3. When every block is back, it shuts down and asks to be started again. The
   restart runs every startup check as usual, now with all block data present.

While in repair mode the node does not process new blocks and skips the startup
steps that read the missing blocks (the DAG plan check, a name index rebuild,
shielded wallet recovery and the wallet rescan). The restart runs them in full.

In the GUI, a message explains the repair and asks you to start Innova again.

## Finding the v5 network

v5 nodes now try `seed.innova-foundation.com` first, a public node on the v5 chain.
The older built-in seeds still run v4, which a v5 node rejects after the IDAG fork,
so a new v5 install could find no peer at all and stay at the last pre-fork block.
On an existing install, add this line to `innova.conf` and restart:

```
addnode=seed.innova-foundation.com
```

`-whitelist` peers are now disconnected when they misbehave instead of banned, and
an existing ban no longer refuses a whitelisted address. A whitelisted address can
stand for many peers, such as a relay in front of a node; banning it cut all of
them off.

## Verification

- Regtest: a node whose newest block data was zeroed, or whose block file was
  truncated, started in repair mode, fetched the missing blocks from its peer, shut
  down, and on restart matched the peer's tip, mined blocks the peer accepted, and
  passed a full block check (`-checkblocks=0`). With the name index also deleted,
  the restart rebuilt it.
- Mainnet data from a node that stopped during sync at height 3,908,943 (45 blocks
  with no data, the last block file ending in zeros): the node repaired all 45
  blocks from a peer and, on restart, loaded and resumed syncing.
- A clean restart flags no blocks.
- A whitelisted peer that reaches the ban score is disconnected and its address is
  not banned (unit test).

## Build

The Windows release build now gives MSYS2's Qt 6.12 qmake the package's install
paths through a `qt.conf`; `docs/BUILD.md` shows the same step for local builds.
