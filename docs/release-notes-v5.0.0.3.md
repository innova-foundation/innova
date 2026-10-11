# Innova v5.0.0.3 release notes

v5.0.0.3 makes block templates fast enough for the 1-second block target. It changes
no consensus rule: every v5.0.0.x node accepts the same blocks.

## Who should upgrade

Pool operators and solo miners. Other nodes may upgrade at their convenience.

## The problem

To pick the parent of a proof-of-work template, the node compared every entry in its
block index, more than 8 million on mainnet, each time the tip moved. Building the
first template after a new block took about 2 seconds, so a pool spent most of each
1-second block on a stale job and blocks arrived every 3 to 5 seconds however low the
share difficulty was set.

## What changed

The node keeps the set of block index entries that nothing builds on yet, and walks
back from those only while a block can still beat the current best. Chain trust never
falls along a chain, so this reaches every block the full scan could have picked and
returns the same parent.

## Verification

- On mainnet data, the first `getblocktemplate` after a new block took 0.056 s on
  average (0.127 s at most) against 1.98 s on v5.0.0.2.
- On the live pool, blocks came every 0.86 s on average over 553 blocks (3 to 5 s
  before), the pool sent each new job 0.06 s after a block, no block was rejected,
  and network difficulty began rising to hold the 1-second target.
- A unit test builds random block trees with side branches and random eligibility
  and checks that the walk picks the same parent as a full scan, and that the leaf
  set stays exact as entries are added and removed.
