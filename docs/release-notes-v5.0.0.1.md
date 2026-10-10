# Innova v5.0.0.1 release notes

v5.0.0.1 lets mining pools build valid blocks after the IDAG fork. It changes no
consensus rule: nodes that do not serve a pool or an external miner through
`getblocktemplate` do not need to upgrade, and v5.0.0.0 and v5.0.0.1 nodes accept
the same blocks.

## Who should upgrade

- **Pool operators and anyone mining through `getblocktemplate`** (stratum
  servers such as YIIMP or NOMP, or custom miners). Upgrade the node your pool
  reads templates from, then update the pool's coinbase builder as described
  below.
- Wallet users, stakers, solo miners using `setgenerate`, and exchanges: optional.
  This release also corrects the build guide (`docs/BUILD.md`).

## The problem

From the IDAG fork, a block's coinbase must carry outputs that depend on node
state, and the network rejects a block without them:

- the IMTS millisecond-timestamp commitment (required from the first v5 gate);
- the IDAG parent commitment, naming the block's DAG parents;
- at one block per 300-block epoch, the settlement payouts to that epoch's
  finality voters, whose value is part of the block's `coinbasevalue`.

The node's coinbase also carries finality votes, tally shares, and certificates.
They are not required for validity, but finality depends on votes reaching the
chain, so a block that drops them delays finality.

v5.0.0.0's `getblocktemplate` exposed none of these outputs. A pool that built its
own coinbase from `coinbasevalue` and `payee` produced blocks the network
rejected.

## What changed

`getblocktemplate` returns two new fields:

- `coinbase_required_outputs`: every output of the node's coinbase other than
  the miner payout and the collateral node payment, in order, as
  `[{"script": "<hex>", "value": <satoshis>}, ...]`.
- `coinbase_dag`: the IDAG commitment script from that list, or an empty string
  before the DAG fork.

## Building the coinbase

1. Pay the collateral node `payee_amount` to `payee`, as before.
2. Pay the pool `coinbasevalue - payee_amount - (sum of every value in
   coinbase_required_outputs)`.
3. Append each entry of `coinbase_required_outputs` unchanged: same script, same
   value.

Do not add an IMTS or IDAG output of your own when using the list; it already
contains both, and a block must carry exactly one IMTS commitment. A pool that
already copies `coinbase_dag` and writes its own IMTS output keeps producing
valid blocks outside settlement heights, but it should switch to the list to pay
settlements and carry votes.

## Verification

A regtest run built blocks the way a pool does, from the template alone, for
every height from just before an epoch boundary through that epoch's settlement.
Pool-built blocks were accepted before the DAG fork, at the fork height, and
after it, and a peer node followed them. Finality votes reached the chain
through the pool-built blocks. The epoch's settlement block, also pool-built,
paid both voters. A pool block that kept the settlement value for itself was
rejected, as were blocks missing the IMTS or IDAG commitment, or carrying a
tampered IDAG commitment.
