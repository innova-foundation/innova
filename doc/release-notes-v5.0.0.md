# Innova v5.0.0 release notes

## Upgrade window

v5.0.0 validates every block below the first v5 activation height (8,220,000) the same
way v4.3.9.5 does, including proof-of-stake: v5 nodes stake blocks v4.3.9.5 accepts
and accept blocks v4.3.9.5 stakes. Upgrade before 8,220,000.

Known differences below the activation heights, each needing a deliberately crafted
block or transaction:

- Transactions with version 2000-2008 are parsed as the v5 transaction types and are
  refused. No such transaction exists in the chain's history.
- Two legacy ring-signature transactions in one block that spend the same key image
  are refused (v4.3.9.5 accepts this double spend).
- A legacy ring-signature output that repeats an existing output's public key is
  refused.

## Known limitations

- Note votes (from 8,375,100): a note vote is about 9.4 KB and has 24 blocks to reach
  a miner. On a fast, multi-hop network it can miss that window, and the epoch then
  relies on transparent votes. A point release before 8,375,100 addresses this.
- NullSend: a round can be filled or held open by callers that never complete it, so
  rounds may abort under that load. No funds are at risk; the service is best effort.
- NullSend: notes prepared with `mixprepare` are paid to issued addresses and are
  visible to a viewing key that covers them.
- Cold staking: ordinary sends from the owner wallet can select a delegated output,
  which ends that delegation. Keep delegated funds in a wallet you do not send from.
- The note-vote count includes copies of a vote the DAG skipped, which can only lower
  the transparent settlement budget.
- A viewing key import rescans on the GUI thread; the window is unresponsive until it
  finishes.
