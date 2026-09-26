# v5 finality: what HARD means

Finality in v5 is a participation quorum layered on proof-of-work DAG ordering. It is
not Byzantine fault tolerance, and it carries no stake-weighted security bound.

## The rule

- An epoch is 300 blocks. Votes for an epoch are carried in blocks within
  `FINALITY_VOTE_INCLUSION_WINDOW` (24) blocks of its boundary.
- An epoch's tier is HARD when at least `FINALITY_MIN_VOTERS` (2) distinct voters are
  counted for the boundary block on the chain that carries them.
- A height becomes final after `FINALITY_CONFIRMATION_EPOCHS` (3) consecutive HARD
  epochs. Nodes refuse a reorganization below the finalized height.

Voters come from two lanes:

- **Transparent:** a named staked output of at least 500 INN from the note-vote
  height (the height-keyed floor, `GetFinalityMinVoteWeight`).
- **Note (anonymous):** an op-10 transaction that spends one IV5 note of at least
  500 INN and reissues it; the tally tag is the spent note's key image, so one note
  votes once per epoch. At most `FINALITY_MAX_EPOCH_NOTE_VOTES` (128) note votes count
  per epoch.

Weight does not change the tier. Every counted voter counts once.

## What that means in practice

- Two voters are enough. When almost no one else votes, a single operator holding two
  500 INN notes (or two transparent outputs) can make an epoch HARD on the branch that
  carries those votes. Note votes are anonymous, so nobody can tell they came from one
  party.
- Two branches can each reach HARD if each carries its own voters. Nothing in the rule
  requires a voter to equivocate for that to happen.
- With broad participation, the honest chain carries its own quorum every epoch, and
  the practical protection comes from proof-of-work ordering plus that participation.

This is a deliberate v5 choice: the quorum is kept at 2 and documented rather than
raised. A higher quorum, or one tied to recent participation, is a candidate for a
later release once real participation data exists.

## Change at the note-vote height

From the note-vote height the transparent floor is also 500 INN. A transparent voter
holding less stops counting at that height, so operators should check their voting
outputs before activation.
