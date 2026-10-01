# IV5 receiver disclosure

The disclosure mask on an IV5 payload is three bits; each set bit hides a field.
Bit 2 (value 2, `DISCLOSURE_HIDE_RECEIVER`) hides the recipient. Masks 0, 1, 4 and 5
leave it clear and publish the recipient of every output.

## What a receiver disclosure publishes

`prove_receiver` writes the recipient's spend and view keys into the payload and
proves they own the output. That is permanent: anyone reading the chain, now or
later, learns which address received the output.

It is also retroactive for the next spender. The proof publishes `S = view·r_tweak`,
and the output key satisfies `O = spend + tweak·G + y·T` with
`tweak = H(S, r_tweak·G, spend, view, index, input context)`. Every input to that hash
is public in a receiver-disclosed payload, so the sender authority `A = spend + tweak·G`
of whoever later spends that output is computable from chain bytes alone
(`src/privacy_vnext/rust/src/disclosure.rs`, `prove_receiver` / `verify_receiver`).

## How the wallet guards it

- `z_iv5transfer` refuses a mask with bit 2 clear unless its fifth parameter,
  `acknowledge_receiver_disclosure`, is `true`. The refusal and the help text state
  the consequence.
- The Qt send and pay-many paths show the warning in the mask selector and in the
  confirmation dialog, and pass the acknowledgement only after the user confirms.
- The wallet default is mask 7, which discloses nothing.

## Recovering privacy after a disclosure

Spending a receiver-disclosed output through a NullSend round breaks the link going
forward:

- still public: that the disclosed output was spent, by whom (its authority is
  computable), and into which round, because a round's inputs are on chain;
- not public: which of the round's outputs belongs to the spender. The new note is
  unlinkable to the disclosed output, and later spends of it carry no disclosed
  receiver.

The protection is bounded by the round's anonymity set: in a round of `n` seats the
new note is one of `n` outputs. A disclosed output spent directly, outside a round,
links the spender's authority to that spend.
