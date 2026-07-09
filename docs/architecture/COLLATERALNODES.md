# Collateralnodes

Collateralnodes are Innova's incentivised service-node tier: full nodes that lock a
fixed amount of INN as collateral, prove ownership of that collateral to the network,
and in return become eligible to receive a share of each block's reward. The tier is
the Innova rename of the Dash-lineage "masternode" concept (the P2P protocol, class
names, and several helper functions still carry `Dsee`/`isee` and `masternode`
naming from that heritage), plus the CoinJoin-style mixing engine (NullSend) that runs
over the same node set.

This document describes the collateralnode subsystem as implemented in
`collateralnode.{h,cpp}`, `collateral.{h,cpp}`, `activecollateralnode.{h,cpp}`,
`collateralnodeconfig.{h,cpp}`, and `rpccollateral.cpp`, together with the
consensus-side payment checks in `main.cpp` and the block-assembly path in
`miner.cpp`.

## What a collateralnode is

A collateralnode is represented in memory by the `CCollateralNode` class
(`collateralnode.h`). Each instance tracks:

- `addr` — the node's advertised `CService` (IP:port).
- `vin` — the `CTxIn` referencing the unspent collateral output that backs the node.
- `pubkey` — the key controlling the collateral (also the default payout key).
- `pubkey2` — the operator/"collateralnode" key used to sign network broadcasts.
- `sig`, `now`, `lastTimeSeen`, `lastDseep` — the signed registration broadcast and
  its timing, used for liveness/expiration.
- `enabled`, `status`, `protocolVersion`, `nRank`, `nBlockLastPaid`, and the
  pay-accounting fields (`payData`, `payCount`, `payValue`, `payRate`).

The global registry is `std::vector<CCollateralNode> vecCollateralnodes` guarded by
`cs_collateralnodes`. Nodes are added, refreshed, and expired as `isee`/`iseep`
broadcasts arrive over the P2P network. A node's minimum protocol version is
`CCollateralNode::minProtoVersion`; liveness constants such as
`COLLATERALNODE_EXPIRATION_SECONDS` (120 min) and `COLLATERALNODE_REMOVAL_SECONDS`
(130 min) govern when a stale entry is dropped.

The locally-operated node (when this daemon is itself a collateralnode) is handled by
the singleton `CActiveCollateralnode activeCollateralnode`
(`activecollateralnode.{h,cpp}`), which owns the state machine that finds the
collateral, proves it, and broadcasts registration and pings.

## The collateral requirement

The collateral amount is a fixed protocol constant defined in `main.h`:

```cpp
inline int64_t GetMNCollateral() { return 25000; }
```

A collateral output must be **exactly 25,000 INN** — `GetMNCollateral() * COIN` — no
more and no less. This exact-value rule is enforced everywhere the collateral is
selected or validated:

- `CActiveCollateralnode::SelectCoinsCollateralnode()` only returns wallet outputs
  whose `nValue == GetMNCollateral()*COIN` (activecollateralnode.cpp).
- `CheckCollateralnodeVin()` rejects any referenced output whose
  `vout.nValue != GetMNCollateral()*COIN` with "specified vin was not a
  collateralnode capable transaction" (collateralnode.cpp).

The collateral is **not spent or transferred** to register — it stays in the
operator's wallet as an ordinary UTXO. Registration merely proves the operator
controls it, and the daemon calls `pwalletMain->LockCoin(vin.prevout)` so the wallet
will not accidentally spend it while the node is running. Spending the collateral
later simply makes the node ineligible; `CheckCollateralnodeVin()` also rejects an
input whose txindex shows it has been spent.

The collateral output must additionally have matured:
`COLLATERALNODE_MIN_CONFIRMATIONS` / `COLLATERALNODE_MIN_CONFIRMATIONS_NOPAY` (15
confirmations) before the node is considered capable.

## Setup and registration

### Configuration

Two configuration surfaces exist:

1. **`innova.conf`** — setting `collateralnode=1` makes the daemon run as a
   collateralnode (`fCollateralNode = GetBoolArg("-collateralnode", false)` in
   `init.cpp`). The operator key is provided via `collateralnodeprivkey`
   (`strCollateralNodePrivKey`), and `collateralnodeaddr` can pin the external
   address if it cannot be auto-detected.

2. **`collateralnode.conf`** — parsed by `CCollateralnodeConfig`
   (`collateralnodeconfig.cpp`). Each non-empty line is whitespace-separated:

   ```
   alias  ip:port  collateralnodeprivkey  collateral_txhash  output_index
   ```

   This file lets one wallet operate several remote ("hot/cold") collateralnodes by
   alias. The parser enforces that the port is `14539` (mainnet) or `15539`
   (testnet); anything else is rejected.

### Bringing a node up

`CActiveCollateralnode::ManageStatus()` drives local activation:

1. Refuses to start until the chain is synced (`COLLATERALNODE_SYNC_IN_PROCESS`).
2. Determines the external `service`, verifies inbound reachability via
   `ConnectNode`, and checks the wallet is present and unlocked.
3. Calls `GetCollateralNodeVin()` → `SelectCoinsCollateralnode()` to locate the
   exact 25,000-INN output, then `GetVinFromOutput()` to recover the key.
4. On success it locks the coin, loads the operator key with `CCollaTeralSigner::SetKey`,
   and calls `Register(...)`, then periodically `Dseep(...)`.

For remote nodes, `EnableHotColdCollateralNode()` and the `start-alias` /
`start-many` RPC paths run the equivalent flow keyed off a `collateralnode.conf`
entry, and can enable a node in the `COLLATERALNODE_REMOTELY_ENABLED` state.

### Network registration protocol

Registration and liveness ride three P2P messages (handled in
`ProcessMessageCollateralnode`, collateralnode.cpp — Innova's rename of Dash's
`dsee`/`dseep`/`dseg`):

- **`isee`** — Innova Election Entry: the full registration broadcast carrying the
  `vin`, address, both pubkeys, the signature, and protocol version. Peers verify the
  collateral (`CheckCollateralnodeVin`) and the signature (`CCollaTeralSigner`), then
  insert/refresh the `CCollateralNode` in `vecCollateralnodes` and relay it.
- **`iseep`** — Election Entry Ping: periodic liveness signed by the operator key;
  rate-limited (`COLLATERALNODE_MIN_DSEEP_SECONDS`, 10 min) and updates
  `lastTimeSeen`.
- **`iseg`** — Election Entry Get: a peer requests the full list or a single entry;
  the node responds with `isee` broadcasts.

## Payment mechanism

### `GetCollateralnodePayment`

The size of a collateralnode's slice of a block is computed by
`GetCollateralnodePayment(int nHeight, int64_t blockValue)` in `main.cpp`:

```cpp
int64_t GetCollateralnodePayment(int nHeight, int64_t blockValue)
{
    if (blockValue <= 0)
        return 0;
    return (blockValue / 100) * 65 + ((blockValue % 100) * 65) / 100;
}
```

This is integer arithmetic for **65% of the block value**, split into a
whole-hundreds term and a remainder term to avoid overflow and round down cleanly.
The collateralnode therefore receives 65% of the block reward and the block producer
(miner for PoW, staker for PoS) keeps the remaining ~35%. `blockValue` is the reward
the payment is carved out of: the PoW subsidy plus fees for PoW blocks, or the
computed coinstake reward (`GetProofOfStakeReward(...)` after `ApplyBlockSizePenalty`)
for PoS blocks.

### Who gets paid — the election

Only one collateralnode is paid per eligible block, chosen deterministically by a
rotation/score election so payouts spread across the active set over time:

- `CCollateralnodePayments::CalculateScore(blockHash, vin)` and
  `CCollateralNode::CalculateScore()` derive a per-node score from the node's `vin`
  hashed against a block hash. The node whose score is furthest from the target wins,
  and recently-paid nodes are de-prioritised (`nBlockLastPaid`, and the
  `COLLATERALNODE_FAIR_PAYMENT_*` fairness window).
- `GetCollateralnodeRanks` / `GetCurrentCollateralNode` / `GetCollateralnodeByRank`
  resolve the current winner.
- `CCollateralnodePayments` (the global `collateralnodePayments`) tracks winning
  payees per height via `CCollateralnodePaymentWinner` records. Winners are gossiped
  (`ProcessBlock` → `Relay`/`Sync`), signed and verified with a network key
  (`Sign` / `CheckSignature`, `SetPrivKey`), and de-duplicated through
  `mapSeenCollateralnodeVotes`. `GetBlockPayee(nHeight, payee)` returns the agreed
  payee script for a height.

### How the payment appears in a block (miner.cpp)

`CreateNewBlock` (miner.cpp) reserves the payout output before finalising the reward:

1. It resolves the winning `payee` for `pindexPrev->nHeight+1` via
   `collateralnodePayments.GetBlockPayee(...)`, falling back to a top-ranked node or a
   burn address if none is known.
2. It appends that payee as an extra coinbase/coinstake output (`payments =
   vout.size()+1`, value initialised to 0).
3. After computing `blockValue`, it sets
   `collateralnodePayment = GetCollateralnodePayment(pindexPrev->nHeight+1, blockValue)`,
   writes it into the reserved output, and **subtracts it from `blockValue`** so the
   producer's own output only receives the remainder. A guard clamps the payment if it
   ever exceeds `blockValue`.

### Consensus validation (main.cpp)

`CheckBlock`/`ConnectBlock` enforce the payment once collateralnode payments are
active. Activation is height-gated:

- Mainnet: enabled when `nHeight > BLOCK_START_COLLATERALNODE_PAYMENTS` (800) **and**
  `nHeight > 2085000`; strict enforcement from `MN_ENFORCEMENT_ACTIVE_HEIGHT` (4500).
- Testnet: gated by `BLOCK_START_COLLATERALNODE_PAYMENTS_TESTNET` and
  `MN_ENFORCEMENT_ACTIVE_HEIGHT_TESTNET` (both 999999 — effectively disabled for the
  clean IDAG public testnet).

When active, the validator recomputes the expected amount with
`GetCollateralnodePayment(...)` and scans the block's coinbase (PoW, `vtx[0]`) or
coinstake (PoS, `vtx[1]`) outputs for one whose `nValue` equals that amount and whose
`scriptPubKey` matches an accepted payee (a registered collateralnode's key, the
anonymous/burn payee `INNXXX…ZeeDTw` on mainnet / `8Test…bCvpq` on testnet, etc.). A
missing payment or payee is a `DoS(100)` rejection ("Couldn't find collateralnode
payment or payee"). Helpers `CheckCNPayment` / `CheckPoSCNPayment` back these checks.

## Interaction with the reward split and PoS/NullStake

The collateralnode payment is a top-slice of the *same* reward the block already
produces — it does not mint new coins. The producer's reward output and the
collateralnode output together sum to the original `blockValue` (see the
`blockValue -= collateralnodePayment` step in miner.cpp).

Important cross-feature interactions:

- **PoW blocks** carve the 65% out of the coinbase (`vtx[0]`); the miner keeps the
  rest.
- **PoS blocks** carve it out of the coinstake (`vtx[1]`); the staker keeps the rest.
- **NullStake / shielded stakes**: when the coinstake is a private-stake transaction
  (`vtx[1].nVersion` is `SHIELDED_TX_VERSION_NULLSTAKE`, `…_NULLSTAKE_V2`, or
  `…_NULLSTAKE_COLD`), the collateralnode payment step is **skipped entirely** — the
  reward goes to the shielded pool and no collateralnode output is required
  (main.cpp, `CheckBlock`). This is deliberate: private staking and the transparent
  collateralnode-payout mechanism are mutually exclusive per block.
- **Post-DAG / finality era**: PoS block *minting* is disabled after the DAG fork and
  stake weight is repurposed for epoch finality voting, so the practical volume of
  collateralnode-bearing PoS blocks is a function of the active consensus regime at a
  given height.

## RPCs

Collateralnode functionality is exposed through `rpccollateral.cpp`, registered in the
dispatch table (`innovarpc.cpp`) as:

- **`collateralnode "command" ( "passphrase" )`** — the main command multiplexer.
  `masternode` is registered as an identical alias for backward compatibility.
- **`getpoolinfo`** — returns the current NullSend/mixing pool state
  (`current_collateralnode`, `state`, `entries`, `entries_accepted`).

`collateralnode`/`masternode` subcommands:

| Subcommand | Purpose |
|------------|---------|
| `count` | Number of known collateralnodes (`vecCollateralnodes.size()`). |
| `current` | Address of the current payment-election winner. |
| `winners` | Payee per height across a window around the tip (`GetBlockPayee`). |
| `genkey` | Generate a new `collateralnodeprivkey` (a `CBitcoinSecret`). |
| `outputs` | List wallet outputs eligible as collateral (exact 25,000-INN coins). |
| `status` | Local node status / `notCapableReason`, plus per-entry network status. |
| `debug` | Human-readable local activation status string. |
| `start` / `stop` | Start/stop the collateralnode configured in `innova.conf` (unlocks the wallet with the optional passphrase argument). |
| `start-alias` / `stop-alias` | Start/stop one node by `collateralnode.conf` alias. |
| `start-many` / `stop-many` | Start/stop every configured node; returns a per-alias result summary. |
| `list` | Print all known collateralnodes. With a mode argument (`active`, `txid`, `pubkey`, `protocol`, `n`, `lastpaid`, `lastseen`, `activeseconds`, `rank`, `roundpayments`, `roundearnings`, `dailyrate`, `full`) selects which field(s) to report. |
| `list-conf` | Dump `collateralnode.conf` entries as JSON. |
| `connect` | Manually connect to a collateralnode address. |
| `enforce` | Report the payment-enforcement time (`enforceCollateralnodePaymentsTime`). |

`start`/`stop` require `collateralnode=1` and will prompt for the wallet passphrase
(second argument) when the wallet is locked.

## Related: NullSend mixing over the same node set

`collateral.{h,cpp}` implements the CoinJoin-style mixing engine (NullSend) that uses
collateralnodes as mixing coordinators. `CCollaTeralPool` (`colLateralPool`) manages
the pool state machine (`POOL_STATUS_*`), standard denominations
(`COLLATERALN_DENOM_10 … _10000`), configurable pool size (`-mixingpoolsize`, clamped
to `POOL_MIN/MAX_TRANSACTIONS_ENHANCED` / `POOL_MAX_TRANSACTIONS_LIMIT`), and mixing
rounds (`COLLATERALN_DEFAULT_MIXING_ROUNDS`, up to `COLLATERALN_MAX_MIXING_ROUNDS`).
`CCollaTeralSigner` provides the message-signing/verification helpers shared with the
registration path, and small "collateral" transactions are used to disincentivise
pool participants from misbehaving. This mixing role is distinct from — but runs on —
the same collateralnode tier described above.

## File map

| File | Responsibility |
|------|----------------|
| `collateralnode.h/.cpp` | `CCollateralNode`, the registry, payment election, `CCollateralnodePayments`, `isee`/`iseep`/`iseg` message handling, `CheckCollateralnodeVin`, `GetCollateralnodeRanks`. |
| `activecollateralnode.h/.cpp` | Local node state machine: collateral selection, `Register`/`Dseep`, hot/cold enable, coin selection. |
| `collateralnodeconfig.h/.cpp` | Parse/maintain `collateralnode.conf` (alias/ip/key/txhash/index). |
| `collateral.h/.cpp` | NullSend mixing pool (`CCollaTeralPool`), signer, queues, denominations. |
| `rpccollateral.cpp` | `collateralnode`/`masternode` and `getpoolinfo` RPCs. |
| `main.cpp` | `GetCollateralnodePayment`, consensus payment checks in `CheckBlock`/`ConnectBlock`, height gates. |
| `miner.cpp` | Reserves and funds the collateralnode payout output during block assembly. |
