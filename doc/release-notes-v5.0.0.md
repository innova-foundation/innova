# Innova v5.0.0.0 release notes

Innova [INN] is a Tribus-algorithm Proof-of-Work / Proof-of-Stake hybrid chain. v5
adds a DAG ordering layer (IDAG), epoch finality, a second-generation shielded
pool (IV5), NullSend mixing, IDNS Tor names, and private collateral node
registration. This document is for node operators, exchange and pool operators,
and wallet users upgrading from the v4.3.9.5 series.

## 1. Summary of v5

- **IDAG DAG ordering.** From the DAG activation height, blocks are produced by
  proof-of-work and ordered by a GHOSTDAG-style rule (DAGKNIGHT ordering from a
  later height); block production is 1-second-target from that height on, and
  proof-of-stake block production ends there. `getdaginfo` reports the live
  ordering algorithm, DAG tips, and adaptive block-size state.
- **Epoch finality.** 300-block epochs collect two kinds of votes: transparent
  votes from a staked output, and anonymous note votes that spend and reissue an
  IV5 note. An epoch is HARD once at least 2 distinct voters are counted for its
  boundary block; a height finalizes after 3 consecutive HARD epochs. See
  `doc/v5-finality-semantics.md` for the full rule and its limits - this is a
  participation quorum, not Byzantine fault tolerance, and weight does not affect
  the tier.
- **IV5 private transactions.** A new transaction type (versions 2000-2008)
  carries FCMP++ membership proofs over a curve tree instead of one-time ring
  signatures. Notes move by `z_iv5transfer`, an internal transfer with a
  three-bit disclosure mask; nothing about a private transfer is transparent
  unless the mask says so.
- **NullSend mixing.** A per-tier CoinJoin-style mixing service for IV5 notes:
  `mixprepare` sets aside a note at a fixed denomination, a coordinator plans a
  round with `mixcoordinate`, and seats join with `mixjoin`. Coordination runs
  over Tor rendezvous directories reached through a SOCKS5 proxy.
- **IDNS names.** The name system (`name_new`, `name_update`, ...) gains
  Tor rendezvous descriptors: `name_rendezvous_encode` builds a v3 onion
  descriptor for a name's value, and `name_rendezvous` classifies and optionally
  dials one without ever learning or printing the service's IP address.
- **Collateral nodes, including private registration.** The existing
  `collateralnode` command gains a private registration path:
  `registerprivate` attests a 25,000 INN IV5 note as collateral,
  `announceprivate` relays the announcement, `statusprivate` reports its chain
  and local state, and `releaseprivate` deregisters it. The key image a private
  registration publishes is permanent and one-shot: a note can be registered
  exactly once, ever.
- **Viewing keys.** `z_exportiv5viewingkey` and `z_importiv5viewingkey` let a
  third party (an auditor, an exchange, a payer) see incoming payments to
  covered addresses without being able to spend or see outgoing activity.
  Watch-only value is reported separately from owned balance.
- **Holds.** `z_holdiv5note` sets aside one IV5 output so no ordinary spend and
  no note vote can select it; used to protect a note pending its own use (a
  private collateral registration, a manual send).
- **24-word recovery phrase.** `z_exportphrase` returns the wallet's IV5 seed as
  a 24-word BIP39 phrase. The same phrase, via `z_adoptphrase`, can also cover
  the wallet's transparent addresses going forward.
- **Qt6 wallet.** The desktop wallet is rebuilt on Qt 6, with new pages for
  IDAG status, staking (including cold staking and NullStake), and privacy
  (sending, migration, collateral nodes, NullSend, holds, and finality status).

## 2. Upgrade requirement and activation schedule

**All nodes must upgrade to v5.0.0.0 before the first mainnet gate.** Below the
first activation height, v5.0.0.0 validates and stakes exactly as v4.3.9.5 does:
v5 nodes stake blocks v4.3.9.5 accepts, and accept blocks v4.3.9.5 stakes. A
node that has not upgraded before the first gate will fork off the network once
that height passes.

Known differences below the activation heights, each needing a deliberately
crafted block or transaction (none exists in the chain's history):

- Transactions with version 2000-2008 are parsed as v5 transaction types and are
  refused.
- Two legacy ring-signature transactions in one block that spend the same key
  image are refused (v4.3.9.5 accepts this double spend).
- A legacy ring-signature output that repeats an existing output's public key is
  refused.

### Mainnet activation heights

Print the ladder your own binary will enforce with:

```
innovad -datadir=<your datadir> -printactivations
```

This prints every gate height, the network it resolves against, and the helper
that computes it, without starting the daemon proper. Run it before the first
gate to confirm your build agrees with the table below.

| Height | Gate |
| --- | --- |
| 8,220,000 | Tighter drift tolerance; collateral node payment validation; cold staking; ring-signature deprecation |
| 8,230,000 | Shielded pool; nullifier binding |
| 8,235,000 | DSP |
| 8,240,000 | NullSend; FCMP |
| 8,245,000 | NullStake v1 |
| 8,250,000 | NullStake v2 |
| 8,255,000 | NullStake v3 |
| 8,260,000 | Chaumian CoinJoin |
| 8,290,000 | Serial v2 |
| 8,320,000 | IDNS reset |
| 8,340,000 | Millisecond timestamps |
| 8,360,000 | PoEM |
| 8,365,000 | Finality |
| 8,370,000 | DAG: 1-second blocks, proof-of-stake block production ends, supply cap, epoch state |
| 8,370,300 | Boundary A/B; IV5 fee note (IV5 unshield retires at this height) |
| 8,375,100 | IV5 note votes |
| 8,420,000 | DAGKnight ordering |

## 3. Wallet migration

Do this in order. Steps 1-4 can be done as soon as you have upgraded; step 5
needs the shielded pool gate (8,230,000) and step 6 needs the IV5 pool active
(Boundary B, 8,370,300) on the network you're using.

### 3a. Headless (`innovad` / `innova-cli`)

1. **Back up `wallet.dat`** before touching anything.
2. **Encrypt the wallet**, if it is not already:
   ```
   innova-cli encryptwallet "<passphrase>"
   ```
   The daemon restarts itself after this. `z_createiv5seed` refuses to run on an
   unencrypted wallet (checked in source: `CWallet::CreatePrivacyVNextSeed`
   requires `IsCrypted()`).
3. **Unlock fully** (not for-staking-only):
   ```
   innova-cli walletpassphrase "<passphrase>" 300
   ```
4. **Create the IV5 seed**:
   ```
   innova-cli z_createiv5seed
   ```
   This only allocates key material; note-carrying transactions remain inactive
   until the network reaches the shielded-pool gate.
5. **Write down the recovery phrase**:
   ```
   innova-cli z_exportphrase
   ```
   returns `phrase` (24 words), `words` (24), `shielded_addresses_issued`,
   `transparent_hd`, and `transparent_keys_not_covered`. The phrase restores
   every IV5 note this wallet can ever hold, plus every transparent address
   *derived from it*. It does **not** restore transparent keys created before
   the phrase was adopted (drawn at random) - those still need the
   `wallet.dat` backup from step 1.
6. **Extend the phrase to transparent addresses**:
   ```
   innova-cli z_adoptphrase
   ```
   From this point, new transparent addresses derive from the seed and are
   covered by the phrase. Existing random transparent keys keep working but are
   still not covered.
7. **Once the shielded pool is active on your network**, move transparent coins
   into the IV5 pool. Two ways to do it:
   - **Whole-wallet migration**, looping until done:
     ```
     innova-cli z_migratetopool
     ```
     Sends one transaction per transparent address (never spending from two, so
     the migration does not link addresses), up to `maxtransactions` (default
     10) per call. Call it in a loop while the result's `more` field is `true`;
     `complete` is `true` once nothing transparent is left. An address whose
     value does not cover the flat shield fee is skipped and reported under
     `skipped`, and is not retried automatically.
   - **Per-address sweep**:
     ```
     innova-cli z_shieldall [fromaddress] [maxinputs]
     ```
     Shields one address per call (the largest-holding one, if you omit
     `fromaddress`); the whole selected value moves, with no transparent
     change output. `remaining` reports unspent outputs still at that
     address, so a caller can loop it too.
8. **Check totals** at any point:
   ```
   innova-cli z_gettotalbalance
   ```
   returns `transparent`, `shielded` (spendable now), `shielded_pending`
   (owned but not yet spendable - too shallow, or waiting for the epoch that
   gives it a tree position), `shielded_collateral`, `shielded_held`, `total`
   (everything owned), and `shielded_watchonly` (value seen through an
   imported viewing key - not owned, not in `total`).
9. **Keep the `wallet.dat` backup** from step 1 until every legacy transparent
   address it holds is empty.

### 3b. Restoring on another machine

```
innova-cli z_importphrase "<24 words>" [addressindexcount] [rescan=true]
```
Restores the IV5 seed and adopts the transparent HD chain from the phrase, then
rescans. Refused if the target wallet already holds a seed - restore into a
fresh wallet. `addressindexcount` is a hint, not a requirement: the rescan
looks past it and moves forward as it finds notes.

### 3c. Qt wallet

The same steps, through the GUI:

1. **File > Backup Wallet...** first.
2. **Settings > Encrypt Wallet...** if not already encrypted.
3. Unlock fully when prompted (or **Settings > Unlock Wallet...**).
4. **Settings > IV5 Seed...** opens the seed dialog: **Create seed**, then
   **Export** (hex, for backup) or use **Settings > Show Recovery Phrase...**
   for the 24-word form. The seed dialog also has **Cover transparent
   addresses** (the GUI's `z_adoptphrase`), and an **Export/Import viewing
   key** section.
5. **Settings > Show Recovery Phrase...** / **Restore from Phrase...** are the
   dedicated 24-word dialogs (reveal, or restore into a wallet with no seed
   yet).
6. Once the pool is active, use the **Privacy** page's **Migrate** tab: a mode
   selector between **Migrate everything** (`z_migratetopool`, looped) and
   **Migrate one address** (`z_shieldall`).
7. The **Overview** page's balance panel adds rows for shielded (with a
   "+pending" note when value is owned but not yet spendable),
   collateral-locked, held, and watch-only balances, alongside the existing
   transparent balance.

## 4. Token/coin migration explanation

Migrating a transparent output moves its value into the IV5 pool as a new note,
recorded on-chain as a v2008 shield transaction (`z_shieldall` /
`z_migratetopool`) with a Bulletproof range proof and Pedersen commitment. The
transparent input and the fact that a shield happened are visible; the note's
subsequent spends inside the pool are not, unless a disclosure mask says
otherwise.

**Timing.** A freshly shielded or migrated note is owned as soon as its
transaction confirms, but it is not *spendable* until the epoch containing it
is finalized and its commitment has a position in the current tree - this is
the `shielded_pending` figure in `z_gettotalbalance`. There is no way to spend
a note ahead of that; the wallet and the RPCs simply do not count it as
spendable balance until then.

**Fees.** Shielding uses the flat shielded transaction fee (`MIN_TX_FEE_SHIELDED`,
retried upward only if the built transaction needs more to relay). Internal IV5
transfers (`z_iv5transfer`) report their own `fee` field per call.

**No unshield.** `z_iv5unshield` exists for moving value back to a transparent
address, but it is retired once the IV5 fee note gate activates (height
8,370,300, Boundary A/B): `CWallet::CreatePrivacyVNextUnshield` refuses every
call from that height on with "IV5 unshield is retired at height ...". This is
permanent - there is no path back to a transparent output from the pool after
that height. A disclosure mask of 0 on `z_iv5transfer` (publishing sender,
receiver and amount) is the closest equivalent to a transparent transaction,
but the value stays inside the pool as a note.

**Disclosure masks.** `z_iv5transfer`'s `disclosure` argument is a three-bit
mask, default 7 (discloses nothing). Clearing bit 1 publishes the spending
authority of each consumed note; bit 2 publishes each output's recipient
address; bit 4 publishes each output's amount. Everything a disclosure
publishes is proved against what the transaction already commits to - a
disclosure cannot claim a different address or amount than the one actually
used. Clearing bit 2 (publishing the recipient) is permanent and retroactive:
the recipient address is written in the clear, and the spending authority of
whoever later spends that output becomes computable from chain data. The RPC
refuses that mask unless you pass `acknowledge_receiver_disclosure=true`.

## 5. New and changed RPC reference

RPC names, arguments and behavior below come directly from each command's help
text and the code backing it (`src/rpcshielded.cpp`, `src/rpcwallet.cpp`,
`src/rpcblockchain.cpp`, `src/rpcmining.cpp`, `src/rpccollateral.cpp`,
`src/namecoin.cpp`, `src/innovarpc.cpp`). Run `innova-cli help <command>` for
the full text at any time.

### Seed & recovery

- `z_createiv5seed`: creates the wallet's encrypted generation-1 IV5 seed.
  Requires an encrypted, unlocked wallet.
- `z_exportiv5seed`: returns the seed as 64 hex characters, plus the number of
  addresses issued under it.
- `z_importiv5seed <seedhex> [addressindexcount] [rescan=true]`: restores an
  exported seed into a wallet that has none; refused if one already exists.
- `z_exportphrase`: returns the wallet's 24-word recovery phrase (the same
  secret as `z_exportiv5seed`, in BIP39 form).
- `z_importphrase "<24 words>" [addressindexcount] [rescan=true]`: restores a
  wallet from its phrase; also adopts the transparent HD chain.
- `z_adoptphrase`: starts deriving transparent addresses from the existing
  seed, so the phrase covers them from then on.
- `z_rescaniv5 [fromheight]`: reprocesses IV5 payloads from a height, default
  the wallet's recorded scan gap. The recovery path after a seed import or a
  block missed while locked.
- `z_getnewiv5address`: returns a new generation-1 IV5 address.

### Migration & balances

- `z_shieldall [fromaddress] [maxinputs]`: shields one transparent address's
  coins into the IV5 pool per call.
- `z_migratetopool [maxtransactions] [maxinputspertx]`: sweeps the whole
  wallet, one transaction per address, bounded per call (loop on `more`).
- `z_getbalance [address]`: spendable shielded balance (IV5 notes plus any
  legacy shielded notes).
- `z_gettotalbalance`: transparent and shielded balances, broken into
  spendable, pending, collateral-locked, held, total, and watch-only.
- `getv5migrationinventory true`: a full, read-only replay inventory of the
  active chain for migration accounting. **Pauses block connection for the
  duration**; the explicit `true` argument acknowledges that. This is a
  diagnostic/audit tool, not a routine operator command.

### Private transfers & holds

- `z_iv5transfer <toaddress> <amount> [disclosure] [hold] [acknowledge_receiver_disclosure]`: spends IV5 notes to another IV5 address, purely inside the pool (no
  transparent input or output). See section 4 for the disclosure mask.
- `z_holdiv5note <txid:index> <true|false>`: places or releases a hold on one
  IV5 output; a held note is skipped by ordinary spends and note votes.
- `z_listiv5holds`: lists this wallet's held IV5 outputs and their amounts.
- `z_iv5unshield <toaddress> <amount>`: spends notes back to a transparent
  address. Retired from height 8,370,300 (Boundary A/B / IV5 fee note); see
  section 4.

### Viewing keys

- `z_exportiv5viewingkey [address|"all"]`: exports a viewing key for one or
  all issued addresses. It sees incoming payments and amounts, never spends,
  and never sees spends, change, shields or vote reissues.
- `z_importiv5viewingkey <viewingkey> [rescan=true] [startheight=0]`: imports
  a viewing key; matching notes show as watch-only, never spendable, and are
  reported under `shielded_watchonly`.
- `z_listiv5viewingkeys`: lists imported viewing keys, the addresses each
  covers, and the watch-only notes found so far.

### NullSend

- `mixprepare <denomination>`: prepares one shielded note for a NullSend
  tier (an ordinary transfer to this wallet of the denomination plus one
  seat's fee share, held until used).
- `mixcoordinate "<address>" <denomination> <seats>`: runs one round as
  coordinator under a wallet address's key: plans it, publishes its rendezvous
  record, and serves its announcement.
- `mixjoin "<coordinator>" <recordslot>`: takes a seat in the round a
  coordinator's record authorizes.
- `mixstatus`: this node's running or joined rounds, and its directory state.
- `mixlistrounds ["directory"]`: asks configured (or one named) mix
  directories for every round still open to join.
- `mixnotes ["round"]`: every note of a tier's size, whether it can take a
  seat, and (given a round id) whether it is eligible for that round.
- `mixsettings`: current and next-start NullSend settings, and whether a
  restart is required to apply a pending change.
- `mixsetsetting "<name>" "<value>"`: changes one NullSend setting
  (`mixdir`, `mixproxy`, `mixonion`, `mixcoordinatorport`,
  `mixdirectoryport`) and persists it to the mix settings file.
- `mixproxystatus`: whether the configured SOCKS5 proxy is reachable and
  answering as SOCKS5, with round-trip latency.
- `mixcancel <id> [force]`: cancels a running seat by its `mixstatus` id.
- `mixclear`: removes finished (done/failed/cancelled) seats from
  `mixstatus`.

### Collateral nodes

- `collateralnode collateral-notes`: lists IV5 notes that could back a
  private registration.
- `collateralnode registerprivate <endpoint> <iv5payout> [txhash:index]
  [confirm]`: attests a 25,000 INN IV5 note as this node's collateral. Prints
  a preview unless the last argument is the literal word `confirm`. The key
  image published is permanent and one-shot.
- `collateralnode announceprivate`: announces a confirmed private
  registration to peers once it has enough confirmations.
- `collateralnode statusprivate`: chain, local-list, and payment view of a
  private registration, including whether its bound configuration still
  matches what was attested.
- `collateralnode releaseprivate <keyimage>`: releases a held collateral note
  back to ordinary spending. Deliberately deregisters the node; the note's key
  image can never be registered again.

### Finality & staking

- `getfinalityinfo`: PoS finality gadget status: current epoch, finalized
  height/hash, vote counts and tier, plus `note_votes` for the private lane.
- `getepochinfo [epoch]`: a DAG epoch's boundary, root hashes, finality tier,
  and counted note-vote tags (current epoch if omitted).
- `isblockfinalized <hash>`: whether a block is at or below the finalized
  height.
- `getstakinginfo`: staking status, including whether PoS block production is
  still active (`pos_block_production`, false past the DAG height) and
  `finality_voting`.
- `getfinalitystakinginfo`: transparent finality-voter status for the
  post-DAG voter: eligible weight and UTXOs against the current epoch.
- `getcoldstakinginfo`: cold staking status: enabled/fork height, this
  wallet's cold-staking balance, and staker/owner key counts held.

### Chain/DAG info

- `getdaginfo`: DAG consensus state: active/fork heights, tip count, ordering
  algorithm (GHOSTDAG or DAGKnight, and when each applies), adaptive block-size
  limits, and epoch/finality summary fields.
- `getdagtips`: the current DAG tip block hashes, each with height, time,
  blue/red color and score.
- `getdagorder [count]`: the DAG's linear ordering of blocks from the best
  tip, default 100 blocks (1-1000).
- `getdagconfidence <blockhash> [comparehash]`: DAGKnight confidence
  information for a block, or pairwise ordering confidence between two blocks.
  Requires DAGKnight to be active.

### Diagnostics

- `-printactivations` (startup flag, not an RPC) - prints the full activation
  ladder as JSON and exits without starting the daemon proper.
- `getblockprofile [reset]`: per-phase block-connect timings; requires
  `-blockprofile` at startup.
- `getv5migrationinventory true`: see "Migration & balances" above; pauses
  block connection while it runs.
- `submitfinalitytallyshare` / `submitfinalitytallycert`: regtest-only,
  for deterministic finality testing.
- `name_rendezvous <name> [connect]`: classifies a name's value as a
  conventional record or a Tor rendezvous descriptor, and optionally dials it
  through `-idnssocks` (reports only success/failure; never prints an IP).
- `name_rendezvous_encode <onionhost> <port>`: builds the canonical
  rendezvous descriptor value for a v3 onion service, for use as a
  `name_new`/`name_update` value.

## 6. Using the Qt6 wallet

The wallet is rebuilt on Qt 6. New and changed screens:

- **Settings menu**: **IV5 Seed...** (create/export/import the seed, extend it
  to transparent addresses, export/import a viewing key), **Show Recovery
  Phrase...** and **Restore from Phrase...** (the 24-word dialogs).
- **Overview page**: balance panel adds shielded (with a "+pending" note),
  collateral-locked, held, and watch-only rows alongside the transparent
  balance.
- **Privacy page** (sidebar):
  - **Send**: send from the pool with a disclosure-mask selector, and pay
    several recipients at once.
  - **Migrate**: mode selector between migrating everything
    (`z_migratetopool`) and one address (`z_shieldall`).
  - **Addresses**: this wallet's IV5/shielded addresses.
  - **Collateralnode**: guided setup (carve a 25,000 INN note), list
    attestable notes, register/preview a node, check status, announce, and
    release.
  - **NullSend**: mix service settings (directories, proxy), prepare a note,
    find and join rounds, and track running rounds.
  - **Holds**: list and release held IV5 outputs.
  - **Finality**: current epoch, tier and finalized-height status.
- **Staking page** (sidebar): **Transparent**, **NullStake** (V1/V2
  private staking), **Cold Staking** (delegate coins to a staking VPS), and
  **Private Cold Stake** (NullStake V3 private delegation).
- **IDAG page** (sidebar): DAG status summary (height, tips, entries, ordering
  algorithm, inferred k, adaptive block limit and utilization, best tip/score,
  finality tier, epoch) and a recent-activity table.
- **Collateral Nodes page** (sidebar): the existing collateral-node manager,
  for the transparent registration and monitoring path.
- **Terms of Use**: updated to describe the v5 wallet and the recovery phrase.

## 7. Headless usage quick start

Typical `innova.conf` entries for a node or seed:

```
server=1
rpcuser=<user>
rpcpassword=<strong password>
staking=1
```

Start the daemon, then check status:

```
innovad -daemon
innova-cli getinfo
innova-cli getdaginfo
innova-cli getfinalityinfo
```

A typical first-time wallet sequence, once synced:

```
innova-cli encryptwallet "<passphrase>"
innova-cli walletpassphrase "<passphrase>" 600
innova-cli z_createiv5seed
innova-cli z_exportphrase
innova-cli z_adoptphrase
```

After the shielded pool activates on your network:

```
innova-cli z_migratetopool
# repeat while "more" is true
innova-cli z_gettotalbalance
```

Confirm the activation ladder your binary enforces:

```
innovad -printactivations
```

## 8. Known limitations

- NullSend: a round can be filled or held open by callers that never complete
  it, so rounds may abort under that load. No funds are at risk; the service is
  best effort.
- NullSend: notes prepared with `mixprepare` are paid to issued addresses and
  are visible to a viewing key that covers them.
- Cold staking: ordinary sends from the owner wallet can select a delegated
  output, which ends that delegation. Keep delegated funds in a wallet you do
  not send from.
- The note-vote count includes copies of a vote the DAG skipped, which can only
  lower the transparent settlement budget.
- A viewing key import rescans on the GUI thread; the window is unresponsive
  until it finishes.
- `z_iv5transfer` spends at most 16 notes. When the 16 largest notes do not
  cover the amount it reports insufficient spendable balance; send a smaller
  amount to yourself first to merge notes.
- Epoch finality is a 2-voter participation quorum, not a stake-weighted
  Byzantine-fault-tolerant threshold. See `doc/v5-finality-semantics.md` for
  what HARD does and does not guarantee.
- `z_iv5unshield` is retired outright from height 8,370,300 onward: there is no
  path back to a transparent output from the IV5 pool after that height (see
  section 4).

## 9. Build and verification

Build instructions for Linux, macOS and Windows, including dependencies and
the reference CI workflow, are in `docs/BUILD.md`.

Each release attaches a `SHA256SUMS.txt` covering every published platform
archive. Verify a downloaded binary against it before running it:

```
shasum -a 256 -c SHA256SUMS.txt
```

### Opening the desktop builds

The macOS and Windows packages of this release are not signed by a commercial
certificate. Verify them against `SHA256SUMS.txt` first, then:

- macOS: the app is ad-hoc signed. On first launch, right-click `Innova.app`,
  choose Open, and confirm. If macOS still blocks it, run
  `xattr -dr com.apple.quarantine /Applications/Innova.app` once.
- Windows: SmartScreen may show "Windows protected your PC". Choose More info,
  then Run anyway.
