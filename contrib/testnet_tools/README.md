# Innova Testnet Audit And Rollout Tooling

These standard-library-only tools collect RPC metrics, audit the four-node v5
fleet, compare consensus state, calculate the schema-V3 activation boundary,
and run explicitly authorized traffic or soak tests. RPC stays on loopback;
remote access is through the existing `innovad` CLI over SSH.

The retired five-seed inventory has been removed. No live command has an
implicit host. `fleet.v3.json` records the same four public VPS
endpoints compiled into the testnet seed list; callers must still select that
file explicitly so a test or audit cannot contact the fleet by accident.

## Fleet inventory

The checked-in `fleet.v3.json` is a credential-free inventory of the
four designated VPS endpoints. Copy it to the operator workspace if local path
or service overrides are needed, and verify the labels, SSH endpoints, and
`p2p_host` values are unique. `p2p_host` must be the host/IP
portion that the other fleet nodes report in `getpeerinfo.addr` (no port); the
same value must appear in that node's `getnetworkinfo.localaddresses`. The
preflight uses both views to bind each SSH/RPC target to its advertised P2P
identity and prove the four nodes are actually connected to each other.
For a soak runner executed on one of those hosts, add `"local": true` to that
node and pass its label as `--active-label`.

Inventory files are configuration, not secret storage. The tools reject common
password, token, and private-key fields. Do not place RPC passwords, SSH private
keys, wallet material, or pasted chat credentials in the JSON.

## Read-only preflight

First rotate any password ever pasted into chat. Create a temporary Ed25519 key,
install only its public half on the four hosts, and pass the private-key path as
an SSH option; verify and preload each VPS SSH host key out of band because the
tools require strict host-key checking. Remove the temporary key from every host
after maintenance.

Collect the converged height/hash, IBD/mining status, binary hashes, epoch-state
health, and the recommended activation height:

```bash
python3 contrib/testnet_tools/v5_testnet_rollout.py \
  --inventory /secure/operator/fleet-v3.json \
  --ssh-option=-i \
  --ssh-option=/secure/operator/id_innova_v3_maintenance \
  --ssh-option='-o UserKnownHostsFile=/secure/operator/known_hosts.innova-v3' \
  --expected-binary-sha256 <preflight-binary-sha256> \
  --artifact-source-commit "$(git rev-parse HEAD)" \
  --output /tmp/v5-testnet-v3-preflight.json
```

Preflight schema v6 has two explicit fail-closed Boundary-B modes and binds the
four-node vNext ABI/parameter/tree/cap/wallet state. It also requires the exact
Boundary-B product contract: disclosure modes 0 through 7, NullStake generations
1 through 3, an eight-layer tree over the full-chain finalized root, post-DAG
staking as finality, and the complete operation set including NullSend. Before the
final Boundary-B candidate exists, omit both Boundary-B calculation arguments;
all four nodes must report the unset height and remain unconfigured/inactive.
For the final two-boundary candidate, add both options to the command above:

```text
  --boundary-a-height <configured-A-height> \
  --boundary-b-candidate-freeze-height <immutable-candidate-freeze-height>
```

The tool then requires all four deployed binaries to report Boundary B
configured at the independently calculated first `60 + 300*k` boundary at
least 900 blocks after both inputs. A mixed fleet, copied-but-invalid arithmetic,
or a configured node without final arithmetic fails preflight.

Run this from the clean commit used to build the deployed binary. Preflight
passes only when all four distinct testnet nodes remain at the same height and
hash across each snapshot, are out of IBD, report no warning, are directly
connected to the other three fleet identities without fleet bans, have
controlled mining paused, expose healthy epoch state, and run the exact expected
binary. It calculates the smallest testnet epoch
boundary `60 + 300*k` at least 900 blocks beyond the common height. For example:

```bash
python3 contrib/testnet_tools/v5_testnet_rollout.py --common-height 430
# activation_height = 1560 (first 60+300*k boundary >= 1330)
```

If the chain advances enough to reduce the 900-block margin before the final
build is deployed, discard the height, rerun preflight, and rebuild.

At each boundary, compare the exact consensus-visible snapshot:

```bash
python3 contrib/test/idag_four_node_differential.py \
  --inventory /secure/operator/fleet-v3.json \
  --ssh-option=-i \
  --ssh-option=/secure/operator/id_innova_v3_maintenance \
  --ssh-option='-o UserKnownHostsFile=/secure/operator/known_hosts.innova-v3' \
  --watch --max-boundaries 4 \
  --output /tmp/v5-four-node-differential.json
```

This gate compares best height/hash, the exact DAG tip set and linear order, the
epoch block list, curve/nullifier/vote roots, certificate, tier, hard streak,
deterministic finalized height, committee state, schema/digest, and mempool.
It also binds the candidate build identifier and compares Boundary A/B,
serializer, migration, legacy-ANON, and privacy-protocol health. Missing RPC
fields or a non-ready migration state fail the gate. In watch mode,
`--max-boundaries` counts
consecutive epoch transitions after the initial snapshot; the command above
therefore records the activation transition and three later boundaries when it
is started in the epoch immediately preceding activation. A skipped or reversed
epoch fails closed instead of silently shortening the observation window.

## Controlled rollout

Public testnet history must be preserved. Do not wipe or recreate its datadirs.

1. Rotate compromised credentials and install the temporary Ed25519 public key.
2. Pause controlled mining and run the read-only preflight above.
3. Confirm all four nodes share height/hash and are out of IBD.
4. Stop each node cleanly and take independently verified data and wallet
   snapshots according to the operator backup policy.
5. Put the calculated height into `GetForkHeightEpochStateV3()`, finish all
   version/source changes, commit them, and build the final candidate from that
   clean commit.
6. Deploy canary-first, never more than one node at a time, then rerun preflight
   with the final binary hash and that commit in `--artifact-source-commit`.
   The candidate's first writable startup atomically migrates finality records
   to the generation-tagged envelope.  That migration is a forward-only
   storage boundary: after it, never start the previous binary against the
   migrated datadir.  A pre-activation rollback must stop the node and restore
   the matching hash-bound chain and wallet snapshots from step 4 before
   restoring the previous binary.
7. Within 24 hours, review and copy the passing preflight JSON to a private path
   outside the source repository. Record only its SHA-256 in
   `docs/v5-release-candidate-manifest.json`; the manifest must never contain an
   audit or evidence path. After the attested source commit, only the manifest
   may change; any source/build change requires a rebuild and a new preflight.
8. Run the four-node differential gate through activation and archive results.
9. Remove the temporary key from every host and the operator workstation.

Before the candidate's first writable startup, rollback may restore the
previous binary directly.  After the finality-record migration, rollback means
restoring the matching pre-migration chain and wallet snapshots together with
the previous binary; a binary-only downgrade is forbidden.  After any V3 block
is accepted, never restore pre-V3 state or downgrade to pre-V3 behavior: stop
mining and deploy a forward fix.

Release publication runs `check_v5_release_policy.py` with an explicit external
evidence file, immutable source artifact, specification-to-code GO attestation,
adversarial-composition GO attestation, and separately supplied private-audit
SHA-256. Every file path must remain outside the checkout and match its manifest
digest. The two review JSON objects must bind the exact source/candidate commits
and artifact hashes and identify distinct reviewers. The checker also fails if
the preflight schema/check set is absent or older than 24 hours, node/P2P
identities are duplicated, manifest/evidence/node binary hashes differ, source
binding changed, testnet V3 remains unset, or activation violates the fixed
boundary arithmetic. It never reads or accepts a path to the private audit;
operators must confirm its GO verdict before supplying its digest.

## Metrics and traffic

Read-only seed audit (four explicit nodes or `--fleet-file` is mandatory):

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py seed-audit \
  --fleet-file /secure/operator/fleet-v3.json \
  --ssh-option='-i /secure/operator/id_innova_v3_maintenance' \
  --output-dir testnet_metrics
```

Render an existing metrics directory:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py report \
  --input-dir testnet_metrics \
  --output testnet_metrics/report.html
```

Traffic-wallet setup derives peers only from `--fleet-file` (or explicit
repeatable `--peer` arguments). Mutating commands still require
`--yes-live-traffic`; use `--dry-run` first. Keep this wallet separate from
mining, committee, and staking wallets.

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py traffic prepare \
  --backend ssh --ssh <traffic-controller> \
  --fleet-file /secure/operator/fleet-v3.json \
  --innovad /usr/local/bin/innovad \
  --dry-run
```

Transparent traffic controls block fill. Privacy, silent-payment, and NullSend
probes are opt-in. The controller backs off on high utilization, growing
mempools, warnings, IBD, low peer count, height divergence, RPC errors, or a
high reject rate.

## Offline checks

These do not contact testnet:

```bash
python3 contrib/testnet_tools/innova_testnet_tool.py selftest
python3 contrib/testnet_tools/v5_testnet_rollout.py --selftest
python3 contrib/test/idag_four_node_differential.py --selftest
python3 contrib/test/check_v5_release_policy.py --selftest
```
