# IV5 normative protocol contract

Status: normative and consensus-inactive.

The exact machine-readable source of this contract is
`src/privacy_vnext/contract/iv5_protocol_v1.json`. Its SHA-256 identifies the
protocol contract used by the inactive ABI-v1 metadata scaffold. It does not
activate any transaction. Boundary B remains invalid until ABI v2, the selected
benchmark caps, the final parameter digest, proving and verification, state
integration, wallet support, review, and activation are complete.

## Envelope

After the common transaction header, every new IV5 transaction carries:

```text
ff 49 56 35 50 || uint16_le(1) || CompactSize(payload_length) || payload
```

The bytes after `ff` spell `IV5P`. `payload_length` must use the shortest
CompactSize form and may not exceed 262,144 bytes. The payload must end exactly
at the declared boundary. Old-format versions 2000 through 2007 remain
decode-only for historical replay. The new marker is collision-free because a
historical payload starts with a bounded vector count no greater than 16.

New-marker 2000 through 2007 and version 2008 are invalid before Boundary B.
After B, all use IV5 keys, the vNext tree, this payload, and the Rust verifier.
The outer version is part of the signing transcript, so changing only the
compatibility envelope invalidates every authorization.

## Typed semantics

The payload has independent one-byte fields for note operation, finality
profile, authorization mode, disclosure mask, and finality object. Note-only
objects use finality profile/object `none`. Finality objects use note operation
`none` and a nonzero profile. Unknown values and contradictory combinations are
non-canonical.

Note operations are `shield=0`, `unshield=1`, `transfer=2`, `nullsend=3`,
`delegation_create=4`, `m_of_n_mint=5`, `reclaim=6`,
`conditional_migration=7`, and the sentinel `none=255`.

Finality profiles are `none=0`, `NullStake V1=1`, `V2=2`, and `V3=3`.
Authorization modes are `owner=0`, `cold_staker=1`,
`M-of-N public signers=2`, and `M-of-N hidden signers=3`. Finality objects are
`none=0`, `vote=1`, `tally_share=2`, `certificate=3`, and
`committee_rotation=4`.

## Selective privacy

The disclosure mask is a hide mask. Bit 0 (`1`) hides sender, bit 1 (`2`) hides
receiver, and bit 2 (`4`) hides amount. Mode 0 therefore exposes all three;
mode 7 hides all three and is the wallet default. Every mode uses the same
FCMP++ membership and spend model. An exposed dimension requires its canonical
disclosure object and linkage proof. A hidden dimension forbids that public
object. Metadata alone never satisfies a disclosure.

Fee and transparent shield/unshield sides remain public. A classic transparent
funding UTXO is an unavoidable sender disclosure even if the requested mask
hides sender; construction APIs must return the effective disclosure set.

## Payload and canonicality

All fixed-width integers use little-endian encoding. Vectors and variable blobs
use shortest-form CompactSize lengths. The top-level field order, input/output
field order, and six proof-section slots are fixed by the JSON contract.
Proof-section slots occur exactly once; an absent section has canonical zero
length. Inputs and outputs are ordered as serialized and may not be sorted or
deduplicated by a decoder.

The payload commits network and genesis, parameter digest, finalized tree root
and size, every `(O,I,C)` leaf, nullifiers, output ciphertexts, transparent
value balance, fee, disclosures, finality body, and proofs. The decoder rejects
unknown enums, nonzero reserved bytes, over-cap vectors, non-minimal lengths,
missing or repeated proof slots, mask/disclosure disagreement, and trailing
bytes.

## Version capability mapping

Versions 2000 through 2007 are compatibility selectors, not separate proof
systems. Version 2000 permits shield/unshield/transfer in mode 7. Version 2001
permits those operations in modes 0 through 7. Version 2002 permits transfer
and NullSend. Versions 2003, 2004, and 2005 select NullStake V1, V2, and V3;
2005 also carries delegation creation. Version 2006 selects M-of-N mint and
authorization, and 2007 selects owner reclaim. Version 2008 exposes every
typed capability. The complete executable matrix is in the JSON contract and
`iv5::EnvelopeAllows`.

## Transcripts and parameter digest

The signing transcript starts with `Innova/IV5/Signing/v1`, then commits in
order to genesis, network, outer version, schema, typed semantics, parameter
digest, finalized root and size, ordered inputs and outputs, transparent value
balance, fee, disclosures, and finality body.

The final consensus parameter digest is SHA-256 over the canonical
`Innova/IV5/ParameterDigest/v1` preimage. That preimage must cover the pinned
upstream revision, vendored source and generator hashes, every transcript
domain, tree shape and empty root, this payload schema and version matrix,
typed enums, disclosure rules, selected caps, ABI-v2 version/hash, and the
benchmark hash. It remains deliberately unfrozen while cap benchmarking and
ABI v2 are incomplete.

## State ownership

Rust exclusively performs canonical IV5 payload/address/proof decoding,
Helios/Selene tree math, note and nullifier cryptography, proving and
verification, disclosure linkage, key/address derivation, encryption, and
scanning. C++ owns the outer transaction, historical decoders, DAG/chain and
LevelDB transitions, epochs/reorgs, wallet database coordination, RPC, P2P,
and Qt. No C++ fallback verifier is permitted.

Run `python3 contrib/test/check_iv5_protocol_contract.py` to compare the
contract's constants and capability matrix with C++, Rust, RPC, and release
evidence declarations.
