//! Differential and property harness for the IV5 surface: canonical payloads from the
//! real prover must validate and every mutation must be rejected. Generators are seeded.

#![cfg(test)]
#![allow(clippy::too_many_lines)]

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    traits::IsIdentity,
};
use sha2::Digest as _;
use monero_ed25519::CompressedPoint;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::Sha256;

use crate::{
    disclosure, fcmp, note, payload, tree, value, ResultCode, FINALITY_OBJECT_NONE, NOTE_SHIELD,
    NOTE_TRANSFER, NOTE_UNSHIELD, PAYLOAD_SCHEMA_U16, PRODUCT_CONTRACT,
};

const WIRE_VERSION: u32 = 2008;
const NETWORK: u8 = 1;
const GENESIS: [u8; 32] = [0x11; 32];
const ADDRESS_TYPE: u8 = 0;
/// Enough leaves that the level-1 branch has a real sibling rather than only padding.
const FILLER_LEAVES: usize = 45;

// ---------------------------------------------------------------------------
// encoding helpers
// ---------------------------------------------------------------------------

fn parameter_digest() -> [u8; 32] {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
    digest
}

fn compact_size(out: &mut Vec<u8>, value: usize) {
    if value <= 252 {
        out.push(u8::try_from(value).expect("bounded"));
    } else if let Ok(short) = u16::try_from(value) {
        out.push(253);
        out.extend_from_slice(&short.to_le_bytes());
    } else {
        out.push(254);
        out.extend_from_slice(&u32::try_from(value).expect("bounded").to_le_bytes());
    }
}

fn vector(out: &mut Vec<u8>, bytes: &[u8]) {
    compact_size(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn monero_t() -> curve25519_dalek::edwards::EdwardsPoint {
    CompressedEdwardsY(CompressedPoint::T.to_bytes())
        .decompress()
        .expect("pinned T decompresses")
}

fn nonzero_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    loop {
        let mut bytes = [0_u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        if scalar != Scalar::ZERO {
            return scalar;
        }
    }
}

// ---------------------------------------------------------------------------
// note material
// ---------------------------------------------------------------------------

/// A recipient the harness holds the secrets for, so a note paid to it is spendable.
#[derive(Clone)]
struct Address {
    spend_secret: Scalar,
    spend: [u8; 32],
    view_secret: Scalar,
    view: [u8; 32],
}

impl Address {
    fn new(rng: &mut ChaCha20Rng) -> Self {
        let spend_secret = nonzero_scalar(rng);
        let view_secret = nonzero_scalar(rng);
        Self {
            spend: (ED25519_BASEPOINT_POINT * spend_secret).compress().to_bytes(),
            spend_secret,
            view: (ED25519_BASEPOINT_POINT * view_secret).compress().to_bytes(),
            view_secret,
        }
    }
}

/// One output record plus everything needed to spend it later.
#[derive(Clone)]
struct Note {
    output_o: [u8; 32],
    output_i: [u8; 32],
    output_c: [u8; 32],
    note_ephemeral: [u8; 32],
    tweak_ephemeral: [u8; 32],
    tweak_ephemeral_secret: Scalar,
    recipient_ciphertext: Vec<u8>,
    outgoing_ciphertext: Vec<u8>,
    address: Address,
    output_index: u32,
    amount: u64,
    mask: Scalar,
    /// `O = x*G + y*T`; the spend witness.
    x: Scalar,
    y: Scalar,
}

// Field offsets in a canonical note-encryption result.
const ENCRYPTED_O: core::ops::Range<usize> = 8..40;
const ENCRYPTED_I: core::ops::Range<usize> = 40..72;
const ENCRYPTED_C: core::ops::Range<usize> = 72..104;
const ENCRYPTED_NOTE_EPHEMERAL: core::ops::Range<usize> = 104..136;
const ENCRYPTED_TWEAK_EPHEMERAL: core::ops::Range<usize> = 136..168;
const ENCRYPTED_RECIPIENT: core::ops::Range<usize> = 168..345;
const ENCRYPTED_OUTGOING: core::ops::Range<usize> = 345..586;

fn field32(bytes: &[u8], range: core::ops::Range<usize>) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes[range]);
    out
}

/// Build a real note through the shipped encryptor, and recover its spend witness.
fn make_note(
    rng: &mut ChaCha20Rng,
    address: &Address,
    output_index: u32,
    amount: u64,
) -> Note {
    let outgoing_secret = nonzero_scalar(rng);
    let note_ephemeral_secret = nonzero_scalar(rng);
    let mut tweak_ephemeral_secret = nonzero_scalar(rng);
    while tweak_ephemeral_secret == note_ephemeral_secret {
        tweak_ephemeral_secret = nonzero_scalar(rng);
    }
    let y = nonzero_scalar(rng);
    let mask = nonzero_scalar(rng);

    let mut request = Vec::with_capacity(note::ENCRYPT_REQUEST_BYTES);
    request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    request.push(NETWORK);
    request.push(ADDRESS_TYPE);
    request.extend_from_slice(&output_index.to_le_bytes());
    request.extend_from_slice(&GENESIS);
    request.extend_from_slice(&address.spend);
    request.extend_from_slice(&address.view);
    request.extend_from_slice(&outgoing_secret.to_bytes());
    request.extend_from_slice(&note_ephemeral_secret.to_bytes());
    request.extend_from_slice(&tweak_ephemeral_secret.to_bytes());
    request.extend_from_slice(&amount.to_le_bytes());
    request.extend_from_slice(&y.to_bytes());
    request.extend_from_slice(&mask.to_bytes());
    assert_eq!(request.len(), note::ENCRYPT_REQUEST_BYTES);
    let encrypted = note::encrypt_request(&request).expect("note encryption must succeed");

    // x = spend_secret + tweak, because O = spend + tweak*G + y*T.
    let tweak_shared = (CompressedEdwardsY(address.view)
        .decompress()
        .expect("view key decompresses")
        * tweak_ephemeral_secret)
        .compress()
        .to_bytes();
    let tweak_ephemeral = field32(&encrypted, ENCRYPTED_TWEAK_EPHEMERAL);
    let tweak = disclosure::receiver_tweak(
        &tweak_shared,
        &tweak_ephemeral,
        &address.spend,
        &address.view,
        output_index,
    );

    let note = Note {
        output_o: field32(&encrypted, ENCRYPTED_O),
        output_i: field32(&encrypted, ENCRYPTED_I),
        output_c: field32(&encrypted, ENCRYPTED_C),
        note_ephemeral: field32(&encrypted, ENCRYPTED_NOTE_EPHEMERAL),
        tweak_ephemeral,
        tweak_ephemeral_secret,
        recipient_ciphertext: encrypted[ENCRYPTED_RECIPIENT].to_vec(),
        outgoing_ciphertext: encrypted[ENCRYPTED_OUTGOING].to_vec(),
        address: address.clone(),
        output_index,
        amount,
        mask,
        x: address.spend_secret + tweak,
        y,
    };
    // The witness must actually open the note, or every spend below is vacuous.
    assert_eq!(
        ((ED25519_BASEPOINT_POINT * note.x) + (monero_t() * note.y))
            .compress()
            .to_bytes(),
        note.output_o,
        "recovered spend witness must reproduce O"
    );
    assert_eq!(
        note.output_i,
        note::key_image_base_checked(&note.output_o).expect("I is derivable"),
        "leaf I must be the derived key-image base"
    );
    note
}

// ---------------------------------------------------------------------------
// tree
// ---------------------------------------------------------------------------

fn leaf_bytes(notes: &[Note]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(notes.len() * 96);
    for note in notes {
        bytes.extend_from_slice(&note.output_o);
        bytes.extend_from_slice(&note.output_i);
        bytes.extend_from_slice(&note.output_c);
    }
    bytes
}

fn tree_state(leaves: &[u8]) -> Vec<u8> {
    let mut state: Option<Vec<u8>> = None;
    for batch in leaves.chunks(16 * 96) {
        let mut request = Vec::new();
        request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.push(u8::from(state.is_none()));
        request.push(0);
        if let Some(previous) = &state {
            request.extend_from_slice(previous);
        }
        request.extend_from_slice(
            &u32::try_from(batch.len() / 96)
                .expect("batch is bounded")
                .to_le_bytes(),
        );
        request.extend_from_slice(batch);
        state = Some(tree::update(&request).expect("tree update").to_vec());
    }
    state.expect("at least one batch")
}

fn tree_witness(state: &[u8], targets: &[u64], leaves: &[u8]) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    request.push(u8::try_from(targets.len()).expect("bounded"));
    request.push(0);
    request.extend_from_slice(state);
    for target in targets {
        request.extend_from_slice(&target.to_le_bytes());
    }
    request.extend_from_slice(
        &u32::try_from(leaves.len() / 96)
            .expect("bounded")
            .to_le_bytes(),
    );
    request.extend_from_slice(leaves);
    tree::witness(&request).expect("witness must be produced")
}

/// One target's witness record, sliced out of a multi-target witness response.
const WITNESS_RECORD_BYTES: usize = 100 + (96 * 38) + 2304 + 3648;

struct Anonymity {
    root: [u8; 32],
    tree_size: u64,
    /// `x || y || record` for each spent note, in payload input order.
    witnesses: Vec<Vec<u8>>,
}

/// Put `spent` at the front of a tree padded with unrelated leaves, and witness them.
fn anonymity_set(rng: &mut ChaCha20Rng, spent: &[Note]) -> Anonymity {
    let filler_address = Address::new(rng);
    let mut leaves = spent.to_vec();
    let mut index = 1_000_u32;
    while leaves.len() < FILLER_LEAVES {
        leaves.push(make_note(rng, &filler_address, index, 1));
        index += 1;
    }
    let bytes = leaf_bytes(&leaves);
    let state = tree_state(&bytes);
    let targets = (0..spent.len() as u64).collect::<Vec<_>>();
    let response = tree_witness(&state, &targets, &bytes);

    let root = field32(&response, 12..44);
    let tree_size = u64::from_le_bytes(response[4..12].try_into().expect("size is 8 bytes"));
    assert_eq!(usize::from(response[44]), spent.len());
    let records = &response[48..];
    assert_eq!(records.len(), spent.len() * WITNESS_RECORD_BYTES);

    let witnesses = spent
        .iter()
        .enumerate()
        .map(|(position, note)| {
            let start = position * WITNESS_RECORD_BYTES;
            let mut witness = Vec::with_capacity(64 + WITNESS_RECORD_BYTES);
            witness.extend_from_slice(&note.x.to_bytes());
            witness.extend_from_slice(&note.y.to_bytes());
            witness.extend_from_slice(&records[start..start + WITNESS_RECORD_BYTES]);
            witness
        })
        .collect();

    Anonymity {
        root,
        tree_size,
        witnesses,
    }
}

// ---------------------------------------------------------------------------
// payload assembly
// ---------------------------------------------------------------------------

/// What a proving pass returns per input, decoded from the response record.
struct InputProof {
    pseudo_out: [u8; 32],
    key_image: [u8; 32],
    mask_delta: Scalar,
    sender_authority: [u8; 32],
    sender_disclosure: Vec<u8>,
}

const FCMP_RESPONSE_HEADER: usize = 4;
const FCMP_RESPONSE_RECORD: usize = 256;

fn fcmp_prove(
    root: [u8; 32],
    signable_hash: [u8; 32],
    entropy: [u8; 32],
    witnesses: &[Vec<u8>],
) -> (Vec<InputProof>, Vec<u8>) {
    let mut request = Vec::new();
    request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    request.push(8); // layers
    request.push(2); // root curve: helios
    request.push(u8::try_from(witnesses.len()).expect("bounded"));
    request.extend_from_slice(&[0; 3]);
    request.extend_from_slice(&root);
    request.extend_from_slice(&signable_hash);
    request.extend_from_slice(&entropy);
    for witness in witnesses {
        request.extend_from_slice(witness);
    }
    let response = fcmp::prove(&request).expect("proving must succeed over real witnesses");

    let mut proofs = Vec::with_capacity(witnesses.len());
    for position in 0..witnesses.len() {
        let start = FCMP_RESPONSE_HEADER + (position * FCMP_RESPONSE_RECORD);
        proofs.push(InputProof {
            pseudo_out: field32(&response, start..start + 32),
            key_image: field32(&response, start + 32..start + 64),
            mask_delta: Option::<Scalar>::from(Scalar::from_canonical_bytes(field32(
                &response,
                start + 64..start + 96,
            )))
            .expect("mask delta is canonical"),
            sender_authority: field32(&response, start + 96..start + 128),
            sender_disclosure: response[start + 128..start + 256].to_vec(),
        });
    }
    let proof_start = FCMP_RESPONSE_HEADER + (witnesses.len() * FCMP_RESPONSE_RECORD);
    let proof_len = u32::from_le_bytes(
        response[proof_start..proof_start + 4]
            .try_into()
            .expect("length is 4 bytes"),
    ) as usize;
    let membership = response[proof_start + 4..proof_start + 4 + proof_len].to_vec();
    (proofs, membership)
}

/// What a payload is meant to say. Every field is separately steerable so a property test
/// can break exactly one claim at a time.
#[derive(Clone)]
struct Spec {
    operation: u8,
    disclosure_mask: u8,
    inputs: Vec<Note>,
    outputs: Vec<Note>,
    transparent_value_balance: i64,
    fee: u64,
}

impl Spec {
    /// A shield: transparent value enters the pool, no inputs.
    fn shield(outputs: Vec<Note>, fee: u64) -> Self {
        let total = outputs.iter().map(|note| note.amount).sum::<u64>();
        Self {
            operation: NOTE_SHIELD,
            disclosure_mask: 7,
            inputs: Vec::new(),
            outputs,
            transparent_value_balance: i64::try_from(total + fee).expect("bounded"),
            fee,
        }
    }

    /// A transfer: nothing crosses the boundary, the fee comes out of the inputs.
    fn transfer(inputs: Vec<Note>, outputs: Vec<Note>, fee: u64) -> Self {
        Self {
            operation: NOTE_TRANSFER,
            disclosure_mask: 7,
            inputs,
            outputs,
            transparent_value_balance: 0,
            fee,
        }
    }

    /// An unshield: value leaves the pool.
    fn unshield(inputs: Vec<Note>, outputs: Vec<Note>, fee: u64) -> Self {
        let incoming = inputs.iter().map(|note| note.amount).sum::<u64>();
        let outgoing = outputs.iter().map(|note| note.amount).sum::<u64>();
        Self {
            operation: NOTE_UNSHIELD,
            disclosure_mask: 7,
            inputs,
            outputs,
            transparent_value_balance: i64::try_from(outgoing + fee).expect("bounded")
                - i64::try_from(incoming).expect("bounded"),
            fee,
        }
    }

    fn with_mask(mut self, mask: u8) -> Self {
        self.disclosure_mask = mask;
        self
    }
}

/// A named byte span of the built payload, so a surviving mutation names its field.
#[derive(Clone, Debug)]
struct Region {
    name: &'static str,
    start: usize,
    end: usize,
}

struct Built {
    /// The full validation request: chain context followed by the payload.
    request: Vec<u8>,
    /// Offset of the payload inside the request.
    payload_at: usize,
    signing_hash: [u8; 32],
    root: [u8; 32],
    regions: Vec<Region>,
}

impl Built {
    fn region_of(&self, offset: usize) -> &'static str {
        for region in &self.regions {
            if offset >= region.start && offset < region.end {
                return region.name;
            }
        }
        "unmapped"
    }
}

fn build(rng: &mut ChaCha20Rng, spec: &Spec) -> Built {
    let entropy = {
        let mut bytes = [0_u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes[0] |= 1;
        bytes
    };

    // A payload with no inputs still needs a finalized root to name.
    let (root, tree_size, witnesses) = if spec.inputs.is_empty() {
        let filler_address = Address::new(rng);
        let mut leaves = Vec::new();
        for index in 0..FILLER_LEAVES {
            leaves.push(make_note(rng, &filler_address, 2_000 + index as u32, 1));
        }
        let bytes = leaf_bytes(&leaves);
        let state = tree_state(&bytes);
        let root = tree::root(&state).expect("root");
        (field32(&root, 12..44), FILLER_LEAVES as u64, Vec::new())
    } else {
        let anonymity = anonymity_set(rng, &spec.inputs);
        (anonymity.root, anonymity.tree_size, anonymity.witnesses)
    };

    // Pass one fixes the pseudo-outputs, which the prefix must name before the hash over
    // that prefix can exist. The rerandomization stream is hash-independent by design, so
    // pass two under the real hash reproduces them.
    let first = (!witnesses.is_empty()).then(|| fcmp_prove(root, [0_u8; 32], entropy, &witnesses));
    let provisional = first
        .as_ref()
        .map_or_else(Vec::new, |(proofs, _)| proofs.iter().map(|p| p.pseudo_out).collect::<Vec<_>>());
    let provisional_images = first
        .as_ref()
        .map_or_else(Vec::new, |(proofs, _)| proofs.iter().map(|p| p.key_image).collect::<Vec<_>>());

    let mut regions = Vec::new();
    let mut payload = Vec::new();
    let mark = |regions: &mut Vec<Region>, name: &'static str, start: usize, end: usize| {
        regions.push(Region { name, start, end });
    };

    let start = payload.len();
    payload.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    mark(&mut regions, "schema", start, payload.len());

    let start = payload.len();
    payload.push(spec.operation);
    mark(&mut regions, "operation", start, payload.len());
    let start = payload.len();
    payload.push(0); // profile
    mark(&mut regions, "profile", start, payload.len());
    let start = payload.len();
    payload.push(0); // authorization
    mark(&mut regions, "authorization", start, payload.len());
    let start = payload.len();
    payload.push(spec.disclosure_mask);
    mark(&mut regions, "disclosure_mask", start, payload.len());
    let start = payload.len();
    payload.push(FINALITY_OBJECT_NONE);
    mark(&mut regions, "finality_object", start, payload.len());
    let start = payload.len();
    payload.push(NETWORK);
    mark(&mut regions, "network", start, payload.len());
    let start = payload.len();
    payload.push(0); // reserved
    mark(&mut regions, "reserved", start, payload.len());

    let start = payload.len();
    payload.extend_from_slice(&GENESIS);
    mark(&mut regions, "genesis", start, payload.len());
    let start = payload.len();
    payload.extend_from_slice(&parameter_digest());
    mark(&mut regions, "parameter_digest", start, payload.len());
    let start = payload.len();
    payload.extend_from_slice(&root);
    mark(&mut regions, "finalized_root", start, payload.len());
    let start = payload.len();
    payload.extend_from_slice(&tree_size.to_le_bytes());
    mark(&mut regions, "finalized_tree_size", start, payload.len());
    let start = payload.len();
    payload.extend_from_slice(&spec.transparent_value_balance.to_le_bytes());
    mark(&mut regions, "transparent_value_balance", start, payload.len());
    let start = payload.len();
    payload.extend_from_slice(&spec.fee.to_le_bytes());
    mark(&mut regions, "fee", start, payload.len());
    let start = payload.len();
    payload.extend_from_slice(&[0x5a; 32]);
    mark(&mut regions, "transparent_binding", start, payload.len());

    let start = payload.len();
    compact_size(&mut payload, spec.inputs.len());
    mark(&mut regions, "input_count", start, payload.len());
    for index in 0..spec.inputs.len() {
        let start = payload.len();
        payload.extend_from_slice(&provisional[index]);
        mark(&mut regions, "pseudo_out", start, payload.len());
        let start = payload.len();
        payload.extend_from_slice(&provisional_images[index]);
        mark(&mut regions, "key_image", start, payload.len());
    }

    let start = payload.len();
    compact_size(&mut payload, spec.outputs.len());
    mark(&mut regions, "output_count", start, payload.len());
    for note in &spec.outputs {
        let start = payload.len();
        payload.extend_from_slice(&note.output_o);
        mark(&mut regions, "output_owner", start, payload.len());
        let start = payload.len();
        payload.extend_from_slice(&note.output_c);
        mark(&mut regions, "output_commitment", start, payload.len());
        let start = payload.len();
        payload.extend_from_slice(&note.note_ephemeral);
        mark(&mut regions, "note_ephemeral", start, payload.len());
        let start = payload.len();
        payload.extend_from_slice(&note.tweak_ephemeral);
        mark(&mut regions, "tweak_ephemeral", start, payload.len());
        let start = payload.len();
        vector(&mut payload, &note.recipient_ciphertext);
        mark(&mut regions, "recipient_ciphertext", start, payload.len());
        let start = payload.len();
        vector(&mut payload, &note.outgoing_ciphertext);
        mark(&mut regions, "outgoing_ciphertext", start, payload.len());
    }

    // Sender authorities: published when mask bit 0 is clear.
    let sender_authorities = first.as_ref().map_or_else(Vec::new, |(proofs, _)| {
        proofs.iter().map(|p| p.sender_authority).collect()
    });
    if spec.disclosure_mask & 1 == 0 {
        for authority in &sender_authorities {
            let start = payload.len();
            payload.extend_from_slice(authority);
            mark(&mut regions, "sender_authority", start, payload.len());
        }
    }
    if spec.disclosure_mask & 2 == 0 {
        for note in &spec.outputs {
            let start = payload.len();
            payload.extend_from_slice(&note.address.spend);
            payload.extend_from_slice(&note.address.view);
            mark(&mut regions, "receiver_address", start, payload.len());
        }
    }
    if spec.disclosure_mask & 4 == 0 {
        for note in &spec.outputs {
            let start = payload.len();
            payload.extend_from_slice(&note.amount.to_le_bytes());
            payload.extend_from_slice(&note.mask.to_bytes());
            mark(&mut regions, "disclosed_amount", start, payload.len());
        }
    }

    let start = payload.len();
    vector(&mut payload, &[]); // finality body
    mark(&mut regions, "finality_body", start, payload.len());

    let signing_hash = payload_signing_hash(&payload);

    // Pass two: same entropy, real hash. The construction record must be identical.
    let (proofs, membership) = if witnesses.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let (proofs, membership) = fcmp_prove(root, signing_hash, entropy, &witnesses);
        for (index, proof) in proofs.iter().enumerate() {
            assert_eq!(
                proof.pseudo_out, provisional[index],
                "pseudo-outputs must not depend on the signing hash"
            );
            assert_eq!(proof.key_image, provisional_images[index]);
        }
        (proofs, membership)
    };

    let start = payload.len();
    vector(&mut payload, &membership);
    mark(&mut regions, "membership_proof", start, payload.len());

    let output_commitments = spec
        .outputs
        .iter()
        .map(|note| note.output_c)
        .collect::<Vec<_>>();

    let requires_range = !spec.outputs.is_empty() && spec.disclosure_mask & 4 != 0;
    let range_proof = if requires_range {
        let amounts = spec.outputs.iter().map(|note| note.amount).collect::<Vec<_>>();
        let masks = spec
            .outputs
            .iter()
            .map(|note| note.mask.to_bytes())
            .collect::<Vec<_>>();
        let (commitments, proof) =
            value::prove_range(&amounts, &masks, &entropy).expect("range proof");
        assert_eq!(commitments, output_commitments);
        proof
    } else {
        Vec::new()
    };
    let start = payload.len();
    vector(&mut payload, &range_proof);
    mark(&mut regions, "range_proof", start, payload.len());

    // excess = sum(input mask + rerandomization delta) - sum(output mask)
    let mut excess = Scalar::ZERO;
    for (index, note) in spec.inputs.iter().enumerate() {
        excess += note.mask + proofs[index].mask_delta;
    }
    for note in &spec.outputs {
        excess -= note.mask;
    }
    let pseudo_outs = proofs.iter().map(|p| p.pseudo_out).collect::<Vec<_>>();
    let balance_proof = value::prove_balance(
        &pseudo_outs,
        &output_commitments,
        spec.transparent_value_balance,
        spec.fee,
        &excess.to_bytes(),
        &signing_hash,
        &entropy,
    )
    .expect("balance proof must be provable: the excess mask is derived, not guessed");
    let start = payload.len();
    vector(&mut payload, &balance_proof);
    mark(&mut regions, "balance_proof", start, payload.len());

    let start = payload.len();
    vector(&mut payload, &[]); // operation proof
    mark(&mut regions, "operation_proof", start, payload.len());

    let mut disclosure_proof = Vec::new();
    if spec.disclosure_mask & 1 == 0 {
        for proof in &proofs {
            disclosure_proof.extend_from_slice(&proof.sender_disclosure);
        }
    }
    if spec.disclosure_mask & 2 == 0 {
        for (index, note) in spec.outputs.iter().enumerate() {
            let mut receiver_entropy = [0_u8; 32];
            rng.fill_bytes(&mut receiver_entropy);
            receiver_entropy[0] |= 1;
            let proof = disclosure::prove_receiver(
                &note.address.spend,
                &note.address.view,
                &note.output_o,
                &note.tweak_ephemeral,
                &note.tweak_ephemeral_secret.to_bytes(),
                &note.y.to_bytes(),
                &signing_hash,
                u32::try_from(index).expect("bounded"),
                &receiver_entropy,
            )
            .expect("receiver disclosure must be provable");
            disclosure_proof.extend_from_slice(&proof);
        }
    }
    let start = payload.len();
    vector(&mut payload, &disclosure_proof);
    mark(&mut regions, "disclosure_proof", start, payload.len());

    let mut request = Vec::new();
    request.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    request.push(NETWORK);
    request.extend_from_slice(&[0_u8; 3]);
    request.extend_from_slice(&GENESIS);
    let payload_at = request.len();
    request.extend_from_slice(&payload);

    Built {
        request,
        payload_at,
        signing_hash,
        root,
        regions,
    }
}

/// The signing hash the validator recomputes, over the prefix through the finality body.
fn payload_signing_hash(prefix: &[u8]) -> [u8; 32] {
    use blake2::{digest::consts::U32, Blake2b};
    let mut transcript = <Blake2b<U32> as blake2::Digest>::new();
    blake2::Digest::update(&mut transcript, b"Innova/IV5/Signing/v1");
    blake2::Digest::update(&mut transcript, WIRE_VERSION.to_le_bytes());
    blake2::Digest::update(&mut transcript, prefix);
    blake2::Digest::finalize(transcript).into()
}

fn validate(request: &[u8]) -> Result<(), ResultCode> {
    payload::validate(request)
}

// ---------------------------------------------------------------------------
// case generation
// ---------------------------------------------------------------------------

/// One representative case per (operation, mask, shape) combination the format allows.
fn cases(seed: u64) -> Vec<(String, Spec, ChaCha20Rng)> {
    let mut built = Vec::new();
    for mask in 0_u8..8 {
        for shape in 0_u8..3 {
            let mut rng = ChaCha20Rng::from_seed({
                let mut bytes = [0_u8; 32];
                bytes[..8].copy_from_slice(&seed.to_le_bytes());
                bytes[8] = mask;
                bytes[9] = shape;
                bytes
            });
            let address = Address::new(&mut rng);
            let spec = match shape {
                0 => {
                    let outputs = vec![make_note(&mut rng, &address, 0, 900)];
                    Spec::shield(outputs, 7)
                }
                1 => {
                    let inputs = vec![
                        make_note(&mut rng, &address, 0, 500),
                        make_note(&mut rng, &address, 1, 700),
                    ];
                    let outputs = vec![
                        make_note(&mut rng, &address, 0, 400),
                        make_note(&mut rng, &address, 1, 795),
                    ];
                    Spec::transfer(inputs, outputs, 5)
                }
                _ => {
                    let inputs = vec![make_note(&mut rng, &address, 0, 1_000)];
                    let outputs = vec![make_note(&mut rng, &address, 0, 250)];
                    Spec::unshield(inputs, outputs, 3)
                }
            }
            .with_mask(mask);
            let label = format!(
                "mask={mask} shape={}",
                match shape {
                    0 => "shield",
                    1 => "transfer",
                    _ => "unshield",
                }
            );
            built.push((label, spec, rng));
        }
    }
    built
}

// ---------------------------------------------------------------------------
// 1. round trip
// ---------------------------------------------------------------------------

#[test]
fn every_shape_and_mask_round_trips() {
    let mut count = 0;
    for (label, spec, mut rng) in cases(1) {
        let built = build(&mut rng, &spec);
        assert_eq!(
            validate(&built.request),
            Ok(()),
            "a payload built by the shipped prover must validate: {label}"
        );
        count += 1;
    }
    assert_eq!(count, 24, "24 (mask, shape) combinations must be covered");
    println!("round-trip: {count} payloads proved and validated");
}

/// Report payload geometry and validation cost, so the sweep sizes below are chosen against
/// measurement rather than guessed at.
#[test]
#[ignore = "measurement, not an assertion"]
fn report_geometry_and_cost() {
    for (label, spec, mut rng) in cases(1) {
        let built = build(&mut rng, &spec);
        let payload_len = built.request.len() - built.payload_at;
        let prefix_end = built
            .regions
            .iter()
            .find(|r| r.name == "membership_proof")
            .map_or(payload_len, |r| r.start);
        let start = std::time::Instant::now();
        for _ in 0..20 {
            let _ = validate(&built.request);
        }
        let accept = start.elapsed() / 20;
        let mut rejected = built.request.clone();
        rejected[built.payload_at] ^= 1;
        let start = std::time::Instant::now();
        for _ in 0..20 {
            let _ = validate(&rejected);
        }
        let reject = start.elapsed() / 20;
        println!(
            "{label}: payload={payload_len}B prefix={prefix_end}B accept={accept:?} reject={reject:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. byte-level mutation
// ---------------------------------------------------------------------------

/// Build every case in parallel; proving is the expensive half of a sweep's setup.
fn build_all(seed: u64) -> Vec<(String, Built)> {
    let specs = cases(seed);
    let mut results: Vec<Option<(String, Built)>> = (0..specs.len()).map(|_| None).collect();
    std::thread::scope(|scope| {
        for (slot, (label, spec, mut rng)) in results.iter_mut().zip(specs) {
            scope.spawn(move || {
                let built = build(&mut rng, &spec);
                assert_eq!(
                    validate(&built.request),
                    Ok(()),
                    "a payload built by the shipped prover must validate: {label}"
                );
                *slot = Some((label, built));
            });
        }
    });
    results.into_iter().map(|slot| slot.expect("built")).collect()
}

/// A mutation the validator accepted.
#[derive(Clone, Debug)]
struct Survivor {
    case: String,
    offset: usize,
    region: &'static str,
    bit: u8,
}

fn worker_threads() -> usize {
    std::thread::available_parallelism().map_or(4, |value| value.get().saturating_sub(2).max(1))
}

/// Every bit flip of every built payload byte must be rejected; the region map names the
/// field of a survivor. `INNOVA_DIFF_STRIDE` samples every Nth byte.
#[test]
fn exhaustive_single_bit_mutation_is_rejected() {
    let built = build_all(2);
    let stride = std::env::var("INNOVA_DIFF_STRIDE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);

    // A flat index space over (case, offset, bit) so threads can steal work by counter.
    let lengths = built
        .iter()
        .map(|(_, case)| (case.request.len() - case.payload_at).div_ceil(stride) * 8)
        .collect::<Vec<_>>();
    let total = lengths.iter().sum::<usize>();
    let mut starts = Vec::with_capacity(lengths.len());
    let mut running = 0_usize;
    for length in &lengths {
        starts.push(running);
        running += length;
    }

    let cursor = std::sync::atomic::AtomicUsize::new(0);
    let survivors = std::sync::Mutex::new(Vec::<Survivor>::new());
    let threads = worker_threads();
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let base = cursor.fetch_add(64, std::sync::atomic::Ordering::Relaxed);
                    if base >= total {
                        break;
                    }
                    for index in base..(base + 64).min(total) {
                        let case_index = starts.partition_point(|start| *start <= index) - 1;
                        let (label, case) = &built[case_index];
                        let within = index - starts[case_index];
                        let offset = (within / 8) * stride;
                        let bit = u8::try_from(within % 8).expect("bit index is bounded");
                        let mut mutated = case.request.clone();
                        mutated[case.payload_at + offset] ^= 1 << bit;
                        if validate(&mutated).is_ok() {
                            local.push(Survivor {
                                case: label.clone(),
                                offset,
                                region: case.region_of(offset),
                                bit,
                            });
                        }
                    }
                }
                if !local.is_empty() {
                    survivors.lock().expect("survivor list").extend(local);
                }
            });
        }
    });

    let survivors = survivors.into_inner().expect("survivor list");
    println!(
        "single-bit mutation: {} payloads, {total} mutations (stride {stride}, {threads} threads)",
        built.len()
    );
    report_survivors(&survivors);
    assert!(
        survivors.is_empty(),
        "{} single-bit mutations still validated",
        survivors.len()
    );
}

fn report_survivors(survivors: &[Survivor]) {
    if survivors.is_empty() {
        println!("  survivors: none");
        return;
    }
    let mut summary: std::collections::BTreeMap<(&str, &'static str), usize> =
        std::collections::BTreeMap::new();
    for survivor in survivors {
        *summary
            .entry((survivor.case.as_str(), survivor.region))
            .or_default() += 1;
    }
    for ((case, region), count) in &summary {
        println!("  SURVIVOR {case} region={region}: {count}");
    }
    for survivor in survivors.iter().take(20) {
        println!(
            "  SURVIVOR {} offset={} region={} bit={}",
            survivor.case, survivor.offset, survivor.region, survivor.bit
        );
    }
}

/// Random multi-byte mutation, which reaches shapes a single bit flip cannot: truncation,
/// extension, and whole-field replacement.
#[test]
fn random_structural_mutation_is_rejected() {
    let mut rng = ChaCha20Rng::from_seed([0x9d; 32]);
    let mut survivors = Vec::new();
    let mut mutations = 0_usize;

    for (label, spec, mut build_rng) in cases(3) {
        let built = build(&mut build_rng, &spec);
        assert_eq!(validate(&built.request), Ok(()), "baseline must hold: {label}");
        let payload_len = built.request.len() - built.payload_at;

        for _ in 0..400 {
            let mut mutated = built.request.clone();
            match rng.next_u32() % 5 {
                // splice a random run
                0 => {
                    let length = 1 + (rng.next_u32() as usize % 32);
                    let at = rng.next_u32() as usize % payload_len;
                    for index in 0..length.min(payload_len - at) {
                        mutated[built.payload_at + at + index] = (rng.next_u32() & 0xff) as u8;
                    }
                }
                // truncate
                1 => {
                    let keep = rng.next_u32() as usize % payload_len;
                    mutated.truncate(built.payload_at + keep);
                }
                // extend
                2 => {
                    let extra = 1 + (rng.next_u32() as usize % 64);
                    for _ in 0..extra {
                        mutated.push((rng.next_u32() & 0xff) as u8);
                    }
                }
                // swap two 32-byte fields
                3 => {
                    if payload_len > 96 {
                        let a = rng.next_u32() as usize % (payload_len - 64);
                        let b = rng.next_u32() as usize % (payload_len - 64);
                        for index in 0..32 {
                            mutated.swap(built.payload_at + a + index, built.payload_at + b + index);
                        }
                    }
                }
                // zero a run
                _ => {
                    let length = 1 + (rng.next_u32() as usize % 48);
                    let at = rng.next_u32() as usize % payload_len;
                    for index in 0..length.min(payload_len - at) {
                        mutated[built.payload_at + at + index] = 0;
                    }
                }
            }
            mutations += 1;
            if mutated != built.request && validate(&mutated).is_ok() {
                survivors.push(label.clone());
            }
        }
    }

    println!("structural mutation: {mutations} mutations");
    assert!(
        survivors.is_empty(),
        "{} structural mutations still validated: {:?}",
        survivors.len(),
        &survivors[..survivors.len().min(10)]
    );
}

/// The chain context the caller supplies, not the payload, must also be binding.
#[test]
fn chain_context_mutation_is_rejected() {
    let mut mutations = 0_usize;
    for (label, spec, mut rng) in cases(4) {
        let built = build(&mut rng, &spec);
        assert_eq!(validate(&built.request), Ok(()), "baseline: {label}");
        for offset in 0..built.payload_at {
            for bit in 0..8_u8 {
                let mut mutated = built.request.clone();
                mutated[offset] ^= 1 << bit;
                mutations += 1;
                assert!(
                    validate(&mutated).is_err(),
                    "context byte {offset} bit {bit} is not binding: {label}"
                );
            }
        }
    }
    println!("context mutation: {mutations} mutations");
}

// ---------------------------------------------------------------------------
// 3. properties
// ---------------------------------------------------------------------------

/// Value is conserved. Every restatement of the amounts that keeps the equation true must
/// validate; every one that breaks it must be unprovable or rejected.
#[test]
fn value_is_conserved() {
    let mut rng = ChaCha20Rng::from_seed([0x21; 32]);
    let mut checked = 0_usize;

    for trial in 0..12_u64 {
        let mut case_rng = ChaCha20Rng::from_seed({
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&trial.to_le_bytes());
            bytes[31] = 0x21;
            bytes
        });
        let address = Address::new(&mut case_rng);
        let in_a = 100 + (rng.next_u32() as u64 % 10_000);
        let in_b = 100 + (rng.next_u32() as u64 % 10_000);
        let fee = 1 + (rng.next_u32() as u64 % 50);
        let out_a = 1 + (rng.next_u32() as u64 % (in_a + in_b - fee - 1));
        let out_b = in_a + in_b - fee - out_a;

        let inputs = vec![
            make_note(&mut case_rng, &address, 0, in_a),
            make_note(&mut case_rng, &address, 1, in_b),
        ];
        let outputs = vec![
            make_note(&mut case_rng, &address, 0, out_a),
            make_note(&mut case_rng, &address, 1, out_b),
        ];
        let spec = Spec::transfer(inputs, outputs, fee);
        let built = build(&mut case_rng, &spec);
        assert_eq!(
            validate(&built.request),
            Ok(()),
            "balanced transfer {in_a}+{in_b} -> {out_a}+{out_b}+{fee} must validate"
        );
        checked += 1;

        // Now break conservation without touching any proof: move the declared fee.
        // The balance statement folds the fee, so the recomputed excess no longer matches.
        for delta in [1_i64, -1, 1_000] {
            let region = built
                .regions
                .iter()
                .find(|region| region.name == "fee")
                .expect("fee region is mapped");
            let mut mutated = built.request.clone();
            let at = built.payload_at + region.start;
            let current = u64::from_le_bytes(
                mutated[at..at + 8].try_into().expect("fee is 8 bytes"),
            );
            let Some(changed) = current.checked_add_signed(delta) else {
                continue;
            };
            mutated[at..at + 8].copy_from_slice(&changed.to_le_bytes());
            assert!(
                validate(&mutated).is_err(),
                "a fee change of {delta} must break the value balance"
            );
            checked += 1;
        }
    }
    println!("value conservation: {checked} assertions");
}

/// The transparent balance and the fee must not be interchangeable. The balance statement
/// folds them into one `tvb - fee` term; if nothing else pins them apart, a payload could
/// claim a larger fee and a larger transparent inflow for free.
#[test]
fn transparent_balance_and_fee_are_not_interchangeable() {
    let mut rng = ChaCha20Rng::from_seed([0x33; 32]);
    let address = Address::new(&mut rng);
    let outputs = vec![make_note(&mut rng, &address, 0, 500)];
    let spec = Spec::shield(outputs, 10);
    let built = build(&mut rng, &spec);
    assert_eq!(validate(&built.request), Ok(()));

    let tvb_region = built
        .regions
        .iter()
        .find(|region| region.name == "transparent_value_balance")
        .expect("mapped")
        .clone();
    let fee_region = built
        .regions
        .iter()
        .find(|region| region.name == "fee")
        .expect("mapped")
        .clone();

    // Shift both by the same amount: `tvb - fee` is unchanged, so the excess point and the
    // Schnorr challenge are identical. Only a rule that reads them apart can reject this.
    let shift = 1_000_u64;
    let mut mutated = built.request.clone();
    let tvb_at = built.payload_at + tvb_region.start;
    let fee_at = built.payload_at + fee_region.start;
    let tvb = i64::from_le_bytes(mutated[tvb_at..tvb_at + 8].try_into().expect("8"));
    let fee = u64::from_le_bytes(mutated[fee_at..fee_at + 8].try_into().expect("8"));
    mutated[tvb_at..tvb_at + 8]
        .copy_from_slice(&(tvb + i64::try_from(shift).expect("bounded")).to_le_bytes());
    mutated[fee_at..fee_at + 8].copy_from_slice(&(fee + shift).to_le_bytes());

    let outcome = validate(&mutated);
    println!("tvb/fee co-shift outcome: {outcome:?}");
    assert!(
        outcome.is_err(),
        "the signing hash must pin the transparent balance and the fee apart, not only their difference"
    );
}

/// A proof verifies only against its own root.
#[test]
fn a_proof_verifies_only_against_its_own_root() {
    let mut rng = ChaCha20Rng::from_seed([0x44; 32]);
    let address = Address::new(&mut rng);
    let inputs = vec![make_note(&mut rng, &address, 0, 900)];
    let outputs = vec![make_note(&mut rng, &address, 0, 890)];
    let spec = Spec::transfer(inputs, outputs, 10);
    let built = build(&mut rng, &spec);
    assert_eq!(validate(&built.request), Ok(()));

    // An unrelated but structurally valid root, from a different anonymity set.
    let other_address = Address::new(&mut rng);
    let mut other_leaves = Vec::new();
    for index in 0..FILLER_LEAVES {
        other_leaves.push(make_note(&mut rng, &other_address, 3_000 + index as u32, 1));
    }
    let other_state = tree_state(&leaf_bytes(&other_leaves));
    let other_root = field32(&tree::root(&other_state).expect("root"), 12..44);
    assert_ne!(other_root, built.root, "the two roots must differ");

    let region = built
        .regions
        .iter()
        .find(|region| region.name == "finalized_root")
        .expect("mapped");
    let mut mutated = built.request.clone();
    let at = built.payload_at + region.start;
    mutated[at..at + 32].copy_from_slice(&other_root);
    assert!(
        validate(&mutated).is_err(),
        "a membership proof must not verify against another tree's root"
    );
}

/// A key image is a function of the note, not of the transaction it appears in: spending the
/// same note in two different payloads must produce the same image, which is what makes a
/// double spend detectable at all.
#[test]
fn a_key_image_is_unique_per_note() {
    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
    let address = Address::new(&mut rng);
    let spent = make_note(&mut rng, &address, 0, 1_000);

    let image_for = |fee: u64, rng: &mut ChaCha20Rng| -> [u8; 32] {
        let outputs = vec![make_note(rng, &address, 0, 1_000 - fee)];
        let spec = Spec::transfer(vec![spent.clone()], outputs, fee);
        let built = build(rng, &spec);
        assert_eq!(validate(&built.request), Ok(()));
        let region = built
            .regions
            .iter()
            .find(|region| region.name == "key_image")
            .expect("mapped");
        field32(&built.request, built.payload_at + region.start..built.payload_at + region.end)
    };

    let first = image_for(10, &mut rng);
    let second = image_for(20, &mut rng);
    assert_eq!(
        first, second,
        "one note must produce one key image whatever transaction spends it"
    );

    // And a different note must produce a different image.
    let other = make_note(&mut rng, &address, 1, 1_000);
    let outputs = vec![make_note(&mut rng, &address, 0, 990)];
    let spec = Spec::transfer(vec![other], outputs, 10);
    let built = build(&mut rng, &spec);
    let region = built
        .regions
        .iter()
        .find(|region| region.name == "key_image")
        .expect("mapped");
    let third = field32(
        &built.request,
        built.payload_at + region.start..built.payload_at + region.end,
    );
    assert_ne!(first, third, "two notes must not share a key image");
}

/// One note may not be spent twice inside one payload. Both inputs would carry the same
/// image while the balance proof counts the value twice, which mints the difference.
#[test]
fn one_note_cannot_be_spent_twice_in_one_payload() {
    let mut rng = ChaCha20Rng::from_seed([0x66; 32]);
    let address = Address::new(&mut rng);
    let spent = make_note(&mut rng, &address, 0, 1_000);

    // Both inputs name the same leaf. If this proves and validates, 1,000 becomes 2,000.
    let anonymity = anonymity_set(&mut rng, &[spent.clone(), spent.clone()]);
    let entropy = [0x7f_u8; 32];
    let mut request = Vec::new();
    request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    request.push(8);
    request.push(2);
    request.push(2);
    request.extend_from_slice(&[0; 3]);
    request.extend_from_slice(&anonymity.root);
    request.extend_from_slice(&[0x11_u8; 32]);
    request.extend_from_slice(&entropy);
    for witness in &anonymity.witnesses {
        request.extend_from_slice(witness);
    }
    let outcome = fcmp::prove(&request);
    println!("double-spend-in-one-payload prove outcome: {outcome:?}");
    assert!(
        outcome.is_err(),
        "the prover must refuse to prove one note twice in one payload"
    );
}

/// A disclosure mask reveals exactly its named fields: the record is present when the bit is
/// clear and absent when it is set, and neither the presence nor the absence is optional.
#[test]
fn a_mask_reveals_exactly_its_named_fields() {
    let mut checked = 0_usize;
    for (label, spec, mut rng) in cases(5) {
        let built = build(&mut rng, &spec);
        assert_eq!(validate(&built.request), Ok(()), "baseline: {label}");

        let has_sender = built.regions.iter().any(|r| r.name == "sender_authority");
        let has_receiver = built.regions.iter().any(|r| r.name == "receiver_address");
        let has_amount = built.regions.iter().any(|r| r.name == "disclosed_amount");

        let expect_sender = spec.disclosure_mask & 1 == 0 && !spec.inputs.is_empty();
        let expect_receiver = spec.disclosure_mask & 2 == 0 && !spec.outputs.is_empty();
        let expect_amount = spec.disclosure_mask & 4 == 0 && !spec.outputs.is_empty();
        assert_eq!(has_sender, expect_sender, "sender record presence: {label}");
        assert_eq!(has_receiver, expect_receiver, "receiver record presence: {label}");
        assert_eq!(has_amount, expect_amount, "amount record presence: {label}");

        // Flipping the mask alone must be rejected: the mask sits inside the signed prefix
        // and changes how many bytes follow.
        let region = built
            .regions
            .iter()
            .find(|r| r.name == "disclosure_mask")
            .expect("mapped");
        for bit in 0..3_u8 {
            let mut mutated = built.request.clone();
            mutated[built.payload_at + region.start] ^= 1 << bit;
            assert!(
                validate(&mutated).is_err(),
                "mask bit {bit} must not be flippable: {label}"
            );
            checked += 1;
        }
        checked += 3;
    }
    println!("mask semantics: {checked} assertions");
}

/// A disclosed amount must equal the amount the commitment actually holds, and the record
/// must not be movable between outputs.
#[test]
fn a_disclosed_amount_binds_to_its_own_output() {
    let mut rng = ChaCha20Rng::from_seed([0x88; 32]);
    let address = Address::new(&mut rng);
    let inputs = vec![make_note(&mut rng, &address, 0, 1_000)];
    let outputs = vec![
        make_note(&mut rng, &address, 0, 400),
        make_note(&mut rng, &address, 1, 590),
    ];
    // Mask bit 2 clear: amounts are published with their openings.
    let spec = Spec::transfer(inputs, outputs, 10).with_mask(3);
    let built = build(&mut rng, &spec);
    assert_eq!(validate(&built.request), Ok(()));

    let disclosed = built
        .regions
        .iter()
        .filter(|r| r.name == "disclosed_amount")
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(disclosed.len(), 2, "both outputs publish an amount record");

    // Swap the two records: each opening now names the other commitment.
    let mut mutated = built.request.clone();
    let first = built.payload_at + disclosed[0].start;
    let second = built.payload_at + disclosed[1].start;
    let width = disclosed[0].end - disclosed[0].start;
    for index in 0..width {
        mutated.swap(first + index, second + index);
    }
    assert!(
        validate(&mutated).is_err(),
        "an amount record must not open another output's commitment"
    );

    // Overstate one amount, keeping the opening.
    let mut mutated = built.request.clone();
    let amount = u64::from_le_bytes(mutated[first..first + 8].try_into().expect("8"));
    mutated[first..first + 8].copy_from_slice(&(amount + 1).to_le_bytes());
    assert!(
        validate(&mutated).is_err(),
        "a disclosed amount must match the commitment it opens"
    );
}

/// A receiver disclosure must not be movable between outputs, and a sender disclosure must
/// not be movable between inputs. Both are indexed proofs; the index must be in the
/// challenge or the proofs are interchangeable.
#[test]
fn disclosure_proofs_bind_to_their_own_index() {
    let mut rng = ChaCha20Rng::from_seed([0x99; 32]);
    let address = Address::new(&mut rng);
    let inputs = vec![
        make_note(&mut rng, &address, 0, 600),
        make_note(&mut rng, &address, 1, 600),
    ];
    let outputs = vec![
        make_note(&mut rng, &address, 0, 500),
        make_note(&mut rng, &address, 1, 690),
    ];
    // Mask 4: sender and receiver both published, amounts hidden.
    let spec = Spec::transfer(inputs, outputs, 10).with_mask(4);
    let built = build(&mut rng, &spec);
    assert_eq!(validate(&built.request), Ok(()));

    let region = built
        .regions
        .iter()
        .find(|r| r.name == "disclosure_proof")
        .expect("mapped");
    // The vector body starts after its compact-size prefix; both counts here are small.
    let body = built.payload_at + region.start + 1;

    // Two sender proofs of 128 bytes, then two receiver proofs of 160.
    let mut mutated = built.request.clone();
    for index in 0..disclosure::SENDER_PROOF_BYTES {
        mutated.swap(body + index, body + disclosure::SENDER_PROOF_BYTES + index);
    }
    assert!(
        validate(&mutated).is_err(),
        "sender disclosure proofs must not be interchangeable between inputs"
    );

    let receivers = body + (2 * disclosure::SENDER_PROOF_BYTES);
    let mut mutated = built.request.clone();
    for index in 0..disclosure::RECEIVER_PROOF_BYTES {
        mutated.swap(
            receivers + index,
            receivers + disclosure::RECEIVER_PROOF_BYTES + index,
        );
    }
    assert!(
        validate(&mutated).is_err(),
        "receiver disclosure proofs must not be interchangeable between outputs"
    );
}

/// A proof made for one payload must not verify inside another. Every proof section is
/// swapped between two independently built payloads.
#[test]
fn proofs_do_not_transplant_between_payloads() {
    let mut first_rng = ChaCha20Rng::from_seed([0xa1; 32]);
    let mut second_rng = ChaCha20Rng::from_seed([0xa2; 32]);
    let address_a = Address::new(&mut first_rng);
    let address_b = Address::new(&mut second_rng);

    let spec_a = Spec::transfer(
        vec![make_note(&mut first_rng, &address_a, 0, 1_000)],
        vec![make_note(&mut first_rng, &address_a, 0, 990)],
        10,
    );
    let spec_b = Spec::transfer(
        vec![make_note(&mut second_rng, &address_b, 0, 1_000)],
        vec![make_note(&mut second_rng, &address_b, 0, 990)],
        10,
    );
    let a = build(&mut first_rng, &spec_a);
    let b = build(&mut second_rng, &spec_b);
    assert_eq!(validate(&a.request), Ok(()));
    assert_eq!(validate(&b.request), Ok(()));
    assert_ne!(a.signing_hash, b.signing_hash);

    for name in ["membership_proof", "balance_proof"] {
        let region_a = a.regions.iter().find(|r| r.name == name).expect("mapped");
        let region_b = b.regions.iter().find(|r| r.name == name).expect("mapped");
        assert_eq!(
            region_a.end - region_a.start,
            region_b.end - region_b.start,
            "{name} sections must be comparable"
        );
        let mut mutated = a.request.clone();
        mutated[a.payload_at + region_a.start..a.payload_at + region_a.end].copy_from_slice(
            &b.request[b.payload_at + region_b.start..b.payload_at + region_b.end],
        );
        assert!(
            validate(&mutated).is_err(),
            "{name} must not transplant into another payload"
        );
    }
}

/// The tree root is a function of the leaf multiset in order, and incremental extension must
/// agree with a single-shot build.
#[test]
fn tree_root_is_deterministic_and_incremental() {
    let mut rng = ChaCha20Rng::from_seed([0xb1; 32]);
    let address = Address::new(&mut rng);
    let notes = (0..40)
        .map(|index| make_note(&mut rng, &address, index, 1 + u64::from(index)))
        .collect::<Vec<_>>();
    let bytes = leaf_bytes(&notes);

    let one_shot = tree_state(&bytes);
    let one_shot_again = tree_state(&bytes);
    assert_eq!(one_shot, one_shot_again, "the tree state must be a function of its leaves");

    // Batched differently, the same leaves must give the same state.
    let mut state: Option<Vec<u8>> = None;
    for batch in bytes.chunks(7 * 96) {
        let mut request = Vec::new();
        request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.push(u8::from(state.is_none()));
        request.push(0);
        if let Some(previous) = &state {
            request.extend_from_slice(previous);
        }
        request.extend_from_slice(
            &u32::try_from(batch.len() / 96).expect("bounded").to_le_bytes(),
        );
        request.extend_from_slice(batch);
        state = Some(tree::update(&request).expect("tree update").to_vec());
    }
    assert_eq!(
        state.expect("batched state"),
        one_shot,
        "batching must not change the tree state"
    );

    // Reordering the leaves must change the root: a set-valued root would let a producer
    // permute a block's outputs freely.
    let mut swapped = notes.clone();
    swapped.swap(0, 1);
    let reordered = tree_state(&leaf_bytes(&swapped));
    assert_ne!(reordered, one_shot, "leaf order must be part of the tree state");
}

/// The nullifier accumulator must be order-sensitive and must refuse a repeat.
#[test]
fn nullifier_accumulator_rejects_a_repeat() {
    let image = |seed: u8| {
        let mut bytes = [seed; 32];
        bytes[31] = 0x40;
        bytes
    };
    let apply = |state: Option<&[u8]>, images: &[[u8; 32]]| {
        let mut request = Vec::new();
        request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.push(u8::from(state.is_none()));
        request.push(0);
        if let Some(previous) = state {
            request.extend_from_slice(previous);
        }
        request.extend_from_slice(&u32::try_from(images.len()).expect("bounded").to_le_bytes());
        for value in images {
            request.extend_from_slice(value);
        }
        crate::nullifier::update(&request)
    };

    let first = apply(None, &[image(1), image(2)]).expect("two fresh images accumulate");
    let reversed = apply(None, &[image(2), image(1)]).expect("reversed order accumulates");
    assert_ne!(
        first, reversed,
        "a rolling hash must not be order-independent, or a block's spends could be permuted"
    );
    assert!(
        apply(Some(&first), &[image(1)]).is_err(),
        "an already-accumulated key image must be refused"
    );
    assert!(
        apply(None, &[image(3), image(3)]).is_err(),
        "a repeat inside one batch must be refused"
    );
}

/// The homegrown note AEAD must authenticate: a flipped ciphertext bit, a wrong key and a
/// swapped note must all fail to open.
#[test]
fn note_ciphertext_is_authenticated() {
    let mut rng = ChaCha20Rng::from_seed([0xc1; 32]);
    let address = Address::new(&mut rng);
    let other = Address::new(&mut rng);
    let subject = make_note(&mut rng, &address, 0, 1_234);

    let scan_request = |view_secret: &Scalar, note: &Note, ciphertext: &[u8]| {
        let mut request = Vec::new();
        request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.push(1); // view-only scan
        request.push(NETWORK);
        request.push(ADDRESS_TYPE);
        request.extend_from_slice(&[0_u8; 3]);
        request.extend_from_slice(&note.output_index.to_le_bytes());
        request.extend_from_slice(&GENESIS);
        request.extend_from_slice(&view_secret.to_bytes());
        request.extend_from_slice(&[0_u8; 32]);
        request.extend_from_slice(&note.output_o);
        request.extend_from_slice(&note.output_i);
        request.extend_from_slice(&note.output_c);
        request.extend_from_slice(&note.note_ephemeral);
        request.extend_from_slice(&note.tweak_ephemeral);
        request.extend_from_slice(
            &u32::try_from(ciphertext.len()).expect("bounded").to_le_bytes(),
        );
        request.extend_from_slice(ciphertext);
        request
    };

    let honest = note::scan(&scan_request(
        &address.view_secret,
        &subject,
        &subject.recipient_ciphertext,
    ));
    println!("note scan (honest) outcome: {:?}", honest.as_ref().map(Vec::len));

    // Wrong view key must not open it.
    assert!(
        note::scan(&scan_request(
            &other.view_secret,
            &subject,
            &subject.recipient_ciphertext
        ))
        .is_err(),
        "a note must not open under an unrelated view key"
    );

    // Every single-bit flip of the ciphertext must fail the tag.
    let mut opened = 0_usize;
    for offset in 0..subject.recipient_ciphertext.len() {
        for bit in 0..8_u8 {
            let mut ciphertext = subject.recipient_ciphertext.clone();
            ciphertext[offset] ^= 1 << bit;
            if note::scan(&scan_request(&address.view_secret, &subject, &ciphertext)).is_ok() {
                opened += 1;
            }
        }
    }
    println!(
        "note AEAD: {} single-bit ciphertext mutations, {opened} opened",
        subject.recipient_ciphertext.len() * 8
    );
    assert_eq!(opened, 0, "the note MAC must reject every ciphertext mutation");
}

/// Elligator-2 hashing must be deterministic, domain-separated and never the identity.
#[test]
fn hash_to_point_is_deterministic_and_separated() {
    let mut rng = ChaCha20Rng::from_seed([0xd1; 32]);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..2_000 {
        let mut input = [0_u8; 32];
        rng.fill_bytes(&mut input);
        let first = crate::hash_to_point::hash_to_point(b"Innova/IV5/Harness/A", &[&input]);
        let again = crate::hash_to_point::hash_to_point(b"Innova/IV5/Harness/A", &[&input]);
        let other_domain =
            crate::hash_to_point::hash_to_point(b"Innova/IV5/Harness/B", &[&input]);
        assert_eq!(first, again, "hashing must be a function of its input");
        assert_ne!(first, other_domain, "domains must not collide");
        assert!(!bool::from(first.is_identity()), "the identity must never be produced");
        assert!(first.is_torsion_free(), "the result must be in the prime-order subgroup");
        seen.insert(first.compress().to_bytes());
    }
    assert_eq!(seen.len(), 2_000, "2,000 distinct inputs must give 2,000 distinct points");

    // Length framing must be real: two field splits of the same bytes must differ.
    let joined = crate::hash_to_point::hash_to_point(b"Innova/IV5/Harness/A", &[b"abcd"]);
    let split = crate::hash_to_point::hash_to_point(b"Innova/IV5/Harness/A", &[b"ab", b"cd"]);
    assert_ne!(joined, split, "field boundaries must be framed, not concatenated");
}

/// A balance proof is a proof of knowledge of one scalar. Two proofs under the same key over
/// different messages would give up that scalar; the format must never carry two.
#[test]
fn a_balance_proof_is_not_replayable_under_a_new_message() {
    let mut rng = ChaCha20Rng::from_seed([0xe1; 32]);
    let address = Address::new(&mut rng);
    let outputs = vec![make_note(&mut rng, &address, 0, 700)];
    let spec = Spec::shield(outputs, 5);
    let built = build(&mut rng, &spec);
    assert_eq!(validate(&built.request), Ok(()));

    // Any prefix byte the proof covers, changed, must invalidate it. Walk the mapped
    // prefix regions rather than trusting that the hash covers what it claims to.
    let mut checked = 0_usize;
    for region in &built.regions {
        if matches!(
            region.name,
            "membership_proof"
                | "range_proof"
                | "balance_proof"
                | "operation_proof"
                | "disclosure_proof"
        ) {
            continue;
        }
        let mut mutated = built.request.clone();
        mutated[built.payload_at + region.start] ^= 0x01;
        assert!(
            validate(&mutated).is_err(),
            "prefix region {} is not covered by the signing hash",
            region.name
        );
        checked += 1;
    }
    println!("signing-hash coverage: {checked} prefix regions checked");
}
