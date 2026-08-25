//! Cross-transaction linkage over the disclosure masks: what an observer recovers from
//! payloads the consensus decoder accepts.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use monero_ed25519::CompressedPoint;
use sha2::{Digest, Sha256};

use crate::{
    disclosure, fcmp, is_attestation_operation, note, payload, tree, value,
    COLLATERAL_ATTESTATION_AMOUNT, NOTE_COLLATERAL_REGISTER, NOTE_SHIELD, NOTE_UNSHIELD,
    PRODUCT_CONTRACT,
};

const NETWORK: u8 = 1;
const GENESIS: [u8; 32] = [0x11; 32];
const TRANSPARENT_BINDING: [u8; 32] = [0x5a; 32];
const ADDRESS_TYPE: u8 = 0;
const WIRE_VERSION: u32 = 2008;

/// Where a payload stops being the chain context every payload repeats and starts being
/// this transaction's own material: schema and flags, genesis, parameter digest, anchor
/// root, tree size, transparent balance, fee, transparent binding.
const CHAIN_CONTEXT_BYTES: usize = 9 + 32 + 32 + 32 + 8 + 8 + 8 + 32;
const MASK_OFFSET: usize = 5;

const SENDER_PROOF_BYTES: usize = 128;
const RECEIVER_PROOF_BYTES: usize = 160;
const ENCRYPTED_NOTE_BYTES: usize = 586;
const RECIPIENT_CIPHERTEXT_BYTES: usize = 177;
const OUTGOING_CIPHERTEXT_BYTES: usize = 241;
const PROVING_RECORD_BYTES: usize = 256;

fn monero_t() -> EdwardsPoint {
    CompressedEdwardsY(CompressedPoint::T.to_bytes())
        .decompress()
        .expect("the pinned Monero T encoding must decompress")
}

fn point(bytes: &[u8; 32]) -> EdwardsPoint {
    CompressedEdwardsY(*bytes)
        .decompress()
        .expect("a payload point must decompress")
}

fn array(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("a 32-byte field")
}

fn parameter_digest() -> [u8; 32] {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
    digest
}

fn compact_size(out: &mut Vec<u8>, value: usize) {
    if value <= 252 {
        out.push(u8::try_from(value).expect("a bounded count"));
    } else if let Ok(short) = u16::try_from(value) {
        out.push(253);
        out.extend_from_slice(&short.to_le_bytes());
    } else {
        out.push(254);
        out.extend_from_slice(&u32::try_from(value).expect("a bounded count").to_le_bytes());
    }
}

fn vector(out: &mut Vec<u8>, bytes: &[u8]) {
    compact_size(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Every 32-byte window of a payload from `start` on, at every offset.
fn windows_from(payload: &[u8], start: usize) -> BTreeSet<[u8; 32]> {
    payload[start..].windows(32).map(array).collect()
}

/// A copy of `payload` with one field overwritten by a per-copy pattern, so copies under
/// different tags cannot match in or across that field.
fn redact(payload: &[u8], start: usize, length: usize, tag: u8) -> Vec<u8> {
    let mut copy = payload.to_vec();
    for (step, byte) in copy[start..start + length].iter_mut().enumerate() {
        *byte = tag ^ u8::try_from(step % 256).expect("a bounded step");
    }
    copy
}

/// One wallet address: the spend and view keys an IV5 payment names.
struct Address {
    spend_secret: Scalar,
    view_secret: Scalar,
    spend: [u8; 32],
    view: [u8; 32],
    outgoing: [u8; 32],
}

impl Address {
    fn new(seed: u64) -> Self {
        let spend_secret = Scalar::from(seed.wrapping_mul(2_003).wrapping_add(7));
        let view_secret = Scalar::from(seed.wrapping_mul(3_001).wrapping_add(11));
        Self {
            spend_secret,
            view_secret,
            spend: (ED25519_BASEPOINT_POINT * spend_secret)
                .compress()
                .to_bytes(),
            view: (ED25519_BASEPOINT_POINT * view_secret)
                .compress()
                .to_bytes(),
            outgoing: Scalar::from(seed.wrapping_mul(4_001).wrapping_add(13)).to_bytes(),
        }
    }
}

/// One note as the chain carries it, plus the secrets its owner holds.
struct Note {
    encrypted: Vec<u8>,
    index: u32,
    amount: u64,
    y: Scalar,
    mask: Scalar,
    tweak_ephemeral_secret: Scalar,
    /// The note's one-time spend authority secret: `O = x*G + y*T`.
    x: Scalar,
}

impl Note {
    fn field(&self, start: usize) -> [u8; 32] {
        array(&self.encrypted[start..start + 32])
    }

    fn owner(&self) -> [u8; 32] {
        self.field(8)
    }

    fn key_image_base(&self) -> [u8; 32] {
        self.field(40)
    }

    fn commitment(&self) -> [u8; 32] {
        self.field(72)
    }

    fn note_ephemeral(&self) -> [u8; 32] {
        self.field(104)
    }

    fn tweak_ephemeral(&self) -> [u8; 32] {
        self.field(136)
    }

    fn recipient_ciphertext(&self) -> &[u8] {
        &self.encrypted[168..168 + RECIPIENT_CIPHERTEXT_BYTES]
    }

    fn outgoing_ciphertext(&self) -> &[u8] {
        &self.encrypted[345..345 + OUTGOING_CIPHERTEXT_BYTES]
    }

    fn leaf(&self) -> [u8; 96] {
        let mut leaf = [0_u8; 96];
        leaf[..32].copy_from_slice(&self.owner());
        leaf[32..64].copy_from_slice(&self.key_image_base());
        leaf[64..].copy_from_slice(&self.commitment());
        leaf
    }

    /// The linking tag this note yields whatever spends it: `I = x * Hp(O)`.
    fn key_image(&self) -> [u8; 32] {
        (point(&self.key_image_base()) * self.x)
            .compress()
            .to_bytes()
    }

    /// The one-time authority a sender disclosure of a spend of this note publishes.
    fn authority(&self) -> [u8; 32] {
        (ED25519_BASEPOINT_POINT * self.x).compress().to_bytes()
    }

    /// What a receiver disclosure of this note publishes as its shared point, derived
    /// from the recipient's side of the exchange rather than the sender's.
    fn tweak_shared(&self, address: &Address) -> [u8; 32] {
        (point(&self.tweak_ephemeral()) * address.view_secret)
            .compress()
            .to_bytes()
    }

    /// The shared point that keys the note ciphertext. No disclosure opens it.
    fn note_shared(&self, address: &Address) -> [u8; 32] {
        (point(&self.note_ephemeral()) * address.view_secret)
            .compress()
            .to_bytes()
    }
}

/// Encrypt one note to `address` with the production note encoder.
fn mint(address: &Address, index: u32, amount: u64, seed: u64) -> Note {
    let note_ephemeral_secret = Scalar::from(seed.wrapping_mul(5_003).wrapping_add(17));
    let tweak_ephemeral_secret = Scalar::from(seed.wrapping_mul(6_007).wrapping_add(19));
    let y = Scalar::from(seed.wrapping_mul(7_013).wrapping_add(23));
    let mask = Scalar::from(seed.wrapping_mul(8_017).wrapping_add(29));

    let mut request = Vec::with_capacity(272);
    request.extend_from_slice(&1_u16.to_le_bytes());
    request.push(NETWORK);
    request.push(ADDRESS_TYPE);
    request.extend_from_slice(&index.to_le_bytes());
    request.extend_from_slice(&GENESIS);
    request.extend_from_slice(&address.spend);
    request.extend_from_slice(&address.view);
    request.extend_from_slice(&address.outgoing);
    request.extend_from_slice(&note_ephemeral_secret.to_bytes());
    request.extend_from_slice(&tweak_ephemeral_secret.to_bytes());
    request.extend_from_slice(&amount.to_le_bytes());
    request.extend_from_slice(&y.to_bytes());
    request.extend_from_slice(&mask.to_bytes());
    let encrypted = note::encrypt_request(&request).expect("the note encoder must accept");
    assert_eq!(encrypted.len(), ENCRYPTED_NOTE_BYTES);

    let tweak_shared = (point(&address.view) * tweak_ephemeral_secret)
        .compress()
        .to_bytes();
    let tweak = disclosure::receiver_tweak(
        &tweak_shared,
        &array(&encrypted[136..168]),
        &address.spend,
        &address.view,
        index,
    );

    let built = Note {
        encrypted,
        index,
        amount,
        y,
        mask,
        tweak_ephemeral_secret,
        x: address.spend_secret + tweak,
    };
    assert_eq!(
        ((ED25519_BASEPOINT_POINT * built.x) + (monero_t() * y))
            .compress()
            .to_bytes(),
        built.owner(),
        "a note's owner key must open as x*G + y*T"
    );
    built
}

/// The finalized tree a spend proves against, with the witness records it needs.
struct Anchor {
    root: [u8; 32],
    root_curve: u8,
    size: u64,
    records: Vec<Vec<u8>>,
}

/// The empty canonical tree, which is anchor enough for an operation that spends nothing.
fn empty_anchor() -> Anchor {
    let state = tree::update(&[1, 0, 1, 0, 0, 0, 0, 0]).expect("the empty tree state");
    let root = tree::root(&state).expect("the empty tree root");
    Anchor {
        root: array(&root[12..44]),
        root_curve: root[3],
        size: 0,
        records: Vec::new(),
    }
}

fn anchor(leaves: &[[u8; 96]], targets: &[u64]) -> Anchor {
    let mut leaf_bytes = Vec::with_capacity(leaves.len() * 96);
    for leaf in leaves {
        leaf_bytes.extend_from_slice(leaf);
    }
    let leaf_count = u32::try_from(leaves.len()).expect("a bounded leaf count");

    let mut update = Vec::new();
    update.extend_from_slice(&1_u16.to_le_bytes());
    update.push(1);
    update.push(0);
    update.extend_from_slice(&leaf_count.to_le_bytes());
    update.extend_from_slice(&leaf_bytes);
    let state = tree::update(&update).expect("the tree must accept canonical leaves");

    let mut request = Vec::new();
    request.extend_from_slice(&1_u16.to_le_bytes());
    request.push(u8::try_from(targets.len()).expect("a bounded target count"));
    request.push(0);
    request.extend_from_slice(&state);
    for target in targets {
        request.extend_from_slice(&target.to_le_bytes());
    }
    request.extend_from_slice(&leaf_count.to_le_bytes());
    request.extend_from_slice(&leaf_bytes);
    let response = tree::witness(&request).expect("a witness must be produced");

    let record_len = (response.len() - 48) / targets.len();
    let records = (0..targets.len())
        .map(|index| response[48 + (index * record_len)..48 + ((index + 1) * record_len)].to_vec())
        .collect();
    Anchor {
        root: array(&response[12..44]),
        root_curve: response[3],
        size: u64::from_le_bytes(response[4..12].try_into().expect("a tree size")),
        records,
    }
}

/// One note being spent, with the material the prover needs.
struct Spend {
    x: Scalar,
    y: Scalar,
    mask: Scalar,
    record: Vec<u8>,
}

/// What proving one input produced. The authority is computed for every input at every
/// mask; only the payload decides whether it reaches the wire.
struct Construction {
    pseudo_out: [u8; 32],
    key_image: [u8; 32],
    mask_delta: Scalar,
    authority: [u8; 32],
    sender_proof: [u8; SENDER_PROOF_BYTES],
}

fn prove_inputs(
    tree_anchor: &Anchor,
    signing_hash: &[u8; 32],
    entropy: &[u8; 32],
    spends: &[Spend],
) -> (Vec<Construction>, Vec<u8>) {
    let mut request = Vec::new();
    request.extend_from_slice(&1_u16.to_le_bytes());
    request.push(8);
    request.push(tree_anchor.root_curve);
    request.push(u8::try_from(spends.len()).expect("a bounded input count"));
    request.extend_from_slice(&[0_u8; 3]);
    request.extend_from_slice(&tree_anchor.root);
    request.extend_from_slice(signing_hash);
    request.extend_from_slice(entropy);
    for spend in spends {
        request.extend_from_slice(&spend.x.to_bytes());
        request.extend_from_slice(&spend.y.to_bytes());
        request.extend_from_slice(&spend.record);
    }
    let response = fcmp::prove(&request).expect("the prover must accept a real witness");

    let count = usize::from(response[3]);
    assert_eq!(count, spends.len());
    let mut constructions = Vec::with_capacity(count);
    for index in 0..count {
        let base = 4 + (index * PROVING_RECORD_BYTES);
        let delta = Option::<Scalar>::from(Scalar::from_canonical_bytes(array(
            &response[base + 64..base + 96],
        )))
        .expect("a canonical rerandomization delta");
        constructions.push(Construction {
            pseudo_out: array(&response[base..base + 32]),
            key_image: array(&response[base + 32..base + 64]),
            mask_delta: delta,
            authority: array(&response[base + 96..base + 128]),
            sender_proof: response[base + 128..base + 256]
                .try_into()
                .expect("a 128-byte sender proof"),
        });
    }
    let start = 4 + (count * PROVING_RECORD_BYTES);
    let length = u32::from_le_bytes(
        response[start..start + 4]
            .try_into()
            .expect("a proof length"),
    );
    let length = usize::try_from(length).expect("a bounded proof length");
    (
        constructions,
        response[start + 4..start + 4 + length].to_vec(),
    )
}

/// What a payload is asked to be. Everything else about it is derived.
struct Spec<'a> {
    operation: u8,
    mask: u8,
    anchor: &'a Anchor,
    spends: &'a [Spend],
    outputs: &'a [(&'a Note, &'a Address)],
    transparent_value_balance: i64,
    fee: u64,
    registration_context: Option<[u8; 32]>,
    entropy: u8,
}

/// A finished payload and what proving it produced, published or not.
struct Built {
    payload: Vec<u8>,
    constructions: Vec<Construction>,
}

/// Serialize, prove and validate one payload, in the order the format fixes.
#[allow(clippy::too_many_lines)]
fn build(spec: &Spec<'_>) -> Built {
    let entropy = [spec.entropy; 32];
    let discloses_sender = spec.mask & 1 == 0;
    let discloses_receiver = spec.mask & 2 == 0;
    let discloses_amount = spec.mask & 4 == 0;
    let is_attestation = is_attestation_operation(spec.operation);

    // The prefix names each input's pseudo-output and the proof binds a hash of that
    // prefix, so the inputs are proved twice: once to learn what to name, once to bind.
    // The rerandomization is drawn without the hash, so the two passes agree.
    let draft = if spec.spends.is_empty() {
        Vec::new()
    } else {
        prove_inputs(spec.anchor, &[0x21; 32], &entropy, spec.spends).0
    };

    let mut prefix = Vec::new();
    prefix.extend_from_slice(&1_u16.to_le_bytes());
    prefix.extend_from_slice(&[spec.operation, 0, 0, spec.mask, 0, NETWORK, 0]);
    prefix.extend_from_slice(&GENESIS);
    prefix.extend_from_slice(&parameter_digest());
    prefix.extend_from_slice(&spec.anchor.root);
    prefix.extend_from_slice(&spec.anchor.size.to_le_bytes());
    prefix.extend_from_slice(&spec.transparent_value_balance.to_le_bytes());
    prefix.extend_from_slice(&spec.fee.to_le_bytes());
    prefix.extend_from_slice(&TRANSPARENT_BINDING);
    assert_eq!(prefix.len(), CHAIN_CONTEXT_BYTES);

    compact_size(&mut prefix, draft.len());
    for construction in &draft {
        prefix.extend_from_slice(&construction.pseudo_out);
        prefix.extend_from_slice(&construction.key_image);
    }
    compact_size(&mut prefix, spec.outputs.len());
    for (index, (output, _)) in spec.outputs.iter().enumerate() {
        assert_eq!(
            output.index,
            u32::try_from(index).expect("a bounded output count"),
            "a note is bound to the output index it was encrypted at"
        );
        prefix.extend_from_slice(&output.owner());
        prefix.extend_from_slice(&output.commitment());
        prefix.extend_from_slice(&output.note_ephemeral());
        prefix.extend_from_slice(&output.tweak_ephemeral());
        vector(&mut prefix, output.recipient_ciphertext());
        vector(&mut prefix, output.outgoing_ciphertext());
    }
    if let Some(context) = spec.registration_context {
        prefix.extend_from_slice(&context);
    }

    if discloses_sender {
        for construction in &draft {
            prefix.extend_from_slice(&construction.authority);
        }
    }
    if discloses_receiver {
        for (_, address) in spec.outputs {
            prefix.extend_from_slice(&address.spend);
            prefix.extend_from_slice(&address.view);
        }
    }
    if discloses_amount {
        for (output, _) in spec.outputs {
            prefix.extend_from_slice(&output.amount.to_le_bytes());
            prefix.extend_from_slice(&output.mask.to_bytes());
        }
    }
    vector(&mut prefix, &[]);

    let mut hash_request = Vec::with_capacity(8 + prefix.len());
    hash_request.extend_from_slice(&1_u16.to_le_bytes());
    hash_request.extend_from_slice(&[0, 0]);
    hash_request.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    hash_request.extend_from_slice(&prefix);
    let signing_hash = payload::signing_hash(&hash_request).expect("a canonical prefix");

    let (constructions, membership) = if spec.spends.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        prove_inputs(spec.anchor, &signing_hash, &entropy, spec.spends)
    };
    for (final_pass, draft_pass) in constructions.iter().zip(&draft) {
        assert_eq!(final_pass.pseudo_out, draft_pass.pseudo_out);
        assert_eq!(final_pass.key_image, draft_pass.key_image);
        assert_eq!(final_pass.authority, draft_pass.authority);
    }

    let mut excess = Scalar::ZERO;
    for (spend, construction) in spec.spends.iter().zip(&constructions) {
        excess += spend.mask + construction.mask_delta;
    }
    for (output, _) in spec.outputs {
        excess -= output.mask;
    }

    let pseudo_outs = constructions
        .iter()
        .map(|construction| construction.pseudo_out)
        .collect::<Vec<_>>();
    let commitments = spec
        .outputs
        .iter()
        .map(|(output, _)| output.commitment())
        .collect::<Vec<_>>();

    let range = if spec.outputs.is_empty() || discloses_amount {
        Vec::new()
    } else {
        let amounts = spec
            .outputs
            .iter()
            .map(|(output, _)| output.amount)
            .collect::<Vec<_>>();
        let masks = spec
            .outputs
            .iter()
            .map(|(output, _)| output.mask.to_bytes())
            .collect::<Vec<_>>();
        let (proved, proof) =
            value::prove_range(&amounts, &masks, &entropy).expect("a valid range proof");
        assert_eq!(proved, commitments);
        proof
    };

    let balance = if is_attestation {
        Vec::new()
    } else {
        value::prove_balance(
            &pseudo_outs,
            &commitments,
            spec.transparent_value_balance,
            spec.fee,
            &excess.to_bytes(),
            &signing_hash,
            &entropy,
        )
        .expect("a valid balance proof")
        .to_vec()
    };
    let operation_proof = if is_attestation {
        let rerandomized = spec.spends[0].mask + constructions[0].mask_delta;
        value::prove_amount_equality(
            &pseudo_outs[0],
            COLLATERAL_ATTESTATION_AMOUNT,
            &rerandomized.to_bytes(),
            &signing_hash,
            &entropy,
        )
        .expect("a valid amount-equality proof")
        .to_vec()
    } else {
        Vec::new()
    };

    let mut disclosure_proofs = Vec::new();
    if discloses_sender {
        for construction in &constructions {
            disclosure_proofs.extend_from_slice(&construction.sender_proof);
        }
    }
    if discloses_receiver {
        for (index, (output, address)) in spec.outputs.iter().enumerate() {
            let proof = disclosure::prove_receiver(
                &address.spend,
                &address.view,
                &output.owner(),
                &output.tweak_ephemeral(),
                &output.tweak_ephemeral_secret.to_bytes(),
                &output.y.to_bytes(),
                &signing_hash,
                u32::try_from(index).expect("a bounded output count"),
                &entropy,
            )
            .expect("a valid receiver disclosure");
            disclosure_proofs.extend_from_slice(&proof);
        }
    }

    let mut built = prefix;
    vector(&mut built, &membership);
    vector(&mut built, &range);
    vector(&mut built, &balance);
    vector(&mut built, &operation_proof);
    vector(&mut built, &disclosure_proofs);
    payload::validate(&validation_request(&built))
        .expect("the consensus decoder must accept this payload");
    Built {
        payload: built,
        constructions,
    }
}

fn validation_request(payload: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(40 + payload.len());
    request.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    request.push(NETWORK);
    request.extend_from_slice(&[0_u8; 3]);
    request.extend_from_slice(&GENESIS);
    request.extend_from_slice(payload);
    request
}

/// A payload read the way an observer reads it: from the bytes, with no help from the
/// wallet that made it and none from the decoder that judged it.
struct Wire {
    mask: u8,
    pseudo_outs: Vec<[u8; 32]>,
    key_images: Vec<[u8; 32]>,
    /// Where each key image starts in the payload, for a sweep that needs to exclude it.
    key_image_offsets: Vec<usize>,
    owners: Vec<[u8; 32]>,
    note_ephemerals: Vec<[u8; 32]>,
    tweak_ephemerals: Vec<[u8; 32]>,
    sender_authorities: Vec<[u8; 32]>,
    receiver_addresses: Vec<([u8; 32], [u8; 32])>,
    disclosed_amounts: Vec<(u64, [u8; 32])>,
    /// `view * r_tweak`, which leads each receiver disclosure proof.
    receiver_shared_points: Vec<[u8; 32]>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> &'a [u8] {
        let slice = &self.bytes[self.at..self.at + count];
        self.at += count;
        slice
    }

    fn field(&mut self) -> [u8; 32] {
        array(self.take(32))
    }

    fn count(&mut self) -> usize {
        let first = self.take(1)[0];
        match first {
            253 => usize::from(u16::from_le_bytes(
                self.take(2).try_into().expect("two bytes"),
            )),
            254 => usize::try_from(u32::from_le_bytes(
                self.take(4).try_into().expect("four bytes"),
            ))
            .expect("a bounded length"),
            _ => usize::from(first),
        }
    }

    fn vector(&mut self) -> &'a [u8] {
        let length = self.count();
        self.take(length)
    }
}

fn read_wire(payload: &[u8]) -> Wire {
    let mask = payload[MASK_OFFSET];
    let is_attestation = is_attestation_operation(payload[2]);
    let mut reader = Reader {
        bytes: payload,
        at: CHAIN_CONTEXT_BYTES,
    };

    let input_count = reader.count();
    let mut pseudo_outs = Vec::with_capacity(input_count);
    let mut key_images = Vec::with_capacity(input_count);
    let mut key_image_offsets = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        pseudo_outs.push(reader.field());
        key_image_offsets.push(reader.at);
        key_images.push(reader.field());
    }
    let output_count = reader.count();
    let mut owners = Vec::with_capacity(output_count);
    let mut note_ephemerals = Vec::with_capacity(output_count);
    let mut tweak_ephemerals = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        owners.push(reader.field());
        reader.field();
        note_ephemerals.push(reader.field());
        tweak_ephemerals.push(reader.field());
        reader.vector();
        reader.vector();
    }
    if is_attestation {
        reader.take(32);
    }

    let mut sender_authorities = Vec::new();
    if mask & 1 == 0 {
        for _ in 0..input_count {
            sender_authorities.push(reader.field());
        }
    }
    let mut receiver_addresses = Vec::new();
    if mask & 2 == 0 {
        for _ in 0..output_count {
            let spend = reader.field();
            receiver_addresses.push((spend, reader.field()));
        }
    }
    let mut disclosed_amounts = Vec::new();
    if mask & 4 == 0 {
        for _ in 0..output_count {
            let amount = u64::from_le_bytes(reader.take(8).try_into().expect("eight bytes"));
            disclosed_amounts.push((amount, reader.field()));
        }
    }
    reader.vector();
    reader.vector();
    reader.vector();
    reader.vector();
    reader.vector();
    let disclosure_section = reader.vector();
    assert_eq!(
        reader.at,
        payload.len(),
        "the payload ends where it declares"
    );
    assert_eq!(
        disclosure_section.len(),
        (sender_authorities.len() * SENDER_PROOF_BYTES)
            + (receiver_addresses.len() * RECEIVER_PROOF_BYTES),
        "the disclosure section is exactly the records the mask declares"
    );

    let base = sender_authorities.len() * SENDER_PROOF_BYTES;
    let receiver_shared_points = (0..receiver_addresses.len())
        .map(|index| {
            let start = base + (index * RECEIVER_PROOF_BYTES);
            array(&disclosure_section[start..start + 32])
        })
        .collect();

    Wire {
        mask,
        pseudo_outs,
        key_images,
        key_image_offsets,
        owners,
        note_ephemerals,
        tweak_ephemerals,
        sender_authorities,
        receiver_addresses,
        disclosed_amounts,
        receiver_shared_points,
    }
}

/// The authority a receiver-disclosed output pins, computed from chain bytes alone.
///
/// The tweak is a hash of values the payload publishes -- the disclosure's shared point,
/// the output's tweak ephemeral, the address it names and the output index -- and the
/// one-time key is the address's spend key shifted by it. No secret enters this.
fn authority_from_chain(wire: &Wire, index: usize) -> [u8; 32] {
    let (spend, view) = wire.receiver_addresses[index];
    let tweak = disclosure::receiver_tweak(
        &wire.receiver_shared_points[index],
        &wire.tweak_ephemerals[index],
        &spend,
        &view,
        u32::try_from(index).expect("a bounded output index"),
    );
    (point(&spend) + (ED25519_BASEPOINT_POINT * tweak))
        .compress()
        .to_bytes()
}

/// One wallet, one note lineage: a receiver-disclosed creation, then the same note spent
/// three ways -- sender-disclosed, fully private, and attested as collateral.
struct Lineage {
    wallet: Address,
    payee: Address,
    /// A shield at mask 0: every field a payload can publish about its outputs.
    disclosed_creation: Vec<u8>,
    /// The note that creation paid to the wallet, which every spend below consumes.
    spent: Note,
    /// A second note the same creation paid, standing where a transfer's change stands.
    second_output: Note,
    /// The note spent at mask 6: sender published.
    sender_disclosed_spend: Vec<u8>,
    /// The note spent at mask 7: nothing published.
    private_spend: Vec<u8>,
    /// The authority the prover computed for the mask-7 spend and did not publish.
    private_spend_authority: [u8; 32],
    /// The sender proof that spend did not publish either.
    private_spend_sender_proof: [u8; SENDER_PROOF_BYTES],
    /// The note attested as collateral, at the only mask an attestation may carry.
    attestation: Vec<u8>,
}

fn lineage() -> &'static Lineage {
    static LINEAGE: OnceLock<Lineage> = OnceLock::new();
    LINEAGE.get_or_init(build_lineage)
}

fn build_lineage() -> Lineage {
    let wallet = Address::new(1);
    let payee = Address::new(2);
    let amount = COLLATERAL_ATTESTATION_AMOUNT;
    let second_amount = 7_000_u64;
    let fee = 1_000_u64;

    let to_wallet = mint(&wallet, 0, amount, 101);
    let to_payee = mint(&payee, 1, second_amount, 102);
    // Mask 0 is the fully transparent end of the range: recipients and amounts both
    // published, which is the strongest thing a creation can hand an observer.
    let creation = build(&Spec {
        operation: NOTE_SHIELD,
        mask: 0,
        anchor: &empty_anchor(),
        spends: &[],
        outputs: &[(&to_wallet, &wallet), (&to_payee, &payee)],
        transparent_value_balance: i64::try_from(amount + second_amount + fee)
            .expect("a bounded balance"),
        fee,
        registration_context: None,
        entropy: 0x31,
    });

    // Both created notes enter the tree the spends below prove against.
    let anchored = anchor(&[to_wallet.leaf(), to_payee.leaf()], &[0]);
    let spend = || Spend {
        x: to_wallet.x,
        y: to_wallet.y,
        mask: to_wallet.mask,
        record: anchored.records[0].clone(),
    };
    let released = amount - fee;
    let balance = -i64::try_from(released).expect("a bounded balance");

    let sender_disclosed_spend = build(&Spec {
        operation: NOTE_UNSHIELD,
        mask: 6,
        anchor: &anchored,
        spends: &[spend()],
        outputs: &[],
        transparent_value_balance: balance,
        fee,
        registration_context: None,
        entropy: 0x41,
    });
    let private_spend = build(&Spec {
        operation: NOTE_UNSHIELD,
        mask: 7,
        anchor: &anchored,
        spends: &[spend()],
        outputs: &[],
        transparent_value_balance: balance,
        fee,
        registration_context: None,
        entropy: 0x53,
    });
    let attestation = build(&Spec {
        operation: NOTE_COLLATERAL_REGISTER,
        mask: 7,
        anchor: &anchored,
        spends: &[spend()],
        outputs: &[],
        transparent_value_balance: 0,
        fee: 0,
        registration_context: Some([0x77; 32]),
        entropy: 0x67,
    });

    Lineage {
        wallet,
        payee,
        disclosed_creation: creation.payload,
        spent: to_wallet,
        second_output: to_payee,
        sender_disclosed_spend: sender_disclosed_spend.payload,
        private_spend: private_spend.payload,
        private_spend_authority: private_spend.constructions[0].authority,
        private_spend_sender_proof: private_spend.constructions[0].sender_proof,
        attestation: attestation.payload,
    }
}

/// One shield at one mask, over a fixed pair of outputs to one address.
struct MaskCase {
    address: Address,
    first: Note,
    second: Note,
    payload: Vec<u8>,
}

/// One shield per mask, all of the same shape. Each gets its own address and notes, so a
/// field found in one payload cannot have come from another.
fn mask_sweep() -> &'static [MaskCase; 8] {
    static SWEEP: OnceLock<[MaskCase; 8]> = OnceLock::new();
    SWEEP.get_or_init(|| {
        core::array::from_fn(|mask| {
            let address = Address::new(40 + u64::try_from(mask).expect("a bounded mask"));
            let first = mint(
                &address,
                0,
                4_100,
                200 + u64::try_from(mask).expect("bounded"),
            );
            let second = mint(
                &address,
                1,
                900,
                300 + u64::try_from(mask).expect("bounded"),
            );
            let built = build(&Spec {
                operation: NOTE_SHIELD,
                mask: u8::try_from(mask).expect("a bounded mask"),
                anchor: &empty_anchor(),
                spends: &[],
                outputs: &[(&first, &address), (&second, &address)],
                transparent_value_balance: 5_050,
                fee: 50,
                registration_context: None,
                entropy: 0x11 + u8::try_from(mask).expect("a bounded mask"),
            });
            MaskCase {
                address,
                first,
                second,
                payload: built.payload,
            }
        })
    })
}

// A receiver disclosure names an address, and the address plus the output's own tweak
// ephemeral plus the shared point the disclosure publishes determine the note's one-time
// key. That key is what a sender disclosure of the later spend publishes, so disclosing
// the receiver of one transaction pre-commits the sender privacy of whoever spends that
// output next -- to everyone, not only to the parties.
#[test]
fn a_receiver_disclosure_predicts_the_authority_a_later_spend_publishes() {
    let lineage = lineage();
    let creation = read_wire(&lineage.disclosed_creation);
    let spend = read_wire(&lineage.sender_disclosed_spend);

    // Positive controls: the two payloads carry the records the linkage reads.
    assert_eq!(creation.mask, 0);
    assert_eq!(creation.receiver_addresses.len(), 2);
    assert_eq!(creation.disclosed_amounts.len(), 2);
    assert_eq!(spend.mask, 6);
    assert_eq!(spend.sender_authorities.len(), 1);

    let predicted = authority_from_chain(&creation, 0);
    assert_eq!(
        predicted, spend.sender_authorities[0],
        "the disclosed creation determines the authority the later spend publishes"
    );

    // The match is a computation, not a copy: those bytes are nowhere in the creation.
    assert!(!contains(&lineage.disclosed_creation, &predicted));
    assert_ne!(predicted, creation.owners[0]);

    // Every disclosed output is predictable, not only the one that was paid on purpose.
    // A transfer's change is one of its outputs, so a receiver disclosure hands the world
    // the change note's one-time key too.
    assert_eq!(
        authority_from_chain(&creation, 1),
        lineage.second_output.authority(),
        "a receiver disclosure pins every output it covers"
    );
}

// The same note spent with the sender hidden. Nothing the disclosed creation published,
// and nothing derivable from it, appears in the private spend.
#[test]
fn a_private_spend_of_a_disclosed_note_matches_nothing_it_published() {
    let lineage = lineage();
    let creation = read_wire(&lineage.disclosed_creation);
    let predicted = authority_from_chain(&creation, 0);

    // Positive control: the byte string does occur on chain, in the disclosed spend.
    assert!(contains(&lineage.sender_disclosed_spend, &predicted));

    assert!(
        !contains(&lineage.private_spend, &predicted),
        "a mask-7 spend must not carry the authority a disclosure predicts"
    );
    for field in [
        lineage.spent.owner(),
        lineage.spent.commitment(),
        lineage.spent.note_ephemeral(),
        lineage.spent.tweak_ephemeral(),
        lineage.spent.key_image_base(),
        lineage.spent.tweak_shared(&lineage.wallet),
        lineage.spent.note_shared(&lineage.wallet),
    ] {
        assert!(
            !contains(&lineage.private_spend, &field),
            "a mask-7 spend must name none of the spent note's own material"
        );
    }

    // No 32-byte window recurs either, past the chain context every payload repeats.
    let published = windows_from(&lineage.disclosed_creation, CHAIN_CONTEXT_BYTES);
    let private = windows_from(&lineage.private_spend, CHAIN_CONTEXT_BYTES);
    assert!(
        published.intersection(&private).next().is_none(),
        "a disclosed creation and a private spend of its own output share no field"
    );

    // The control for that sweep: it does find a recurrence where one exists. The two
    // spends of this note share their key image.
    let disclosed = windows_from(&lineage.sender_disclosed_spend, CHAIN_CONTEXT_BYTES);
    assert!(disclosed.intersection(&private).next().is_some());

    // The creation-to-spend link is derived, not copied, so the recurrence sweep does not
    // find it.
    assert!(
        published.intersection(&disclosed).next().is_none(),
        "the composed link is computational, so no field recurs to find it by"
    );
}

// The ledger records the same thing from a spend at every mask: no pruning, anchor is an
// input, and the nullifier is identical.
#[test]
fn the_ledger_effects_of_a_spend_do_not_depend_on_its_disclosure_mask() {
    let lineage = lineage();
    let disclosed = payload::effects(&validation_request(&lineage.sender_disclosed_spend))
        .expect("the disclosed spend must report effects");
    let private = payload::effects(&validation_request(&lineage.private_spend))
        .expect("the private spend must report effects");
    assert_eq!(
        disclosed, private,
        "disclosure must change nothing the chain records"
    );

    // Positive control: the encoding does distinguish payloads that settle differently.
    let creation = payload::effects(&validation_request(&lineage.disclosed_creation))
        .expect("the creation must report effects");
    let attestation = payload::effects(&validation_request(&lineage.attestation))
        .expect("the attestation must report effects");
    assert_ne!(disclosed, creation);
    assert_ne!(disclosed, attestation);
}

// The prover derives the mask-6 authority for a mask-7 spend too; only the payload omits it.
#[test]
fn the_mask_gates_publication_and_not_the_authority_itself() {
    let lineage = lineage();
    let spend = read_wire(&lineage.sender_disclosed_spend);
    assert_eq!(
        lineage.private_spend_authority, spend.sender_authorities[0],
        "the prover computes one authority per note, whatever the mask"
    );
    assert_eq!(lineage.private_spend_authority, lineage.spent.authority());
    assert!(!contains(
        &lineage.private_spend,
        &lineage.private_spend_authority
    ));
}

// Two spends of one note are linked to each other by the key image whatever they
// disclose, and a rerandomized commitment is not a second identifier.
#[test]
fn one_note_spent_twice_recurs_only_in_its_key_image() {
    let lineage = lineage();
    let disclosed = read_wire(&lineage.sender_disclosed_spend);
    let private = read_wire(&lineage.private_spend);

    assert_eq!(disclosed.key_images[0], private.key_images[0]);
    assert_eq!(disclosed.key_images[0], lineage.spent.key_image());
    assert_ne!(disclosed.pseudo_outs[0], private.pseudo_outs[0]);

    // Positive control: another note of the same wallet carries a different tag.
    let other = mint(&lineage.wallet, 0, 5_000, 909);
    assert_ne!(other.key_image(), private.key_images[0]);

    // Positive control: the sweep finds the tag the two payloads really do share.
    let left = windows_from(&lineage.sender_disclosed_spend, CHAIN_CONTEXT_BYTES);
    let right = windows_from(&lineage.private_spend, CHAIN_CONTEXT_BYTES);
    assert!(left.contains(&private.key_images[0]));
    assert!(right.contains(&private.key_images[0]));

    // With the tag replaced -- differently in each copy, so neither the replacement nor a
    // window straddling it can match -- the two payloads have nothing left in common.
    let left = redact(
        &lineage.sender_disclosed_spend,
        disclosed.key_image_offsets[0],
        32,
        0xa1,
    );
    let right = redact(
        &lineage.private_spend,
        private.key_image_offsets[0],
        32,
        0xb2,
    );
    assert!(
        windows_from(&left, CHAIN_CONTEXT_BYTES)
            .intersection(&windows_from(&right, CHAIN_CONTEXT_BYTES))
            .next()
            .is_none(),
        "two spends of one note share the key image and nothing else"
    );
}

// An attestation publishes the note's real linking tag, the same one its eventual spend
// publishes, so the spend is tied to the registered node identity.
#[test]
fn an_attestation_and_a_later_spend_publish_one_key_image() {
    let lineage = lineage();
    let attestation = read_wire(&lineage.attestation);
    let private = read_wire(&lineage.private_spend);

    assert_eq!(attestation.mask, 7);
    assert_eq!(private.mask, 7);
    assert_eq!(attestation.key_images.len(), 1);
    assert_eq!(
        attestation.key_images[0], private.key_images[0],
        "an attested note's spend republishes the attestation's key image"
    );
    assert_eq!(attestation.key_images[0], lineage.spent.key_image());

    // Positive control: the recurrence is the tag, not the whole payload.
    assert_ne!(attestation.pseudo_outs[0], private.pseudo_outs[0]);
    let other = mint(&lineage.wallet, 0, 1_234, 911);
    assert_ne!(other.key_image(), attestation.key_images[0]);

    let left = windows_from(&lineage.attestation, CHAIN_CONTEXT_BYTES);
    let right = windows_from(&lineage.private_spend, CHAIN_CONTEXT_BYTES);
    assert!(left.contains(&attestation.key_images[0]));
    assert!(right.contains(&attestation.key_images[0]));

    // The tag is the whole of it: with it replaced, an attestation and the spend of the
    // note it attested have no field in common.
    let left = redact(
        &lineage.attestation,
        attestation.key_image_offsets[0],
        32,
        0xc3,
    );
    let right = redact(
        &lineage.private_spend,
        private.key_image_offsets[0],
        32,
        0xd4,
    );
    assert!(
        windows_from(&left, CHAIN_CONTEXT_BYTES)
            .intersection(&windows_from(&right, CHAIN_CONTEXT_BYTES))
            .next()
            .is_none(),
        "the attestation link is the key image and nothing else"
    );
}

// Both ephemerals are present at every mask. A receiver disclosure opens only the tweak
// ephemeral's shared point; the note-key shared point never reaches the wire.
#[test]
fn every_output_carries_both_ephemerals_and_only_the_tweak_one_is_ever_opened() {
    for case in mask_sweep() {
        let MaskCase {
            address,
            first,
            second,
            payload,
        } = case;
        let mask = payload[MASK_OFFSET];
        let wire = read_wire(payload);
        assert_eq!(wire.mask, mask, "the mask is read from the payload bytes");
        assert_eq!(wire.note_ephemerals.len(), 2);
        assert_eq!(wire.tweak_ephemerals.len(), 2);

        for (index, note) in [first, second].into_iter().enumerate() {
            assert_eq!(wire.note_ephemerals[index], note.note_ephemeral());
            assert_eq!(wire.tweak_ephemerals[index], note.tweak_ephemeral());
            assert_ne!(wire.note_ephemerals[index], wire.tweak_ephemerals[index]);
            assert_ne!(wire.note_ephemerals[index], [0_u8; 32]);
            assert_ne!(wire.tweak_ephemerals[index], [0_u8; 32]);

            // The note key's shared point is absent at every mask, mask 0 included.
            assert!(
                !contains(payload, &note.note_shared(address)),
                "no mask publishes the point that keys a note ciphertext"
            );

            let tweak_shared = note.tweak_shared(address);
            if mask & 2 == 0 {
                assert_eq!(wire.receiver_shared_points[index], tweak_shared);
                assert!(contains(payload, &tweak_shared));
            } else {
                assert!(
                    !contains(payload, &tweak_shared),
                    "a hidden receiver publishes no shared point"
                );
            }
        }
    }
}

// One shape, eight masks: only the records the mask declares change, and a hidden field is
// absent from the whole payload.
#[test]
fn a_mask_changes_exactly_the_records_it_declares() {
    for case in mask_sweep() {
        let MaskCase {
            address,
            first,
            second,
            payload,
        } = case;
        let mask = payload[MASK_OFFSET];
        let wire = read_wire(payload);

        // A shield spends nothing, so no mask can publish a sender record here.
        assert!(wire.sender_authorities.is_empty());

        if mask & 2 == 0 {
            assert_eq!(wire.receiver_addresses.len(), 2);
            assert_eq!(wire.receiver_addresses[0], (address.spend, address.view));
            assert!(contains(payload, &address.spend));
            assert!(contains(payload, &address.view));
        } else {
            assert!(wire.receiver_addresses.is_empty());
            assert!(
                !contains(payload, &address.spend),
                "a hidden receiver's spend key is absent from the payload"
            );
            assert!(
                !contains(payload, &address.view),
                "a hidden receiver's view key is absent from the payload"
            );
        }

        for (index, note) in [first, second].into_iter().enumerate() {
            if mask & 4 == 0 {
                assert_eq!(
                    wire.disclosed_amounts[index],
                    (note.amount, note.mask.to_bytes())
                );
                assert!(contains(payload, &note.amount.to_le_bytes()));
                assert!(contains(payload, &note.mask.to_bytes()));
            } else {
                assert!(wire.disclosed_amounts.is_empty());
                assert!(
                    !contains(payload, &note.mask.to_bytes()),
                    "a hidden amount's opening is absent from the payload"
                );
            }
        }

        // The owner key, both ephemerals and the ciphertexts are published at every mask,
        // so no mask can be told from which of those fields is present.
        assert_eq!(wire.owners[0], first.owner());
        assert!(contains(payload, first.recipient_ciphertext()));
        assert!(contains(payload, second.outgoing_ciphertext()));
    }
}

// A disclosure publishes an address, not a way to recognize later payments to it.
#[test]
fn a_published_address_does_not_find_later_private_payments_to_it() {
    let lineage = lineage();
    let creation = read_wire(&lineage.disclosed_creation);
    let (spend, view) = creation.receiver_addresses[0];
    assert_eq!((spend, view), (lineage.wallet.spend, lineage.wallet.view));

    // A second note to the same address under mask 7. Its one-time key is predictable only
    // with the tweak ephemeral's shared point (wallet and payer).
    let later = mint(&lineage.wallet, 0, 3_000, 707);
    let hidden = build(&Spec {
        operation: NOTE_SHIELD,
        mask: 7,
        anchor: &empty_anchor(),
        spends: &[],
        outputs: &[(&later, &lineage.wallet)],
        transparent_value_balance: 3_050,
        fee: 50,
        registration_context: None,
        entropy: 0x29,
    })
    .payload;

    assert!(!contains(&hidden, &spend));
    assert!(!contains(&hidden, &view));
    assert!(!contains(&hidden, &later.tweak_shared(&lineage.wallet)));
    assert!(!contains(&hidden, &later.authority()));

    // And the earlier disclosure does not reach it: the two payloads share no field.
    let published = windows_from(&lineage.disclosed_creation, CHAIN_CONTEXT_BYTES);
    let private = windows_from(&hidden, CHAIN_CONTEXT_BYTES);
    assert!(published.intersection(&private).next().is_none());

    // The payee's address is likewise absent from the wallet's own later payload.
    assert!(!contains(&hidden, &lineage.payee.spend));
}

// The mask is inside the signing hash and fixes the disclosure section's length, so a
// payload cannot be relabelled or carry an extra record.
#[test]
fn a_finished_payload_has_no_room_for_a_record_its_mask_does_not_declare() {
    let lineage = lineage();

    // Positive controls: both payloads are accepted as they stand.
    assert!(payload::validate(&validation_request(&lineage.sender_disclosed_spend)).is_ok());
    assert!(payload::validate(&validation_request(&lineage.private_spend)).is_ok());

    let mut relabelled = lineage.sender_disclosed_spend.clone();
    relabelled[MASK_OFFSET] = 7;
    assert!(
        payload::validate(&validation_request(&relabelled)).is_err(),
        "a disclosed payload cannot be relabelled private"
    );

    let mut relabelled = lineage.private_spend.clone();
    relabelled[MASK_OFFSET] = 6;
    assert!(
        payload::validate(&validation_request(&relabelled)).is_err(),
        "a private payload cannot be relabelled disclosed"
    );

    // Inserting the unpublished sender proof into the empty disclosure vector is refused.
    let end = lineage.private_spend.len() - 1;
    assert_eq!(lineage.private_spend[end], 0);
    let mut spliced = lineage.private_spend[..end].to_vec();
    vector(&mut spliced, &lineage.private_spend_sender_proof);
    assert!(
        payload::validate(&validation_request(&spliced)).is_err(),
        "a mask-7 payload has no room for a sender proof"
    );

    // Control for that edit: re-terminating the same prefix reproduces the payload.
    let mut restored = lineage.private_spend[..end].to_vec();
    vector(&mut restored, &[]);
    assert_eq!(restored, lineage.private_spend);
    assert!(payload::validate(&validation_request(&restored)).is_ok());
}

/// Ask the note scanner to open one output's outgoing ciphertext under `secret`.
fn scan_outgoing(note: &Note, secret: &[u8; 32]) -> Option<Vec<u8>> {
    let mut request = Vec::with_capacity(236 + OUTGOING_CIPHERTEXT_BYTES);
    request.extend_from_slice(&1_u16.to_le_bytes());
    request.extend_from_slice(&[2, NETWORK, ADDRESS_TYPE, 0, 0, 0]);
    request.extend_from_slice(&note.index.to_le_bytes());
    request.extend_from_slice(&GENESIS);
    request.extend_from_slice(secret);
    request.extend_from_slice(&[0_u8; 32]);
    request.extend_from_slice(&note.owner());
    request.extend_from_slice(&note.commitment());
    request.extend_from_slice(&note.note_ephemeral());
    request.extend_from_slice(&note.tweak_ephemeral());
    request.extend_from_slice(note.outgoing_ciphertext());
    note::scan(&request).ok()
}

// The outgoing ciphertext opens under the sender's outgoing view secret at every mask,
// returning recipient, amount and opening; the scan checks both ephemeral secrets against
// the wire points.
#[test]
fn the_outgoing_key_opens_every_output_whatever_the_mask() {
    for case in mask_sweep() {
        let MaskCase {
            address,
            first,
            second,
            payload,
        } = case;
        for note in [first, second] {
            let opened = scan_outgoing(note, &address.outgoing)
                .expect("an outgoing ciphertext must open under its own secret");
            assert_eq!(opened.len(), 212);
            assert_eq!(
                u64::from_le_bytes(opened[12..20].try_into().expect("an amount")),
                note.amount
            );
            assert_eq!(array(&opened[20..52]), address.spend);
            assert_eq!(array(&opened[52..84]), address.view);
            assert_eq!(array(&opened[148..180]), note.mask.to_bytes());

            // The mask decided none of that: at mask 7 the payload named neither the
            // address nor the amount, and the scan returned both.
            if payload[MASK_OFFSET] == 7 {
                assert!(!contains(payload, &address.spend));
                assert!(!contains(payload, &note.mask.to_bytes()));
            }
        }

        // Positive control: another wallet's outgoing secret opens nothing here.
        let stranger = Address::new(999);
        assert!(scan_outgoing(first, &stranger.outgoing).is_none());
    }
}
