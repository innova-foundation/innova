use blake2::{digest::consts::U32, Blake2b};
use ciphersuite::group::{Group, GroupEncoding};
use curve25519_dalek::scalar::Scalar;
use helioselene::HeliosPoint;
use monero_fcmp_plus_plus::FcmpPlusPlus;
use sha2::{Digest, Sha256};

use zeroize::Zeroize;

use crate::{
    disclosure, envelope_allows, fcmp, validate_public_key, value, ResultCode, ADDRESS_TYPE_MAX,
    AUTH_M_OF_N_HIDDEN_SIGNERS, FINALITY_OBJECT_NONE, MAX_INPUTS, MAX_OUTPUTS, MAX_PAYLOAD_BYTES,
    NETWORK_ID_MAX, NOTE_SHIELD, NOTE_TRANSFER, NOTE_UNSHIELD, PAYLOAD_SCHEMA_U16,
    PRODUCT_CONTRACT, TREE_LAYERS,
};

/// `[wire version u32][network u8][reserved 3][genesis 32]`.
/// The caller supplies its own chain context and the parser compares.
const VALIDATION_PREFIX_SIZE: usize = 40;
const MAX_CIPHERTEXT_BYTES: usize = 4_096;
const MAX_FINALITY_BODY_BYTES: usize = 65_536;
const MAX_PROOF_SECTION_BYTES: usize = 65_536;
const TREE_CAPACITY: u64 = 38_u64.pow(4) * 18_u64.pow(4);
const SIGNING_DOMAIN: &[u8] = b"Innova/IV5/Signing/v1";
const EFFECTS_HEADER_BYTES: usize = 124;

struct PayloadEffects {
    finalized_root: [u8; 32],
    finalized_tree_size: u64,
    parameter_digest: [u8; 32],
    /// Signed value crossing the transparent boundary: positive enters the pool.
    transparent_value_balance: i64,
    fee: u64,
    /// Opaque commitment to the including transaction's transparent side.
    transparent_binding: [u8; 32],
    key_images: Vec<[u8; 32]>,
    output_leaves: Vec<([u8; 32], [u8; 32], [u8; 32])>,
}

impl PayloadEffects {
    fn encode(&self) -> Result<Vec<u8>, ResultCode> {
        let capacity = EFFECTS_HEADER_BYTES
            .checked_add(self.key_images.len() * 32)
            .and_then(|size| size.checked_add(self.output_leaves.len() * 96))
            .ok_or(ResultCode::ResourceLimit)?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        encoded.push(u8::try_from(self.key_images.len()).map_err(|_| ResultCode::ResourceLimit)?);
        encoded
            .push(u8::try_from(self.output_leaves.len()).map_err(|_| ResultCode::ResourceLimit)?);
        encoded.extend_from_slice(&self.finalized_root);
        encoded.extend_from_slice(&self.finalized_tree_size.to_le_bytes());
        encoded.extend_from_slice(&self.parameter_digest);
        // The caller needs both to derive what the pool gained or lost:
        // pool delta = transparent value balance - fee, for every operation.
        encoded.extend_from_slice(&self.transparent_value_balance.to_le_bytes());
        encoded.extend_from_slice(&self.fee.to_le_bytes());
        // The caller checks this against the transaction carrying the payload; the
        // digest's construction is the caller's, so it stays opaque here.
        encoded.extend_from_slice(&self.transparent_binding);
        for key_image in &self.key_images {
            encoded.extend_from_slice(key_image);
        }
        for (owner, nullifier_base, commitment) in &self.output_leaves {
            encoded.extend_from_slice(owner);
            encoded.extend_from_slice(nullifier_base);
            encoded.extend_from_slice(commitment);
        }
        Ok(encoded)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ResultCode> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ResultCode::ResourceLimit)?;
        if end > self.bytes.len() {
            return Err(ResultCode::ConsensusInvalid);
        }
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ResultCode> {
        self.take(N)?
            .try_into()
            .map_err(|_| ResultCode::InternalLocalStateFailure)
    }

    fn u8(&mut self) -> Result<u8, ResultCode> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ResultCode> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ResultCode> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ResultCode> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, ResultCode> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    fn compact_size(&mut self) -> Result<u64, ResultCode> {
        match self.u8()? {
            value @ 0..=252 => Ok(u64::from(value)),
            253 => {
                let value = self.u16()?;
                if value < 253 {
                    return Err(ResultCode::ConsensusInvalid);
                }
                Ok(u64::from(value))
            }
            254 => {
                let value = self.u32()?;
                if u16::try_from(value).is_ok() {
                    return Err(ResultCode::ConsensusInvalid);
                }
                Ok(u64::from(value))
            }
            255 => {
                let value = self.u64()?;
                if u32::try_from(value).is_ok() {
                    return Err(ResultCode::ConsensusInvalid);
                }
                Ok(value)
            }
        }
    }

    fn vector(&mut self, maximum: usize) -> Result<&'a [u8], ResultCode> {
        let length =
            usize::try_from(self.compact_size()?).map_err(|_| ResultCode::ResourceLimit)?;
        if length > maximum {
            return Err(ResultCode::ResourceLimit);
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), ResultCode> {
        if self.position != self.bytes.len() {
            return Err(ResultCode::ConsensusInvalid);
        }
        Ok(())
    }

    const fn position(&self) -> usize {
        self.position
    }
}

fn validate_nonzero(bytes: &[u8]) -> Result<(), ResultCode> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(())
}

fn validate_ed25519_point(bytes: [u8; 32]) -> Result<(), ResultCode> {
    validate_public_key(bytes)
}

fn validate_helios_point(bytes: [u8; 32]) -> Result<(), ResultCode> {
    let point = Option::<HeliosPoint>::from(HeliosPoint::from_bytes(&bytes))
        .ok_or(ResultCode::ConsensusInvalid)?;
    if bool::from(point.is_identity()) || point.to_bytes() != bytes {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(())
}

fn validate_scalar(bytes: [u8; 32], nonzero: bool) -> Result<(), ResultCode> {
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(ResultCode::ConsensusInvalid)?;
    if nonzero && scalar == Scalar::ZERO {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(())
}

fn bounded_count(cursor: &mut Cursor<'_>, maximum: u32) -> Result<usize, ResultCode> {
    let count = cursor.compact_size()?;
    if count > u64::from(maximum) {
        return Err(ResultCode::ResourceLimit);
    }
    usize::try_from(count).map_err(|_| ResultCode::ResourceLimit)
}

fn signable_hash(wire_version: u32, payload_prefix: &[u8]) -> [u8; 32] {
    let mut transcript = Blake2b::<U32>::new();
    transcript.update(SIGNING_DOMAIN);
    transcript.update(wire_version.to_le_bytes());
    transcript.update(payload_prefix);
    transcript.finalize().into()
}

/// A note is only openable in the one encoding a wallet knows, so an output carrying
/// any other length or version byte is unspendable the moment it enters the tree.
fn read_ciphertext(cursor: &mut Cursor<'_>, expected: usize) -> Result<Vec<u8>, ResultCode> {
    let bytes = cursor.vector(MAX_CIPHERTEXT_BYTES)?;
    if bytes.len() != expected || bytes[0] != crate::note::CIPHERTEXT_VERSION {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(bytes.to_vec())
}

/// Everything a canonical payload declares before its disclosures and proofs.
struct PayloadPrefix<'a> {
    cursor: Cursor<'a>,
    disclosure_mask: u8,
    finality_object: u8,
    genesis: [u8; 32],
    parameter_digest: [u8; 32],
    finalized_root: [u8; 32],
    finalized_tree_size: u64,
    transparent_value_balance: i64,
    fee: u64,
    transparent_binding: [u8; 32],
    pseudo_outs: Vec<[u8; 32]>,
    key_images: Vec<[u8; 32]>,
    output_owners: Vec<[u8; 32]>,
    /// Derived from each owner key, never read from the wire.
    output_nullifier_bases: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    /// Keys the recipient ciphertext; never published by any disclosure.
    output_note_ephemerals: Vec<[u8; 32]>,
    /// Determines the address tweak; a receiver disclosure publishes its shared point.
    output_tweak_ephemerals: Vec<[u8; 32]>,
    output_recipient_ciphertexts: Vec<Vec<u8>>,
    output_outgoing_ciphertexts: Vec<Vec<u8>>,
}

/// Read the header, inputs and outputs of a canonical payload. Shared by validation
/// and scanning; `expected_genesis` is absent only for a scan.
#[allow(clippy::too_many_lines)] // Mirrors the normative payload field order in one audit path.
fn parse_payload_prefix<'a>(
    wire_version: u32,
    payload: &'a [u8],
    expected_network: u8,
    expected_genesis: Option<&[u8; 32]>,
) -> Result<PayloadPrefix<'a>, ResultCode> {
    let mut cursor = Cursor::new(payload);
    if cursor.u16()? != PAYLOAD_SCHEMA_U16 {
        return Err(ResultCode::UnsupportedFormat);
    }
    let operation = cursor.u8()?;
    let profile = cursor.u8()?;
    let authorization = cursor.u8()?;
    let disclosure_mask = cursor.u8()?;
    let finality_object = cursor.u8()?;
    let network = cursor.u8()?;
    if cursor.u8()? != 0 {
        return Err(ResultCode::ConsensusInvalid);
    }
    // Pinned here rather than left to the caller: a payload built for another chain is
    // not this chain's to accept, and a field consensus only parses is a field an
    // attacker chooses freely.
    if network != expected_network
        || network > NETWORK_ID_MAX
        || authorization > AUTH_M_OF_N_HIDDEN_SIGNERS
        || !envelope_allows(
            wire_version,
            operation,
            profile,
            authorization,
            finality_object,
            disclosure_mask,
        )
    {
        return Err(ResultCode::ConsensusInvalid);
    }
    // Extended operations fail closed before proof verification until their typed frame and
    // verifier exist.
    if finality_object != FINALITY_OBJECT_NONE
        || !matches!(operation, NOTE_SHIELD | NOTE_UNSHIELD | NOTE_TRANSFER)
    {
        return Err(ResultCode::UnsupportedFormat);
    }

    let genesis = cursor.array::<32>()?;
    validate_nonzero(&genesis)?;
    if expected_genesis.is_some_and(|expected| *expected != genesis) {
        return Err(ResultCode::ConsensusInvalid);
    }
    let parameter_digest = cursor.array::<32>()?;
    if parameter_digest.as_slice() != &Sha256::digest(PRODUCT_CONTRACT)[..] {
        return Err(ResultCode::ConsensusInvalid);
    }
    let finalized_root = cursor.array()?;
    validate_helios_point(finalized_root)?;
    let finalized_tree_size = cursor.u64()?;
    if finalized_tree_size > TREE_CAPACITY {
        return Err(ResultCode::ResourceLimit);
    }
    let transparent_value_balance = cursor.i64()?;
    let fee = cursor.u64()?;
    // Sits inside the region the signing hash covers, so the proofs bind to it and the
    // transparent side of the transaction can no longer be rewritten after proving. Any
    // 32 bytes are structurally valid: what they must equal is the caller's rule.
    let transparent_binding = cursor.array::<32>()?;

    let input_count = bounded_count(&mut cursor, MAX_INPUTS)?;
    let mut pseudo_outs = Vec::with_capacity(input_count);
    let mut key_images = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let pseudo_out = cursor.array()?;
        validate_ed25519_point(pseudo_out)?;
        pseudo_outs.push(pseudo_out);
        let key_image = cursor.array()?;
        validate_ed25519_point(key_image)?;
        key_images.push(key_image);
    }

    let output_count = bounded_count(&mut cursor, MAX_OUTPUTS)?;
    let mut output_owners = Vec::with_capacity(output_count);
    let mut output_nullifier_bases = Vec::with_capacity(output_count);
    let mut output_commitments = Vec::with_capacity(output_count);
    let mut output_note_ephemerals = Vec::with_capacity(output_count);
    let mut output_tweak_ephemerals = Vec::with_capacity(output_count);
    let mut output_recipient_ciphertexts = Vec::with_capacity(output_count);
    let mut output_outgoing_ciphertexts = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let owner = cursor.array()?;
        validate_ed25519_point(owner)?;
        // I = Hp(O), so two leaves that share O share a key image: whichever is spent
        // first consumes both, and the value behind the other is unrecoverable.
        if output_owners.contains(&owner) {
            return Err(ResultCode::ConsensusInvalid);
        }
        output_owners.push(owner);
        // I is derived, not declared: a sender that could choose it could publish owner
        // material and link every note paid to one address.
        output_nullifier_bases.push(crate::note::key_image_base_checked(&owner)?);
        let commitment = cursor.array()?;
        validate_ed25519_point(commitment)?;
        output_commitments.push(commitment);
        // Two ephemerals: the first keys the note, the second determines the tweak and is
        // the only one a receiver disclosure ever opens.
        let note_ephemeral = cursor.array()?;
        validate_ed25519_point(note_ephemeral)?;
        let tweak_ephemeral = cursor.array()?;
        validate_ed25519_point(tweak_ephemeral)?;
        if note_ephemeral == tweak_ephemeral {
            return Err(ResultCode::ConsensusInvalid);
        }
        output_note_ephemerals.push(note_ephemeral);
        output_tweak_ephemerals.push(tweak_ephemeral);
        // Pinned lengths, not a range: a length consensus accepts but the scanner
        // rejects is a caller-fatal code a peer gets to choose.
        let recipient_ciphertext =
            read_ciphertext(&mut cursor, crate::note::RECIPIENT_CIPHERTEXT_BYTES)?;
        let outgoing_ciphertext =
            read_ciphertext(&mut cursor, crate::note::OUTGOING_CIPHERTEXT_BYTES)?;
        output_recipient_ciphertexts.push(recipient_ciphertext);
        output_outgoing_ciphertexts.push(outgoing_ciphertext);
    }

    Ok(PayloadPrefix {
        cursor,
        disclosure_mask,
        finality_object,
        genesis,
        parameter_digest,
        finalized_root,
        finalized_tree_size,
        transparent_value_balance,
        fee,
        transparent_binding,
        pseudo_outs,
        key_images,
        output_owners,
        output_nullifier_bases,
        output_commitments,
        output_note_ephemerals,
        output_tweak_ephemerals,
        output_recipient_ciphertexts,
        output_outgoing_ciphertexts,
    })
}

#[allow(clippy::too_many_lines)] // Mirrors the normative payload field order in one audit path.
fn validate_payload(
    wire_version: u32,
    payload: &[u8],
    expected_network: u8,
    expected_genesis: &[u8; 32],
) -> Result<PayloadEffects, ResultCode> {
    let PayloadPrefix {
        mut cursor,
        disclosure_mask,
        finality_object,
        parameter_digest,
        finalized_root,
        finalized_tree_size,
        transparent_value_balance,
        fee,
        transparent_binding,
        pseudo_outs,
        key_images,
        output_owners,
        output_nullifier_bases,
        output_commitments,
        output_tweak_ephemerals,
        ..
    } = parse_payload_prefix(
        wire_version,
        payload,
        expected_network,
        Some(expected_genesis),
    )?;
    let input_count = key_images.len();
    let output_count = output_owners.len();

    let mut sender_authorities = Vec::new();
    if disclosure_mask & 1 == 0 {
        sender_authorities.reserve(input_count);
        for _ in 0..input_count {
            let authority = cursor.array()?;
            validate_ed25519_point(authority)?;
            sender_authorities.push(authority);
        }
    }
    let mut receiver_addresses = Vec::new();
    if disclosure_mask & 2 == 0 {
        receiver_addresses.reserve(output_count);
        for _ in 0..output_count {
            let spend = cursor.array()?;
            let view = cursor.array()?;
            validate_ed25519_point(spend)?;
            validate_ed25519_point(view)?;
            receiver_addresses.push((spend, view));
        }
    }
    if disclosure_mask & 4 == 0 {
        for commitment in &output_commitments {
            let value = cursor.u64()?;
            let opening = cursor.array()?;
            validate_scalar(opening, false)?;
            if !value::validate_disclosed_commitment(commitment, value, &opening)
                .map_err(|_| ResultCode::ConsensusInvalid)?
            {
                return Err(ResultCode::ConsensusInvalid);
            }
        }
    }

    let finality_body = cursor.vector(MAX_FINALITY_BODY_BYTES)?;
    if (finality_object == FINALITY_OBJECT_NONE) != finality_body.is_empty() {
        return Err(ResultCode::ConsensusInvalid);
    }
    let signing_hash = signable_hash(wire_version, &payload[..cursor.position()]);

    let membership = cursor.vector(MAX_PROOF_SECTION_BYTES)?;
    let expected_membership = if input_count == 0 {
        0
    } else {
        FcmpPlusPlus::proof_size(input_count, TREE_LAYERS as usize)
    };
    if membership.len() != expected_membership {
        return Err(ResultCode::ConsensusInvalid);
    }
    if input_count != 0 {
        fcmp::verify_components(
            finalized_root,
            signing_hash,
            &pseudo_outs,
            &key_images,
            membership,
        )?;
    }

    let range = cursor.vector(MAX_PROOF_SECTION_BYTES)?;
    let requires_range = output_count != 0 && disclosure_mask & 4 != 0;
    if requires_range == range.is_empty() {
        return Err(ResultCode::ConsensusInvalid);
    }
    if requires_range
        && !value::verify_range(&output_commitments, range, &signing_hash).map_err(|error| {
            match error {
                value::ValueError::ResourceLimit => ResultCode::ResourceLimit,
                _ => ResultCode::ConsensusInvalid,
            }
        })?
    {
        return Err(ResultCode::ConsensusInvalid);
    }

    let balance_proof = cursor.vector(MAX_PROOF_SECTION_BYTES)?;
    if balance_proof.is_empty()
        || !value::verify_balance(
            &pseudo_outs,
            &output_commitments,
            transparent_value_balance,
            fee,
            &signing_hash,
            balance_proof,
        )
        .map_err(|error| match error {
            value::ValueError::ResourceLimit => ResultCode::ResourceLimit,
            _ => ResultCode::ConsensusInvalid,
        })?
    {
        return Err(ResultCode::ConsensusInvalid);
    }

    let operation_proof = cursor.vector(MAX_PROOF_SECTION_BYTES)?;
    if !operation_proof.is_empty() {
        return Err(ResultCode::ConsensusInvalid);
    }

    let disclosure_proof = cursor.vector(MAX_PROOF_SECTION_BYTES)?;
    let expected_disclosure_proof = sender_authorities
        .len()
        .checked_mul(disclosure::SENDER_PROOF_BYTES)
        .and_then(|bytes| {
            receiver_addresses
                .len()
                .checked_mul(disclosure::RECEIVER_PROOF_BYTES)
                .and_then(|receiver_bytes| bytes.checked_add(receiver_bytes))
        })
        .ok_or(ResultCode::ResourceLimit)?;
    if disclosure_proof.len() != expected_disclosure_proof {
        return Err(ResultCode::ConsensusInvalid);
    }
    let mut disclosure_offset = 0_usize;
    for (input_index, authority) in sender_authorities.iter().enumerate() {
        let end = disclosure_offset + disclosure::SENDER_PROOF_BYTES;
        let o_tilde = fcmp::input_o_tilde(membership, input_count, input_index)?;
        if !disclosure::verify_sender(
            authority,
            &o_tilde,
            &signing_hash,
            u32::try_from(input_index).map_err(|_| ResultCode::ResourceLimit)?,
            &disclosure_proof[disclosure_offset..end],
        )
        .map_err(|_| ResultCode::ConsensusInvalid)?
        {
            return Err(ResultCode::ConsensusInvalid);
        }
        disclosure_offset = end;
    }
    for (output_index, (spend, view)) in receiver_addresses.iter().enumerate() {
        let end = disclosure_offset + disclosure::RECEIVER_PROOF_BYTES;
        if !disclosure::verify_receiver(
            spend,
            view,
            &output_owners[output_index],
            &output_tweak_ephemerals[output_index],
            &signing_hash,
            u32::try_from(output_index).map_err(|_| ResultCode::ResourceLimit)?,
            &disclosure_proof[disclosure_offset..end],
        )
        .map_err(|_| ResultCode::ConsensusInvalid)?
        {
            return Err(ResultCode::ConsensusInvalid);
        }
        disclosure_offset = end;
    }

    let binding_signature = cursor.vector(MAX_PROOF_SECTION_BYTES)?;
    if !value::verify_binding_signature(
        &pseudo_outs,
        &output_commitments,
        transparent_value_balance,
        fee,
        &signing_hash,
        binding_signature,
    )
    .map_err(|error| match error {
        value::ValueError::ResourceLimit => ResultCode::ResourceLimit,
        _ => ResultCode::ConsensusInvalid,
    })? {
        return Err(ResultCode::ConsensusInvalid);
    }
    cursor.finish()?;
    let output_leaves = output_owners
        .into_iter()
        .zip(output_nullifier_bases)
        .zip(output_commitments)
        .map(|((owner, nullifier_base), commitment)| (owner, nullifier_base, commitment))
        .collect();
    Ok(PayloadEffects {
        finalized_root,
        finalized_tree_size,
        parameter_digest,
        transparent_value_balance,
        fee,
        transparent_binding,
        key_images,
        output_leaves,
    })
}

/// The local chain context a validation request carries, and the payload it judges.
struct ValidationRequest<'a> {
    wire_version: u32,
    network: u8,
    genesis: [u8; 32],
    payload: &'a [u8],
}

/// Split a validation request into the local chain context and the payload it judges.
fn request_parts(request: &[u8]) -> Result<ValidationRequest<'_>, ResultCode> {
    if request.len() < VALIDATION_PREFIX_SIZE + 1 {
        return Err(ResultCode::BadLength);
    }
    if request.len() > (MAX_PAYLOAD_BYTES as usize) + VALIDATION_PREFIX_SIZE {
        return Err(ResultCode::ResourceLimit);
    }
    let wire_version = u32::from_le_bytes(
        request[..4]
            .try_into()
            .map_err(|_| ResultCode::InternalLocalStateFailure)?,
    );
    let network = request[4];
    if request[5..8] != [0_u8; 3] || network > NETWORK_ID_MAX {
        return Err(ResultCode::BadLength);
    }
    let genesis: [u8; 32] = request[8..VALIDATION_PREFIX_SIZE]
        .try_into()
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
    if genesis.iter().all(|byte| *byte == 0) {
        return Err(ResultCode::BadLength);
    }
    Ok(ValidationRequest {
        wire_version,
        network,
        genesis,
        payload: &request[VALIDATION_PREFIX_SIZE..],
    })
}

const SCAN_REQUEST_HEADER_BYTES: usize = 16;
const SCAN_KEY_BYTES: usize = 64;
const MAX_SCAN_KEYS: usize = 1024;
const SCAN_RESPONSE_HEADER_BYTES: usize = 6;
const NOTE_SCAN_PREFIX_BYTES: usize = 236;
const NOTE_SCAN_RESULT_BYTES: usize = 212;
const SCAN_RECORD_BYTES: usize = 2 + 4 + 96 + NOTE_SCAN_RESULT_BYTES;
const SCAN_OUTGOING: u8 = 2;

/// Try every output of one payload with the caller's scanning material, emitting
/// the matched leaf so the caller can check it against the consensus leaf.
#[allow(clippy::too_many_lines)] // Mirrors the normative payload field order in one audit path.
pub(crate) fn scan_outputs(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    if request.len() <= SCAN_REQUEST_HEADER_BYTES {
        return Err(ResultCode::BadLength);
    }
    if u16::from_le_bytes([request[0], request[1]]) != PAYLOAD_SCHEMA_U16 {
        return Err(ResultCode::UnsupportedFormat);
    }
    let scan_kind = request[2];
    let network = request[3];
    let address_type = request[4];
    if request[5..8] != [0_u8; 3] || request[14..16] != [0_u8; 2] {
        return Err(ResultCode::ConsensusInvalid);
    }
    if network > NETWORK_ID_MAX || address_type > ADDRESS_TYPE_MAX {
        return Err(ResultCode::ConsensusInvalid);
    }
    if scan_kind > SCAN_OUTGOING {
        return Err(ResultCode::UnsupportedFormat);
    }
    let wire_version = u32::from_le_bytes(
        request[8..12]
            .try_into()
            .map_err(|_| ResultCode::BadLength)?,
    );
    let key_count = usize::from(u16::from_le_bytes([request[12], request[13]]));
    if key_count == 0 {
        return Err(ResultCode::BadLength);
    }
    if key_count > MAX_SCAN_KEYS {
        return Err(ResultCode::ResourceLimit);
    }
    let payload_start = SCAN_REQUEST_HEADER_BYTES
        .checked_add(
            key_count
                .checked_mul(SCAN_KEY_BYTES)
                .ok_or(ResultCode::ResourceLimit)?,
        )
        .ok_or(ResultCode::ResourceLimit)?;
    if request.len() <= payload_start {
        return Err(ResultCode::BadLength);
    }

    // The scanner holds no independent genesis, so the chain binding is authenticated
    // by the note tag rather than compared here.
    let prefix = parse_payload_prefix(wire_version, &request[payload_start..], network, None)?;

    let key_image_count =
        u8::try_from(prefix.key_images.len()).map_err(|_| ResultCode::ResourceLimit)?;
    let mut records = Vec::new();
    let mut matches: u8 = 0;
    for index in 0..prefix.output_owners.len() {
        let ciphertext = if scan_kind == SCAN_OUTGOING {
            &prefix.output_outgoing_ciphertexts[index]
        } else {
            &prefix.output_recipient_ciphertexts[index]
        };
        let output_index = u32::try_from(index).map_err(|_| ResultCode::ResourceLimit)?;

        // A note opens for at most one key, so the first that authenticates ends the
        // search for this output.
        for key in 0..key_count {
            let key_at = SCAN_REQUEST_HEADER_BYTES + (key * SCAN_KEY_BYTES);
            let mut scan_request = Vec::with_capacity(NOTE_SCAN_PREFIX_BYTES + ciphertext.len());
            scan_request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
            scan_request.push(scan_kind);
            scan_request.push(network);
            scan_request.push(address_type);
            scan_request.extend_from_slice(&[0_u8; 3]);
            scan_request.extend_from_slice(&output_index.to_le_bytes());
            scan_request.extend_from_slice(&prefix.genesis);
            scan_request.extend_from_slice(&request[key_at..key_at + 32]);
            scan_request.extend_from_slice(&request[key_at + 32..key_at + 64]);
            scan_request.extend_from_slice(&prefix.output_owners[index]);
            scan_request.extend_from_slice(&prefix.output_commitments[index]);
            scan_request.extend_from_slice(&prefix.output_note_ephemerals[index]);
            scan_request.extend_from_slice(&prefix.output_tweak_ephemerals[index]);
            scan_request.extend_from_slice(ciphertext);

            // Bytes here are peer-chosen: an output this key cannot open is simply not
            // ours, whatever the failure, so no scan failure may propagate to the caller.
            let scanned = match crate::note::scan(&scan_request) {
                Ok(scanned) if scanned.len() == NOTE_SCAN_RESULT_BYTES => scanned,
                _ => {
                    scan_request.zeroize();
                    continue;
                }
            };
            scan_request.zeroize();

            let key_index = u16::try_from(key).map_err(|_| ResultCode::ResourceLimit)?;
            records.extend_from_slice(&key_index.to_le_bytes());
            records.extend_from_slice(&output_index.to_le_bytes());
            records.extend_from_slice(&prefix.output_owners[index]);
            records.extend_from_slice(&prefix.output_nullifier_bases[index]);
            records.extend_from_slice(&prefix.output_commitments[index]);
            records.extend_from_slice(&scanned);
            matches = matches.checked_add(1).ok_or(ResultCode::ResourceLimit)?;
            break;
        }
    }

    // The output count lets a caller place its notes in the tree without decoding
    // the payloads it does not own.
    let output_count =
        u8::try_from(prefix.output_owners.len()).map_err(|_| ResultCode::ResourceLimit)?;
    let mut result = Vec::new();
    result.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    result.push(matches);
    result.push(key_image_count);
    result.push(output_count);
    result.push(0);
    for key_image in &prefix.key_images {
        result.extend_from_slice(key_image);
    }
    result.extend_from_slice(&records);
    if result.len()
        != SCAN_RESPONSE_HEADER_BYTES
            + (usize::from(key_image_count) * 32)
            + (usize::from(matches) * SCAN_RECORD_BYTES)
    {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    Ok(result)
}

pub(crate) fn validate(request: &[u8]) -> Result<(), ResultCode> {
    let ValidationRequest {
        wire_version,
        network,
        genesis,
        payload,
    } = request_parts(request)?;
    validate_payload(wire_version, payload, network, &genesis).map(|_| ())
}

/// Hash of the serialized payload prefix; the single definition shared by builder
/// and validator.
pub(crate) fn signing_hash(request: &[u8]) -> Result<[u8; 32], ResultCode> {
    if request.len() < VALIDATION_PREFIX_SIZE + 4 {
        return Err(ResultCode::BadLength);
    }
    if u16::from_le_bytes([request[0], request[1]]) != PAYLOAD_SCHEMA_U16 {
        return Err(ResultCode::UnsupportedFormat);
    }
    if request[2] != 0 || request[3] != 0 {
        return Err(ResultCode::ConsensusInvalid);
    }
    let wire_version = u32::from_le_bytes(
        request[4..8]
            .try_into()
            .map_err(|_| ResultCode::BadLength)?,
    );
    Ok(signable_hash(wire_version, &request[8..]))
}

pub(crate) fn effects(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    let ValidationRequest {
        wire_version,
        network,
        genesis,
        payload,
    } = request_parts(request)?;
    validate_payload(wire_version, payload, network, &genesis)?.encode()
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{
        constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    };

    use super::*;
    use crate::tree;

    // Stands in for whatever the caller commits its transparent side to; the payload
    // decoder carries these bytes and never interprets them.
    const TEST_TRANSPARENT_BINDING: [u8; 32] = [0x5a; 32];
    const TEST_NETWORK: u8 = 1;
    const TEST_GENESIS: [u8; 32] = [0x11; 32];

    fn validation_request(payload: &[u8]) -> Vec<u8> {
        validation_request_for(TEST_NETWORK, &TEST_GENESIS, payload)
    }

    fn validation_request_for(network: u8, genesis: &[u8; 32], payload: &[u8]) -> Vec<u8> {
        let mut request = 2008_u32.to_le_bytes().to_vec();
        request.push(network);
        request.extend_from_slice(&[0_u8; 3]);
        request.extend_from_slice(genesis);
        request.extend_from_slice(payload);
        request
    }

    // A ciphertext of the canonical length whose body no key can open.
    fn opaque_ciphertext(length: usize) -> Vec<u8> {
        let mut bytes = vec![0x5c_u8; length];
        bytes[0] = crate::note::CIPHERTEXT_VERSION;
        bytes
    }

    // Fields of a canonical note-encryption result.
    const ENCRYPTED_O: core::ops::Range<usize> = 8..40;
    const ENCRYPTED_C: core::ops::Range<usize> = 72..104;
    const ENCRYPTED_TWEAK_EPHEMERAL: core::ops::Range<usize> = 136..168;
    const ENCRYPTED_EPHEMERALS: core::ops::Range<usize> = 104..168;
    const ENCRYPTED_RECIPIENT: core::ops::Range<usize> = 168..345;
    const ENCRYPTED_OUTGOING: core::ops::Range<usize> = 345..586;

    // One output record, in payload order: O, C, both ephemerals, then the ciphertexts.
    fn put_output(payload: &mut Vec<u8>, encrypted: &[u8]) {
        payload.extend_from_slice(&encrypted[ENCRYPTED_O]);
        payload.extend_from_slice(&encrypted[ENCRYPTED_C]);
        payload.extend_from_slice(&encrypted[ENCRYPTED_EPHEMERALS]);
        vector(payload, &encrypted[ENCRYPTED_RECIPIENT]);
        vector(payload, &encrypted[ENCRYPTED_OUTGOING]);
    }

    fn compact_size(output: &mut Vec<u8>, value: usize) {
        if value <= 252 {
            output.push(u8::try_from(value).expect("compact test value is bounded"));
        } else if u16::try_from(value).is_ok() {
            output.push(253);
            output.extend_from_slice(
                &u16::try_from(value)
                    .expect("compact test value fits u16")
                    .to_le_bytes(),
            );
        } else {
            output.push(254);
            output.extend_from_slice(
                &u32::try_from(value)
                    .expect("compact test value fits u32")
                    .to_le_bytes(),
            );
        }
    }

    fn vector(output: &mut Vec<u8>, bytes: &[u8]) {
        compact_size(output, bytes.len());
        output.extend_from_slice(bytes);
    }

    fn valid_request() -> Vec<u8> {
        let point = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let second_point = (ED25519_BASEPOINT_POINT * Scalar::from(2_u64))
            .compress()
            .to_bytes();
        let output_mask = Scalar::from(3_u64).to_bytes();
        let output_commitment = value::commitment(9, &output_mask).expect("valid commitment");
        let state = tree::update(&[1, 0, 1, 0, 0, 0, 0, 0]).expect("empty canonical tree state");
        let root = tree::root(&state).expect("empty canonical tree root");
        let mut payload = Vec::new();
        payload.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        payload.extend_from_slice(&[NOTE_SHIELD, 0, 0, 7, FINALITY_OBJECT_NONE, 1, 0]);
        payload.extend_from_slice(&[0x11; 32]);
        payload.extend_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
        payload.extend_from_slice(&root[12..44]);
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&10_i64.to_le_bytes());
        payload.extend_from_slice(&1_u64.to_le_bytes());
        payload.extend_from_slice(&TEST_TRANSPARENT_BINDING);

        compact_size(&mut payload, 0);

        compact_size(&mut payload, 1);
        payload.extend_from_slice(&point);
        payload.extend_from_slice(&output_commitment);
        payload.extend_from_slice(&point);
        payload.extend_from_slice(&second_point);
        vector(
            &mut payload,
            &opaque_ciphertext(crate::note::RECIPIENT_CIPHERTEXT_BYTES),
        );
        vector(
            &mut payload,
            &opaque_ciphertext(crate::note::OUTGOING_CIPHERTEXT_BYTES),
        );

        vector(&mut payload, &[]);
        let signing_hash = signable_hash(2008, &payload);
        let (range_commitments, range_proof) =
            value::prove_range(&[9], &[output_mask], &[0x41; 32]).expect("valid range proof");
        assert_eq!(range_commitments, vec![output_commitment]);
        let balance_proof = value::prove_balance(
            &[],
            &[output_commitment],
            10,
            1,
            &(-Scalar::from(3_u64)).to_bytes(),
            &signing_hash,
            &[0x42; 32],
        )
        .expect("valid balance proof");
        let binding_signature = value::prove_binding_signature(
            &[],
            &[output_commitment],
            10,
            1,
            &(-Scalar::from(3_u64)).to_bytes(),
            &signing_hash,
            &[0x43; 32],
        )
        .expect("valid binding signature");
        vector(&mut payload, &[]);
        vector(&mut payload, &range_proof);
        vector(&mut payload, &balance_proof);
        vector(&mut payload, &[]);
        vector(&mut payload, &[]);
        vector(&mut payload, &binding_signature);

        validation_request(&payload)
    }

    // A shield that publishes its amount. `declared` is what the disclosure record says;
    // the commitment is always over `true_amount`, and every proof is made over whatever
    // prefix results, so a lie here is not a corrupted payload but a consistent one.
    fn disclosed_amount_request(true_amount: u64, declared: u64) -> Vec<u8> {
        disclosed_amount_request_with_range(true_amount, declared, false)
    }

    fn disclosed_amount_request_with_range(
        true_amount: u64,
        declared: u64,
        include_range: bool,
    ) -> Vec<u8> {
        let point = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let second_point = (ED25519_BASEPOINT_POINT * Scalar::from(2_u64))
            .compress()
            .to_bytes();
        let output_mask = Scalar::from(3_u64).to_bytes();
        let output_commitment =
            value::commitment(true_amount, &output_mask).expect("valid commitment");
        let state = tree::update(&[1, 0, 1, 0, 0, 0, 0, 0]).expect("empty canonical tree state");
        let root = tree::root(&state).expect("empty canonical tree root");
        let fee = 1_u64;
        let balance = i64::try_from(true_amount).expect("test amount fits") + 1;
        let mut payload = Vec::new();
        payload.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        // Mask 3 keeps the sender and the recipient hidden and publishes the amounts.
        payload.extend_from_slice(&[NOTE_SHIELD, 0, 0, 3, FINALITY_OBJECT_NONE, 1, 0]);
        payload.extend_from_slice(&[0x11; 32]);
        payload.extend_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
        payload.extend_from_slice(&root[12..44]);
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&balance.to_le_bytes());
        payload.extend_from_slice(&fee.to_le_bytes());
        payload.extend_from_slice(&TEST_TRANSPARENT_BINDING);

        compact_size(&mut payload, 0);
        compact_size(&mut payload, 1);
        payload.extend_from_slice(&point);
        payload.extend_from_slice(&output_commitment);
        payload.extend_from_slice(&point);
        payload.extend_from_slice(&second_point);
        vector(
            &mut payload,
            &opaque_ciphertext(crate::note::RECIPIENT_CIPHERTEXT_BYTES),
        );
        vector(
            &mut payload,
            &opaque_ciphertext(crate::note::OUTGOING_CIPHERTEXT_BYTES),
        );

        payload.extend_from_slice(&declared.to_le_bytes());
        payload.extend_from_slice(&output_mask);
        vector(&mut payload, &[]);

        let signing_hash = signable_hash(2008, &payload);
        let excess = (-Scalar::from(3_u64)).to_bytes();
        let balance_proof = value::prove_balance(
            &[],
            &[output_commitment],
            balance,
            fee,
            &excess,
            &signing_hash,
            &[0x42; 32],
        )
        .expect("valid balance proof");
        let binding_signature = value::prove_binding_signature(
            &[],
            &[output_commitment],
            balance,
            fee,
            &excess,
            &signing_hash,
            &[0x43; 32],
        )
        .expect("valid binding signature");
        vector(&mut payload, &[]);
        // Published amounts carry no range proof: each is checked against its commitment.
        let range_proof = if include_range {
            value::prove_range(&[true_amount], &[output_mask], &[0x41; 32])
                .expect("valid range proof")
                .1
        } else {
            Vec::new()
        };
        vector(&mut payload, &range_proof);
        vector(&mut payload, &balance_proof);
        vector(&mut payload, &[]);
        vector(&mut payload, &[]);
        vector(&mut payload, &binding_signature);

        validation_request(&payload)
    }

    // A false published amount with proofs made over its own prefix: only the opening
    // check catches it.
    #[test]
    fn a_published_amount_must_open_the_commitment_it_names() {
        let honest = disclosed_amount_request(9, 9);
        assert_eq!(validate(&honest), Ok(()));

        assert_eq!(
            validate(&disclosed_amount_request(9, 10)),
            Err(ResultCode::ConsensusInvalid),
            "an overstated amount must not be accepted"
        );
        assert_eq!(
            validate(&disclosed_amount_request(9, 8)),
            Err(ResultCode::ConsensusInvalid),
            "an understated amount must not be accepted"
        );
        assert_eq!(
            validate(&disclosed_amount_request(9, 0)),
            Err(ResultCode::ConsensusInvalid),
            "a zeroed amount must not be accepted"
        );

        // A payload that publishes its amounts must not also carry a range proof, or the
        // value would be established two ways that could disagree.
        assert_eq!(
            validate(&disclosed_amount_request_with_range(9, 9, true)),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    // A shield disclosing the recipient address of its one output; `named` is the
    // claimed address, the output always pays the true one.
    fn disclosed_receiver_request(
        genesis: &[u8; 32],
        encrypted: &[u8],
        named: ([u8; 32], [u8; 32]),
    ) -> Vec<u8> {
        let true_spend = (ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
            .compress()
            .to_bytes();
        let true_view = (ED25519_BASEPOINT_POINT * Scalar::from(5_u64))
            .compress()
            .to_bytes();
        let tweak_ephemeral_secret = Scalar::from(14_u64).to_bytes();
        let output_y = Scalar::from(17_u64).to_bytes();
        let output_mask = Scalar::from(19_u64).to_bytes();
        let amount = 99_u64;
        let fee = 1_u64;

        let state = tree::update(&[1, 0, 1, 0, 0, 0, 0, 0]).expect("empty canonical tree state");
        let root = tree::root(&state).expect("empty canonical tree root");
        let mut payload = Vec::new();
        payload.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        // Mask 5 hides the sender and the amount and publishes the recipient.
        payload.extend_from_slice(&[NOTE_SHIELD, 0, 0, 5, FINALITY_OBJECT_NONE, 1, 0]);
        payload.extend_from_slice(genesis);
        payload.extend_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
        payload.extend_from_slice(&root[12..44]);
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&(i64::try_from(amount).expect("fits") + 1).to_le_bytes());
        payload.extend_from_slice(&fee.to_le_bytes());
        payload.extend_from_slice(&TEST_TRANSPARENT_BINDING);
        compact_size(&mut payload, 0);
        compact_size(&mut payload, 1);
        put_output(&mut payload, encrypted);

        payload.extend_from_slice(&named.0);
        payload.extend_from_slice(&named.1);
        vector(&mut payload, &[]);

        // Every proof, including the receiver disclosure, is made over the prefix that
        // carries the claim, so nothing here is stale or mismatched.
        let signing_hash = signable_hash(2008, &payload);
        let output_o: [u8; 32] = encrypted[ENCRYPTED_O].try_into().expect("O is 32 bytes");
        // The disclosure names the tweak ephemeral, never the one that keys the note.
        let tweak_ephemeral: [u8; 32] = encrypted[ENCRYPTED_TWEAK_EPHEMERAL]
            .try_into()
            .expect("R2 is 32 bytes");
        let receiver_proof = disclosure::prove_receiver(
            &true_spend,
            &true_view,
            &output_o,
            &tweak_ephemeral,
            &tweak_ephemeral_secret,
            &output_y,
            &signing_hash,
            0,
            &[0x44; 32],
        )
        .expect("the true address always has a proof");

        let (commitments, range_proof) =
            value::prove_range(&[amount], &[output_mask], &[0x41; 32]).expect("valid range proof");
        let excess = (-Scalar::from(19_u64)).to_bytes();
        let balance = i64::try_from(amount).expect("fits") + 1;
        let balance_proof = value::prove_balance(
            &[],
            &commitments,
            balance,
            fee,
            &excess,
            &signing_hash,
            &[0x42; 32],
        )
        .expect("valid balance proof");
        let binding_signature = value::prove_binding_signature(
            &[],
            &commitments,
            balance,
            fee,
            &excess,
            &signing_hash,
            &[0x43; 32],
        )
        .expect("valid binding signature");
        vector(&mut payload, &[]);
        vector(&mut payload, &range_proof);
        vector(&mut payload, &balance_proof);
        vector(&mut payload, &[]);
        vector(&mut payload, &receiver_proof);
        vector(&mut payload, &binding_signature);

        validation_request(&payload)
    }

    // A forged recipient with a real proof over its own prefix: only the address
    // check catches it.
    #[test]
    fn a_published_recipient_must_be_the_one_the_output_pays() {
        let genesis = [0x11_u8; 32];
        let (encrypted, _, _) = encrypted_output(&genesis, 0);
        let true_spend = (ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
            .compress()
            .to_bytes();
        let true_view = (ED25519_BASEPOINT_POINT * Scalar::from(5_u64))
            .compress()
            .to_bytes();

        assert_eq!(
            validate(&disclosed_receiver_request(
                &genesis,
                &encrypted,
                (true_spend, true_view)
            )),
            Ok(())
        );

        let other_spend = (ED25519_BASEPOINT_POINT * Scalar::from(23_u64))
            .compress()
            .to_bytes();
        let other_view = (ED25519_BASEPOINT_POINT * Scalar::from(29_u64))
            .compress()
            .to_bytes();
        for named in [
            (other_spend, other_view),
            (other_spend, true_view),
            (true_spend, other_view),
        ] {
            assert_eq!(
                validate(&disclosed_receiver_request(&genesis, &encrypted, named)),
                Err(ResultCode::ConsensusInvalid),
                "a payload must not name an address its output does not pay"
            );
        }
    }

    // Mask 5 publishes the recipient and hides the amount: the published receiver
    // point must be useless against the ciphertext.
    #[test]
    fn a_published_receiver_disclosure_does_not_open_the_amount() {
        let genesis = [0x11_u8; 32];
        let (encrypted, _, view_secret) = encrypted_output(&genesis, 0);
        let true_spend = (ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
            .compress()
            .to_bytes();
        let true_view = (ED25519_BASEPOINT_POINT * Scalar::from(5_u64))
            .compress()
            .to_bytes();
        let request = disclosed_receiver_request(&genesis, &encrypted, (true_spend, true_view));
        assert_eq!(validate(&request), Ok(()));
        let payload = &request[VALIDATION_PREFIX_SIZE..];

        // Everything from here on reads the serialized payload and nothing else.
        let mut prefix = parse_payload_prefix(2008, payload, TEST_NETWORK, Some(&genesis))
            .expect("the payload decodes");
        assert_eq!(prefix.disclosure_mask, 5);
        // Mask 5: the sender is hidden, one receiver record follows the outputs, and the
        // amounts are hidden.
        let named_spend = prefix.cursor.array::<32>().expect("receiver spend");
        let named_view = prefix.cursor.array::<32>().expect("receiver view");
        assert_eq!(named_spend, true_spend);
        assert_eq!(named_view, true_view);
        prefix
            .cursor
            .vector(MAX_FINALITY_BODY_BYTES)
            .expect("finality body");
        for _ in 0..4 {
            prefix
                .cursor
                .vector(MAX_PROOF_SECTION_BYTES)
                .expect("proof section before the disclosures");
        }
        let disclosure_section = prefix
            .cursor
            .vector(MAX_PROOF_SECTION_BYTES)
            .expect("disclosure section");
        assert_eq!(disclosure_section.len(), disclosure::RECEIVER_PROOF_BYTES);
        let published: [u8; 32] = disclosure_section[..32]
            .try_into()
            .expect("the disclosure leads with its shared point");

        let owner = prefix.output_owners[0];
        let commitment = prefix.output_commitments[0];
        let note_ephemeral = prefix.output_note_ephemerals[0];
        let tweak_ephemeral = prefix.output_tweak_ephemerals[0];
        let ciphertext = prefix.output_recipient_ciphertexts[0].clone();

        // The published point is exactly the shared secret behind the tweak, so the attempt
        // below is aimed at the right value and not at noise.
        let view_point = |bytes: &[u8; 32]| {
            (CompressedEdwardsY(*bytes)
                .decompress()
                .expect("a payload ephemeral is canonical")
                * view_secret)
                .compress()
                .to_bytes()
        };
        assert_eq!(published, view_point(&tweak_ephemeral));

        // The owner opens the note, so the ciphertext really does carry the amount.
        assert_eq!(
            crate::note::try_open_recipient(
                1,
                0,
                0,
                &genesis,
                &owner,
                &commitment,
                &note_ephemeral,
                &tweak_ephemeral,
                &ciphertext,
                &view_point(&note_ephemeral),
            ),
            Some(99)
        );

        // The observer holding the published point must not.
        assert_eq!(
            crate::note::try_open_recipient(
                1,
                0,
                0,
                &genesis,
                &owner,
                &commitment,
                &note_ephemeral,
                &tweak_ephemeral,
                &ciphertext,
                &published,
            ),
            None,
            "the disclosed shared point decrypted the note"
        );

        // Nor may the raw ephemerals or the disclosed address stand in for it.
        for candidate in [note_ephemeral, tweak_ephemeral, named_spend, named_view] {
            assert_eq!(
                crate::note::try_open_recipient(
                    1,
                    0,
                    0,
                    &genesis,
                    &owner,
                    &commitment,
                    &note_ephemeral,
                    &tweak_ephemeral,
                    &ciphertext,
                    &candidate,
                ),
                None,
                "a public payload field decrypted the note"
            );
        }
    }

    fn encrypted_output_to(
        genesis: &[u8; 32],
        index: u32,
        ephemeral_secret: u64,
        mask: u64,
    ) -> Vec<u8> {
        let mut request = vec![0_u8; 272];
        request[..2].copy_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request[2] = 1;
        request[4..8].copy_from_slice(&index.to_le_bytes());
        request[8..40].copy_from_slice(genesis);
        request[40..72].copy_from_slice(
            &(ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
                .compress()
                .to_bytes(),
        );
        request[72..104].copy_from_slice(
            &(ED25519_BASEPOINT_POINT * Scalar::from(5_u64))
                .compress()
                .to_bytes(),
        );
        request[104..136].copy_from_slice(&Scalar::from(7_u64).to_bytes());
        request[136..168].copy_from_slice(&Scalar::from(ephemeral_secret).to_bytes());
        request[168..200].copy_from_slice(&Scalar::from(ephemeral_secret + 1).to_bytes());
        request[200..208].copy_from_slice(&99_u64.to_le_bytes());
        request[208..240].copy_from_slice(&Scalar::from(17_u64).to_bytes());
        request[240..272].copy_from_slice(&Scalar::from(mask).to_bytes());
        crate::note::encrypt_request(&request).expect("canonical note")
    }

    fn encrypted_output(genesis: &[u8; 32], index: u32) -> (Vec<u8>, Scalar, Scalar) {
        (
            encrypted_output_to(genesis, index, 13, 19),
            Scalar::from(3_u64),
            Scalar::from(5_u64),
        )
    }

    fn payload_with_output(genesis: &[u8; 32], encrypted: &[u8]) -> Vec<u8> {
        let state = tree::update(&[1, 0, 1, 0, 0, 0, 0, 0]).expect("empty canonical tree state");
        let root = tree::root(&state).expect("empty canonical tree root");
        let mut payload = Vec::new();
        payload.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        payload.extend_from_slice(&[NOTE_SHIELD, 0, 0, 7, FINALITY_OBJECT_NONE, 1, 0]);
        payload.extend_from_slice(genesis);
        payload.extend_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
        payload.extend_from_slice(&root[12..44]);
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&100_i64.to_le_bytes());
        payload.extend_from_slice(&1_u64.to_le_bytes());
        payload.extend_from_slice(&TEST_TRANSPARENT_BINDING);
        compact_size(&mut payload, 0);
        compact_size(&mut payload, 1);
        put_output(&mut payload, encrypted);
        payload
    }

    fn scan_request_keys(scan_kind: u8, keys: &[(Scalar, Scalar)], payload: &[u8]) -> Vec<u8> {
        let mut request = vec![0_u8; SCAN_REQUEST_HEADER_BYTES];
        request[..2].copy_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request[2] = scan_kind;
        request[3] = 1;
        request[8..12].copy_from_slice(&2008_u32.to_le_bytes());
        let count = u16::try_from(keys.len()).expect("test key count is bounded");
        request[12..14].copy_from_slice(&count.to_le_bytes());
        for (scan_secret, spend) in keys {
            request.extend_from_slice(&scan_secret.to_bytes());
            request.extend_from_slice(&spend.to_bytes());
        }
        request.extend_from_slice(payload);
        request
    }

    fn scan_request(
        scan_kind: u8,
        scan_secret: &Scalar,
        spend: &Scalar,
        payload: &[u8],
    ) -> Vec<u8> {
        scan_request_keys(scan_kind, &[(*scan_secret, *spend)], payload)
    }

    // Scanning must find the wallet's own output and report the leaf it matched, so the
    // caller can hold it against the leaf consensus recorded at the same index.
    #[test]
    fn payload_scan_opens_an_owned_output_and_reports_its_leaf() {
        let genesis = [0x11_u8; 32];
        let (encrypted, spend_secret, view_secret) = encrypted_output(&genesis, 0);
        let payload = payload_with_output(&genesis, &encrypted);

        let scanned = scan_outputs(&scan_request(0, &view_secret, &spend_secret, &payload))
            .expect("an owned output must open");
        assert_eq!(
            u16::from_le_bytes([scanned[0], scanned[1]]),
            PAYLOAD_SCHEMA_U16
        );
        assert_eq!(scanned[2], 1);
        assert_eq!(scanned[3], 0, "a shield carries no key images");
        assert_eq!(
            scanned.len(),
            SCAN_RESPONSE_HEADER_BYTES + SCAN_RECORD_BYTES
        );

        assert_eq!(scanned[4], 1, "the payload declares one output");
        let record = &scanned[SCAN_RESPONSE_HEADER_BYTES..];
        assert_eq!(u16::from_le_bytes(record[..2].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(record[2..6].try_into().unwrap()), 0);
        // The leaf the scan matched must be the leaf carried in the payload.
        assert_eq!(&record[6..102], &encrypted[8..104]);
        // The opened amount and output index travel in the note-scan result.
        assert_eq!(u64::from_le_bytes(record[114..122].try_into().unwrap()), 99);
        assert_eq!(u32::from_le_bytes(record[110..114].try_into().unwrap()), 0);

        // A view-only scan opens the same note without the spend material.
        let view_only = scan_outputs(&scan_request(1, &view_secret, &Scalar::ZERO, &payload))
            .expect("view-only scan must open");
        assert_eq!(view_only[2], 1);
        assert_eq!(&view_only[6..108], &record[..102]);

        // Another wallet's material must find nothing, and that is not an error.
        let stranger = Scalar::from(23_u64);
        let missed = scan_outputs(&scan_request(0, &stranger, &stranger, &payload))
            .expect("a foreign scan is empty, not an error");
        assert_eq!(missed[2], 0);
        assert_eq!(missed.len(), SCAN_RESPONSE_HEADER_BYTES);
    }

    // The leaves a scan reports must equal the leaves validation derives from the same
    // payload (single decode path).
    #[test]
    fn scanning_and_validation_agree_on_the_same_payload() {
        let genesis = [0x11_u8; 32];
        let (encrypted, spend_secret, view_secret) = encrypted_output(&genesis, 0);
        let mut payload = payload_with_output(&genesis, &encrypted);

        let output_mask = Scalar::from(19_u64).to_bytes();
        let output_commitment = value::commitment(99, &output_mask).expect("valid commitment");
        vector(&mut payload, &[]);
        let signing_hash = signable_hash(2008, &payload);
        let (range_commitments, range_proof) =
            value::prove_range(&[99], &[output_mask], &[0x41; 32]).expect("valid range proof");
        assert_eq!(range_commitments, vec![output_commitment]);
        let excess = (-Scalar::from(19_u64)).to_bytes();
        let balance_proof = value::prove_balance(
            &[],
            &[output_commitment],
            100,
            1,
            &excess,
            &signing_hash,
            &[0x42; 32],
        )
        .expect("valid balance proof");
        let binding_signature = value::prove_binding_signature(
            &[],
            &[output_commitment],
            100,
            1,
            &excess,
            &signing_hash,
            &[0x43; 32],
        )
        .expect("valid binding signature");
        vector(&mut payload, &[]);
        vector(&mut payload, &range_proof);
        vector(&mut payload, &balance_proof);
        vector(&mut payload, &[]);
        vector(&mut payload, &[]);
        vector(&mut payload, &binding_signature);

        let request = validation_request(&payload);
        let encoded = effects(&request).expect("the payload must validate");

        let scanned = scan_outputs(&scan_request(0, &view_secret, &spend_secret, &payload))
            .expect("the same payload must scan");
        assert_eq!(scanned[2], 1);
        assert_eq!(scanned[3], 0);

        // The validated effects carry the leaf right after the header and no key
        // images, so the scan's leaf must be byte-identical to it.
        let validated_leaf = &encoded[EFFECTS_HEADER_BYTES..EFFECTS_HEADER_BYTES + 96];
        let scanned_leaf = &scanned[12..108];
        assert_eq!(validated_leaf, scanned_leaf);
    }

    // A wallet holding several derivation indices must find its note under the right
    // one and report which, so a stranger's key in the set changes nothing.
    #[test]
    fn payload_scan_reports_which_key_opened_an_output() {
        let genesis = [0x11_u8; 32];
        let (encrypted, spend_secret, view_secret) = encrypted_output(&genesis, 0);
        let payload = payload_with_output(&genesis, &encrypted);
        let stranger = Scalar::from(23_u64);

        let keys = [
            (stranger, stranger),
            (Scalar::from(29_u64), Scalar::from(31_u64)),
            (view_secret, spend_secret),
        ];
        let scanned = scan_outputs(&scan_request_keys(0, &keys, &payload))
            .expect("the owning key must open the output");
        assert_eq!(scanned[2], 1);
        assert_eq!(u16::from_le_bytes(scanned[6..8].try_into().unwrap()), 2);

        let foreign = [(stranger, stranger)];
        let missed = scan_outputs(&scan_request_keys(0, &foreign, &payload))
            .expect("a foreign key set is empty, not an error");
        assert_eq!(missed[2], 0);

        let mut none = scan_request_keys(0, &keys, &payload);
        none[12] = 0;
        none[13] = 0;
        assert_eq!(scan_outputs(&none), Err(ResultCode::BadLength));
    }

    #[test]
    fn payload_scan_rejects_malformed_requests() {
        let genesis = [0x11_u8; 32];
        let (encrypted, spend_secret, view_secret) = encrypted_output(&genesis, 0);
        let payload = payload_with_output(&genesis, &encrypted);

        assert_eq!(scan_outputs(&[]), Err(ResultCode::BadLength));
        assert_eq!(scan_outputs(&[0_u8; 16]), Err(ResultCode::BadLength));

        let mut wrong_schema = scan_request(0, &view_secret, &spend_secret, &payload);
        wrong_schema[0] = 2;
        assert_eq!(
            scan_outputs(&wrong_schema),
            Err(ResultCode::UnsupportedFormat)
        );

        let mut wrong_kind = scan_request(9, &view_secret, &spend_secret, &payload);
        wrong_kind[2] = 9;
        assert_eq!(
            scan_outputs(&wrong_kind),
            Err(ResultCode::UnsupportedFormat)
        );

        let mut reserved = scan_request(0, &view_secret, &spend_secret, &payload);
        reserved[5] = 1;
        assert_eq!(scan_outputs(&reserved), Err(ResultCode::ConsensusInvalid));

        // The declared network must be the payload's, or the scan context is not ours.
        let mut wrong_network = scan_request(0, &view_secret, &spend_secret, &payload);
        wrong_network[3] = 0;
        assert_eq!(
            scan_outputs(&wrong_network),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    // The leaves consensus records are the whole on-chain footprint of an output. Paying
    // one address repeatedly must leave no constant in them, or holding that address is
    // enough to enumerate every note ever sent to it.
    #[test]
    fn repeated_payments_to_one_address_share_no_leaf_field() {
        let genesis = [0x11_u8; 32];
        let masks = [19_u64, 23, 29];
        let ephemerals = [13_u64, 31, 37];
        let outputs: Vec<Vec<u8>> = (0..3)
            .map(|index| {
                encrypted_output_to(
                    &genesis,
                    u32::try_from(index).expect("index is bounded"),
                    ephemerals[index],
                    masks[index],
                )
            })
            .collect();

        let state = tree::update(&[1, 0, 1, 0, 0, 0, 0, 0]).expect("empty canonical tree state");
        let root = tree::root(&state).expect("empty canonical tree root");
        let mut payload = Vec::new();
        payload.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        payload.extend_from_slice(&[NOTE_SHIELD, 0, 0, 7, FINALITY_OBJECT_NONE, 1, 0]);
        payload.extend_from_slice(&genesis);
        payload.extend_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
        payload.extend_from_slice(&root[12..44]);
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&((99 * 3) + 1_i64).to_le_bytes());
        payload.extend_from_slice(&1_u64.to_le_bytes());
        payload.extend_from_slice(&TEST_TRANSPARENT_BINDING);
        compact_size(&mut payload, 0);
        compact_size(&mut payload, outputs.len());
        for encrypted in &outputs {
            put_output(&mut payload, encrypted);
        }
        vector(&mut payload, &[]);

        let signing_hash = signable_hash(2008, &payload);
        let mask_bytes: Vec<[u8; 32]> = masks.iter().map(|m| Scalar::from(*m).to_bytes()).collect();
        let commitments: Vec<[u8; 32]> = mask_bytes
            .iter()
            .map(|mask| value::commitment(99, mask).expect("valid commitment"))
            .collect();
        let (range_commitments, range_proof) =
            value::prove_range(&[99, 99, 99], &mask_bytes, &[0x41; 32]).expect("valid range proof");
        assert_eq!(range_commitments, commitments);
        let excess =
            (-(Scalar::from(19_u64) + Scalar::from(23_u64) + Scalar::from(29_u64))).to_bytes();
        let balance_proof = value::prove_balance(
            &[],
            &commitments,
            298,
            1,
            &excess,
            &signing_hash,
            &[0x42; 32],
        )
        .expect("valid balance proof");
        let binding_signature = value::prove_binding_signature(
            &[],
            &commitments,
            298,
            1,
            &excess,
            &signing_hash,
            &[0x43; 32],
        )
        .expect("valid binding signature");
        vector(&mut payload, &[]);
        vector(&mut payload, &range_proof);
        vector(&mut payload, &balance_proof);
        vector(&mut payload, &[]);
        vector(&mut payload, &[]);
        vector(&mut payload, &binding_signature);

        let request = validation_request(&payload);
        let encoded = effects(&request).expect("three same-address outputs must validate");
        assert_eq!(encoded.len(), EFFECTS_HEADER_BYTES + (3 * 96));

        let spend_public = (ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
            .compress()
            .to_bytes();
        let view_public = (ED25519_BASEPOINT_POINT * Scalar::from(5_u64))
            .compress()
            .to_bytes();
        let mut bases = std::collections::BTreeSet::new();
        let mut owners = std::collections::BTreeSet::new();
        for index in 0..3 {
            let leaf = &encoded[EFFECTS_HEADER_BYTES + (index * 96)..][..96];
            let owner: [u8; 32] = leaf[..32].try_into().expect("O is 32 bytes");
            let base: [u8; 32] = leaf[32..64].try_into().expect("I is 32 bytes");
            assert_ne!(base, spend_public, "I must not carry the address spend key");
            assert_ne!(base, view_public, "I must not carry the address view key");
            assert_eq!(
                base,
                crate::note::key_image_base_checked(&owner).expect("I is derived from O"),
                "consensus must derive I from this leaf's own O"
            );
            assert!(bases.insert(base), "two same-address outputs share an I");
            assert!(owners.insert(owner), "two same-address outputs share an O");
        }
        assert_eq!(bases.len(), 3);

        // Nothing in the serialized payload equals any leaf I: it is not on the wire at all.
        for base in &bases {
            assert!(
                !payload.windows(32).any(|window| window == base),
                "a derived I must never be serialized"
            );
        }
    }

    #[test]
    fn canonical_payload_is_accepted_without_trailing_bytes() {
        let request = valid_request();
        assert_eq!(validate(&request), Ok(()));

        let state_effects = effects(&request).expect("valid payload has canonical state effects");
        assert_eq!(state_effects.len(), EFFECTS_HEADER_BYTES + 96);
        assert_eq!(&state_effects[..2], &PAYLOAD_SCHEMA_U16.to_le_bytes());
        assert_eq!(state_effects[2], 0);
        assert_eq!(state_effects[3], 1);
        assert_eq!(
            &state_effects[44..76],
            &Sha256::digest(PRODUCT_CONTRACT)[..]
        );
        assert_eq!(&state_effects[76..84], &10_i64.to_le_bytes());
        assert_eq!(&state_effects[84..92], &1_u64.to_le_bytes());
        // The caller cannot check the transparent side against anything unless the
        // payload's own bytes reach it unchanged.
        assert_eq!(&state_effects[92..124], &TEST_TRANSPARENT_BINDING);
        // O and C come off the wire; I is derived from O and never travels. Assert
        // the relation against the leaf itself rather than wire offsets, which move
        // whenever the prefix or the output record changes.
        let leaf = &state_effects[EFFECTS_HEADER_BYTES..];
        let owner: [u8; 32] = leaf[..32].try_into().expect("owner is 32 bytes");
        assert_eq!(
            &leaf[32..64],
            &crate::note::key_image_base_checked(&owner).expect("owner hashes to a point")
        );

        let mut trailing = request;
        trailing.push(0);
        assert_eq!(validate(&trailing), Err(ResultCode::ConsensusInvalid));
    }

    // The binding must stay inside the signing hash so the proofs cover it.
    #[test]
    fn transparent_binding_is_covered_by_the_signing_hash() {
        const BINDING_OFFSET: usize = VALIDATION_PREFIX_SIZE + 129;
        let request = valid_request();
        assert_eq!(
            &request[BINDING_OFFSET..BINDING_OFFSET + 32],
            &TEST_TRANSPARENT_BINDING
        );

        let mut restated = request;
        restated[BINDING_OFFSET] ^= 1;
        assert_eq!(validate(&restated), Err(ResultCode::ConsensusInvalid));
    }

    #[test]
    fn extended_operations_are_fail_closed_until_typed_proofs_exist() {
        let mut request = valid_request();
        request[VALIDATION_PREFIX_SIZE + 2] = crate::NOTE_NULLSEND;
        assert_eq!(validate(&request), Err(ResultCode::UnsupportedFormat));
    }

    #[test]
    fn payload_rejects_noncanonical_lengths_context_and_points() {
        const INPUT_COUNT_OFFSET: usize = VALIDATION_PREFIX_SIZE + 161;
        const PARAMETER_DIGEST_OFFSET: usize = VALIDATION_PREFIX_SIZE + 41;
        let request = valid_request();

        let mut noncanonical_count = request.clone();
        noncanonical_count.splice(INPUT_COUNT_OFFSET..=INPUT_COUNT_OFFSET, [253, 1, 0]);
        assert_eq!(
            validate(&noncanonical_count),
            Err(ResultCode::ConsensusInvalid)
        );

        let mut over_cap = request.clone();
        over_cap[INPUT_COUNT_OFFSET] = 17;
        assert_eq!(validate(&over_cap), Err(ResultCode::ResourceLimit));

        let mut wrong_parameter = request.clone();
        wrong_parameter[PARAMETER_DIGEST_OFFSET] ^= 1;
        assert_eq!(
            validate(&wrong_parameter),
            Err(ResultCode::ConsensusInvalid)
        );

        let mut identity_output = request.clone();
        identity_output[INPUT_COUNT_OFFSET + 2..INPUT_COUNT_OFFSET + 34].fill(0);
        assert_eq!(
            validate(&identity_output),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    #[test]
    fn payload_rejects_unknown_schema_envelope_and_missing_disclosures() {
        let request = valid_request();

        let mut unknown_schema = request.clone();
        unknown_schema[VALIDATION_PREFIX_SIZE] = 2;
        assert_eq!(
            validate(&unknown_schema),
            Err(ResultCode::UnsupportedFormat)
        );

        let mut wrong_envelope = request.clone();
        wrong_envelope[..4].copy_from_slice(&2003_u32.to_le_bytes());
        assert_eq!(validate(&wrong_envelope), Err(ResultCode::ConsensusInvalid));

        let mut missing_disclosures = request;
        missing_disclosures[VALIDATION_PREFIX_SIZE + 5] = 0;
        assert_eq!(
            validate(&missing_disclosures),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    // Two leaves sharing an owner key share I = Hp(O); the prefix parser (the single
    // decode path) must refuse it.
    #[test]
    fn payload_rejects_a_repeated_output_owner() {
        let genesis = [0x11_u8; 32];
        let (encrypted, _, _) = encrypted_output(&genesis, 0);
        let two_outputs = |second_owner: &[u8; 32]| -> Vec<u8> {
            let state =
                tree::update(&[1, 0, 1, 0, 0, 0, 0, 0]).expect("empty canonical tree state");
            let root = tree::root(&state).expect("empty canonical tree root");
            let mut payload = Vec::new();
            payload.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
            payload.extend_from_slice(&[NOTE_SHIELD, 0, 0, 7, FINALITY_OBJECT_NONE, 1, 0]);
            payload.extend_from_slice(&genesis);
            payload.extend_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
            payload.extend_from_slice(&root[12..44]);
            payload.extend_from_slice(&0_u64.to_le_bytes());
            payload.extend_from_slice(&100_i64.to_le_bytes());
            payload.extend_from_slice(&1_u64.to_le_bytes());
            payload.extend_from_slice(&TEST_TRANSPARENT_BINDING);
            compact_size(&mut payload, 0);
            compact_size(&mut payload, 2);
            for owner in [&encrypted[ENCRYPTED_O], &second_owner[..]] {
                payload.extend_from_slice(owner);
                payload.extend_from_slice(&encrypted[ENCRYPTED_C]);
                payload.extend_from_slice(&encrypted[ENCRYPTED_EPHEMERALS]);
                vector(&mut payload, &encrypted[ENCRYPTED_RECIPIENT]);
                vector(&mut payload, &encrypted[ENCRYPTED_OUTGOING]);
            }
            payload
        };

        let mut repeated = [0_u8; 32];
        repeated.copy_from_slice(&encrypted[ENCRYPTED_O]);
        assert_eq!(
            parse_payload_prefix(2008, &two_outputs(&repeated), TEST_NETWORK, Some(&genesis)).err(),
            Some(ResultCode::ConsensusInvalid)
        );

        let distinct = (ED25519_BASEPOINT_POINT * Scalar::from(29_u64))
            .compress()
            .to_bytes();
        assert!(
            parse_payload_prefix(2008, &two_outputs(&distinct), TEST_NETWORK, Some(&genesis))
                .is_ok(),
            "distinct owners must still parse"
        );
    }

    // The declared network and genesis must be compared against the local chain.
    #[test]
    fn payload_pins_the_declared_chain_to_the_local_one() {
        let request = valid_request();
        assert_eq!(validate(&request), Ok(()));

        let payload = &request[VALIDATION_PREFIX_SIZE..];
        for network in 0..=NETWORK_ID_MAX {
            if network == TEST_NETWORK {
                continue;
            }
            assert_eq!(
                validate(&validation_request_for(network, &TEST_GENESIS, payload)),
                Err(ResultCode::ConsensusInvalid),
                "a payload declaring another network must not validate here"
            );
        }

        assert_eq!(
            validate(&validation_request_for(TEST_NETWORK, &[0x22; 32], payload)),
            Err(ResultCode::ConsensusInvalid),
            "a payload declaring another genesis must not validate here"
        );
    }

    // An output whose ciphertext no wallet can decode must never reach the tree.
    #[test]
    fn payload_pins_the_note_ciphertext_encoding() {
        let genesis = TEST_GENESIS;
        let (encrypted, _, _) = encrypted_output(&genesis, 0);
        let recipient = &encrypted[ENCRYPTED_RECIPIENT];
        let outgoing = &encrypted[ENCRYPTED_OUTGOING];

        let build = |recipient: &[u8], outgoing: &[u8]| -> Vec<u8> {
            let state =
                tree::update(&[1, 0, 1, 0, 0, 0, 0, 0]).expect("empty canonical tree state");
            let root = tree::root(&state).expect("empty canonical tree root");
            let mut payload = Vec::new();
            payload.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
            payload.extend_from_slice(&[NOTE_SHIELD, 0, 0, 7, FINALITY_OBJECT_NONE, 1, 0]);
            payload.extend_from_slice(&genesis);
            payload.extend_from_slice(&Sha256::digest(PRODUCT_CONTRACT));
            payload.extend_from_slice(&root[12..44]);
            payload.extend_from_slice(&0_u64.to_le_bytes());
            payload.extend_from_slice(&100_i64.to_le_bytes());
            payload.extend_from_slice(&1_u64.to_le_bytes());
            payload.extend_from_slice(&TEST_TRANSPARENT_BINDING);
            compact_size(&mut payload, 0);
            compact_size(&mut payload, 1);
            payload.extend_from_slice(&encrypted[ENCRYPTED_O]);
            payload.extend_from_slice(&encrypted[ENCRYPTED_C]);
            payload.extend_from_slice(&encrypted[ENCRYPTED_EPHEMERALS]);
            vector(&mut payload, recipient);
            vector(&mut payload, outgoing);
            payload
        };

        assert!(
            parse_payload_prefix(
                2008,
                &build(recipient, outgoing),
                TEST_NETWORK,
                Some(&genesis)
            )
            .is_ok(),
            "the canonical encoding must still parse"
        );

        let mut short = recipient.to_vec();
        short.truncate(recipient.len() - 1);
        let mut long = recipient.to_vec();
        long.push(0);
        let mut wrong_version = recipient.to_vec();
        wrong_version[0] = crate::note::CIPHERTEXT_VERSION.wrapping_add(1);
        for broken in [vec![1_u8], short, long, wrong_version] {
            assert_eq!(
                parse_payload_prefix(
                    2008,
                    &build(&broken, outgoing),
                    TEST_NETWORK,
                    Some(&genesis)
                )
                .err(),
                Some(ResultCode::ConsensusInvalid),
                "a non-canonical recipient ciphertext must not parse"
            );
        }
        assert_eq!(
            parse_payload_prefix(
                2008,
                &build(recipient, &outgoing[..outgoing.len() - 1]),
                TEST_NETWORK,
                Some(&genesis)
            )
            .err(),
            Some(ResultCode::ConsensusInvalid),
            "a non-canonical outgoing ciphertext must not parse"
        );
    }

    // A scan over published bytes may only yield "not mine" or a reproducible
    // rejection, never a node-local failure class.
    #[test]
    fn a_scan_reports_no_class_a_published_byte_can_choose() {
        let genesis = TEST_GENESIS;
        let (encrypted, spend_secret, view_secret) = encrypted_output(&genesis, 0);
        let payload = payload_with_output(&genesis, &encrypted);
        assert_eq!(
            scan_outputs(&scan_request(0, &view_secret, &spend_secret, &payload))
                .expect("the owner's own note must scan")[2],
            1
        );

        // Layout of the payload tail: the recipient ciphertext, then the outgoing one,
        // each behind its own one-byte length.
        let outgoing_at = payload.len() - crate::note::OUTGOING_CIPHERTEXT_BYTES;
        let recipient_at = outgoing_at - 1 - crate::note::RECIPIENT_CIPHERTEXT_BYTES;
        assert_eq!(
            payload[recipient_at],
            crate::note::CIPHERTEXT_VERSION,
            "the recipient ciphertext must start where this test expects"
        );

        for at in [
            recipient_at,     // version byte: read as a length error, not a tag mismatch
            recipient_at + 1, // encrypted body
            recipient_at + crate::note::RECIPIENT_CIPHERTEXT_BYTES - 1, // tag
            outgoing_at,
            outgoing_at + 1,
            payload.len() - 1,
        ] {
            let mut broken = payload.clone();
            broken[at] ^= 0xff;
            for kind in [0_u8, 1, 2] {
                match scan_outputs(&scan_request(kind, &view_secret, &spend_secret, &broken)) {
                    // Opening or not opening are both answers; only the class matters.
                    Ok(_) | Err(ResultCode::ConsensusInvalid) => {}
                    Err(code) => panic!(
                        "byte {at} let a published payload choose the failure class {code:?}"
                    ),
                }
            }
        }
    }
}
