use blake2::{
    digest::{consts::U32, KeyInit, Mac},
    Blake2b512, Blake2bMac, Digest,
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use monero_ed25519::{CompressedPoint, Point as MoneroPoint};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroize;

use crate::{disclosure, value, ResultCode, ADDRESS_TYPE_MAX, NETWORK_ID_MAX, PAYLOAD_SCHEMA_U16};

pub(crate) const CIPHERTEXT_VERSION: u8 = 1;
const SCAN_FULL: u8 = 0;
const SCAN_VIEW_ONLY: u8 = 1;
const SCAN_OUTGOING: u8 = 2;
const SCAN_PREFIX_BYTES: usize = 236;
const KEY_IMAGE_BASE_DOMAIN: &[u8] = b"Innova/IV5/NoteKeyImageBase/v1";
const RECIPIENT_PLAINTEXT_BYTES: usize = 144;
const OUTGOING_PLAINTEXT_BYTES: usize = 208;
const TAG_BYTES: usize = 32;
pub(crate) const RECIPIENT_CIPHERTEXT_BYTES: usize = 1 + RECIPIENT_PLAINTEXT_BYTES + TAG_BYTES;
pub(crate) const OUTGOING_CIPHERTEXT_BYTES: usize = 1 + OUTGOING_PLAINTEXT_BYTES + TAG_BYTES;
const SCAN_RESULT_BYTES: usize = 212;
pub(crate) const ENCRYPT_REQUEST_BYTES: usize = 272;
const ENCRYPT_RESULT_BYTES: usize = 586;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoteError {
    BadLength,
    InvalidEncoding,
    InvalidProof,
    Unsupported,
}

impl From<NoteError> for ResultCode {
    fn from(error: NoteError) -> Self {
        match error {
            NoteError::BadLength => ResultCode::BadLength,
            NoteError::Unsupported => ResultCode::UnsupportedFormat,
            NoteError::InvalidEncoding | NoteError::InvalidProof => ResultCode::ConsensusInvalid,
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], NoteError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(NoteError::BadLength)?;
        if end > self.bytes.len() {
            return Err(NoteError::BadLength);
        }
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NoteError> {
        self.take(N)?.try_into().map_err(|_| NoteError::BadLength)
    }

    fn u8(&mut self) -> Result<u8, NoteError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, NoteError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, NoteError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, NoteError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), NoteError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(NoteError::BadLength)
        }
    }
}

fn canonical_scalar(bytes: &[u8; 32], nonzero: bool) -> Result<Scalar, NoteError> {
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or(NoteError::InvalidEncoding)?;
    if nonzero && scalar == Scalar::ZERO {
        return Err(NoteError::InvalidEncoding);
    }
    Ok(scalar)
}

fn canonical_point(bytes: &[u8; 32]) -> Result<EdwardsPoint, NoteError> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .filter(|point| point.compress().to_bytes() == *bytes)
        .filter(EdwardsPoint::is_torsion_free)
        .ok_or(NoteError::InvalidEncoding)?;
    if point.is_identity() {
        return Err(NoteError::InvalidEncoding);
    }
    Ok(point)
}

fn monero_t() -> EdwardsPoint {
    CompressedEdwardsY(CompressedPoint::T.to_bytes())
        .decompress()
        .expect("the pinned Monero T encoding must decompress")
}

/// Derive a note's key-image base I by hashing its one-time output key O.
/// I is cleartext in every leaf, so it must not be owner-derived; Elligator 2 clears
/// the cofactor, so the result is in the prime-order subgroup.
fn key_image_base(output_o: &[u8; 32]) -> Result<[u8; 32], NoteError> {
    canonical_point(output_o)?;
    let mut hash = Blake2b512::new();
    Digest::update(&mut hash, KEY_IMAGE_BASE_DOMAIN);
    Digest::update(&mut hash, output_o);
    let digest = hash.finalize();
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&digest[..32]);
    let derived = MoneroPoint::hash(seed).compress().to_bytes();
    // Only the negligible identity case can fail here, and it must fail closed.
    canonical_point(&derived)?;
    Ok(derived)
}

/// Derive I for a caller outside this module, mapping the error to the shared ABI code.
pub(crate) fn key_image_base_checked(output_o: &[u8; 32]) -> Result<[u8; 32], ResultCode> {
    key_image_base(output_o).map_err(ResultCode::from)
}

#[allow(clippy::too_many_arguments)]
fn associated_data(
    network: u8,
    address_type: u8,
    output_index: u32,
    genesis: &[u8; 32],
    output_o: &[u8; 32],
    output_i: &[u8; 32],
    output_c: &[u8; 32],
    note_ephemeral: &[u8; 32],
    tweak_ephemeral: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(204);
    data.extend_from_slice(b"Innova/IV5/NoteAssociatedData/v1");
    data.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    data.push(network);
    data.push(address_type);
    data.extend_from_slice(&output_index.to_le_bytes());
    data.extend_from_slice(genesis);
    data.extend_from_slice(output_o);
    data.extend_from_slice(output_i);
    data.extend_from_slice(output_c);
    // Both ephemerals: swapping either one must break the tag rather than silently
    // leaving the note undecryptable or the owner key underivable.
    data.extend_from_slice(note_ephemeral);
    data.extend_from_slice(tweak_ephemeral);
    data
}

fn derive_keys(domain: &[u8], secret: &[u8; 32], associated_data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hash = Blake2b512::new();
    Digest::update(&mut hash, domain);
    Digest::update(&mut hash, (secret.len() as u64).to_le_bytes());
    Digest::update(&mut hash, secret);
    Digest::update(&mut hash, (associated_data.len() as u64).to_le_bytes());
    Digest::update(&mut hash, associated_data);
    let digest = hash.finalize();
    let mut encryption_key = [0_u8; 32];
    let mut authentication_key = [0_u8; 32];
    encryption_key.copy_from_slice(&digest[..32]);
    authentication_key.copy_from_slice(&digest[32..]);
    (encryption_key, authentication_key)
}

fn authentication_tag(
    domain: &[u8],
    key: &[u8; 32],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> [u8; TAG_BYTES] {
    let mut mac =
        <Blake2bMac<U32> as KeyInit>::new_from_slice(key).expect("BLAKE2b accepts a 32-byte key");
    Mac::update(&mut mac, domain);
    Mac::update(&mut mac, &(associated_data.len() as u64).to_le_bytes());
    Mac::update(&mut mac, associated_data);
    Mac::update(&mut mac, &(ciphertext.len() as u64).to_le_bytes());
    Mac::update(&mut mac, ciphertext);
    Mac::finalize(mac).into_bytes().into()
}

fn tags_equal(left: &[u8; TAG_BYTES], right: &[u8; TAG_BYTES]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn encrypt(domain: &[u8], secret: &[u8; 32], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (mut encryption_key, mut authentication_key) = derive_keys(domain, secret, associated_data);
    let mut stream = vec![0_u8; plaintext.len()];
    ChaCha20Rng::from_seed(encryption_key).fill_bytes(&mut stream);
    let mut ciphertext = Vec::with_capacity(1 + plaintext.len() + TAG_BYTES);
    ciphertext.push(CIPHERTEXT_VERSION);
    ciphertext.extend(
        plaintext
            .iter()
            .zip(&stream)
            .map(|(plain, key)| plain ^ key),
    );
    let tag = authentication_tag(domain, &authentication_key, associated_data, &ciphertext);
    ciphertext.extend_from_slice(&tag);
    encryption_key.zeroize();
    authentication_key.zeroize();
    stream.zeroize();
    ciphertext
}

fn decrypt(
    domain: &[u8],
    secret: &[u8; 32],
    associated_data: &[u8],
    ciphertext: &[u8],
    expected_plaintext_bytes: usize,
) -> Result<Vec<u8>, NoteError> {
    if ciphertext.len() != 1 + expected_plaintext_bytes + TAG_BYTES
        || ciphertext.first() != Some(&CIPHERTEXT_VERSION)
    {
        return Err(NoteError::BadLength);
    }
    let (mut encryption_key, mut authentication_key) = derive_keys(domain, secret, associated_data);
    let authenticated_len = ciphertext.len() - TAG_BYTES;
    let mut encoded_tag = [0_u8; TAG_BYTES];
    encoded_tag.copy_from_slice(&ciphertext[authenticated_len..]);
    let expected_tag = authentication_tag(
        domain,
        &authentication_key,
        associated_data,
        &ciphertext[..authenticated_len],
    );
    if !tags_equal(&encoded_tag, &expected_tag) {
        encryption_key.zeroize();
        authentication_key.zeroize();
        return Err(NoteError::InvalidProof);
    }
    let encrypted = &ciphertext[1..authenticated_len];
    let mut stream = vec![0_u8; encrypted.len()];
    ChaCha20Rng::from_seed(encryption_key).fill_bytes(&mut stream);
    let plaintext = encrypted
        .iter()
        .zip(&stream)
        .map(|(byte, key)| byte ^ key)
        .collect();
    encryption_key.zeroize();
    authentication_key.zeroize();
    stream.zeroize();
    Ok(plaintext)
}

struct EncryptedNote {
    output_o: [u8; 32],
    output_i: [u8; 32],
    output_c: [u8; 32],
    note_ephemeral: [u8; 32],
    tweak_ephemeral: [u8; 32],
    recipient_ciphertext: Vec<u8>,
    outgoing_ciphertext: Vec<u8>,
}

/// Encrypt one note under two independent ephemeral keys: one for the note, one for
/// the address tweak. The receiver disclosure publishes the tweak's shared point, so
/// that point must never key the ciphertext.
#[allow(clippy::too_many_arguments)]
fn encrypt_note(
    network: u8,
    address_type: u8,
    output_index: u32,
    genesis: &[u8; 32],
    recipient_spend: &[u8; 32],
    recipient_view: &[u8; 32],
    outgoing_secret_bytes: &[u8; 32],
    note_ephemeral_secret_bytes: &[u8; 32],
    tweak_ephemeral_secret_bytes: &[u8; 32],
    amount: u64,
    y_bytes: &[u8; 32],
    mask_bytes: &[u8; 32],
) -> Result<EncryptedNote, NoteError> {
    if network > NETWORK_ID_MAX
        || address_type > ADDRESS_TYPE_MAX
        || genesis.iter().all(|byte| *byte == 0)
    {
        return Err(NoteError::InvalidEncoding);
    }
    let spend = canonical_point(recipient_spend)?;
    let view = canonical_point(recipient_view)?;
    canonical_scalar(outgoing_secret_bytes, true)?;
    let note_ephemeral_secret = canonical_scalar(note_ephemeral_secret_bytes, true)?;
    let tweak_ephemeral_secret = canonical_scalar(tweak_ephemeral_secret_bytes, true)?;
    // Independence is the whole property: one is published by a disclosure, the other
    // stays secret for the life of the note.
    if note_ephemeral_secret == tweak_ephemeral_secret {
        return Err(NoteError::InvalidEncoding);
    }
    let y = canonical_scalar(y_bytes, true)?;
    canonical_scalar(mask_bytes, false)?;

    let note_ephemeral = (ED25519_BASEPOINT_POINT * note_ephemeral_secret)
        .compress()
        .to_bytes();
    let mut note_shared = (view * note_ephemeral_secret).compress().to_bytes();
    let tweak_ephemeral = (ED25519_BASEPOINT_POINT * tweak_ephemeral_secret)
        .compress()
        .to_bytes();
    let tweak_shared = (view * tweak_ephemeral_secret).compress().to_bytes();
    let tweak = disclosure::receiver_tweak(
        &tweak_shared,
        &tweak_ephemeral,
        recipient_spend,
        recipient_view,
        output_index,
    );
    let output_o = (spend + (ED25519_BASEPOINT_POINT * tweak) + (monero_t() * y))
        .compress()
        .to_bytes();
    let output_i = key_image_base(&output_o)?;
    let output_c = value::commitment(amount, mask_bytes).map_err(|_| NoteError::InvalidEncoding)?;
    canonical_point(&output_c)?;
    let associated_data = associated_data(
        network,
        address_type,
        output_index,
        genesis,
        &output_o,
        &output_i,
        &output_c,
        &note_ephemeral,
        &tweak_ephemeral,
    );

    let mut recipient_plaintext = Vec::with_capacity(RECIPIENT_PLAINTEXT_BYTES);
    recipient_plaintext.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    recipient_plaintext.push(network);
    recipient_plaintext.push(address_type);
    recipient_plaintext.extend_from_slice(&output_index.to_le_bytes());
    recipient_plaintext.extend_from_slice(recipient_spend);
    recipient_plaintext.extend_from_slice(recipient_view);
    recipient_plaintext.extend_from_slice(&amount.to_le_bytes());
    recipient_plaintext.extend_from_slice(y_bytes);
    recipient_plaintext.extend_from_slice(mask_bytes);
    let recipient_ciphertext = encrypt(
        b"Innova/IV5/NoteEncryption/Recipient/v1",
        &note_shared,
        &associated_data,
        &recipient_plaintext,
    );

    let mut outgoing_plaintext = recipient_plaintext.clone();
    outgoing_plaintext.extend_from_slice(note_ephemeral_secret_bytes);
    outgoing_plaintext.extend_from_slice(tweak_ephemeral_secret_bytes);
    let outgoing_ciphertext = encrypt(
        b"Innova/IV5/NoteEncryption/Outgoing/v1",
        outgoing_secret_bytes,
        &associated_data,
        &outgoing_plaintext,
    );
    recipient_plaintext.zeroize();
    outgoing_plaintext.zeroize();
    note_shared.zeroize();

    Ok(EncryptedNote {
        output_o,
        output_i,
        output_c,
        note_ephemeral,
        tweak_ephemeral,
        recipient_ciphertext,
        outgoing_ciphertext,
    })
}

pub(crate) fn encrypt_request(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    if request.len() != ENCRYPT_REQUEST_BYTES {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    if reader.u16().map_err(ResultCode::from)? != PAYLOAD_SCHEMA_U16 {
        return Err(ResultCode::UnsupportedFormat);
    }
    let network = reader.u8().map_err(ResultCode::from)?;
    let address_type = reader.u8().map_err(ResultCode::from)?;
    let output_index = reader.u32().map_err(ResultCode::from)?;
    let genesis = reader.array().map_err(ResultCode::from)?;
    let recipient_spend = reader.array().map_err(ResultCode::from)?;
    let recipient_view = reader.array().map_err(ResultCode::from)?;
    let outgoing_secret = reader.array().map_err(ResultCode::from)?;
    let note_ephemeral_secret = reader.array().map_err(ResultCode::from)?;
    let tweak_ephemeral_secret = reader.array().map_err(ResultCode::from)?;
    let amount = reader.u64().map_err(ResultCode::from)?;
    let y = reader.array().map_err(ResultCode::from)?;
    let mask = reader.array().map_err(ResultCode::from)?;
    reader.finish().map_err(ResultCode::from)?;
    let encrypted = encrypt_note(
        network,
        address_type,
        output_index,
        &genesis,
        &recipient_spend,
        &recipient_view,
        &outgoing_secret,
        &note_ephemeral_secret,
        &tweak_ephemeral_secret,
        amount,
        &y,
        &mask,
    )
    .map_err(ResultCode::from)?;

    // Construction is returned only after the outgoing path independently
    // authenticates and reopens every public note component.
    let reopened = scan_outgoing(
        network,
        address_type,
        output_index,
        &genesis,
        &outgoing_secret,
        &[0_u8; 32],
        &encrypted.output_o,
        &encrypted.output_c,
        &encrypted.note_ephemeral,
        &encrypted.tweak_ephemeral,
        &encrypted.outgoing_ciphertext,
    )
    .map_err(ResultCode::from)?;
    if reopened.amount != amount
        || reopened.recipient_spend != recipient_spend
        || reopened.recipient_view != recipient_view
        || reopened.y != y
        || reopened.mask != mask
    {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let mut result = Vec::with_capacity(ENCRYPT_RESULT_BYTES);
    result.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    result.push(network);
    result.push(address_type);
    result.extend_from_slice(&output_index.to_le_bytes());
    result.extend_from_slice(&encrypted.output_o);
    result.extend_from_slice(&encrypted.output_i);
    result.extend_from_slice(&encrypted.output_c);
    result.extend_from_slice(&encrypted.note_ephemeral);
    result.extend_from_slice(&encrypted.tweak_ephemeral);
    result.extend_from_slice(&encrypted.recipient_ciphertext);
    result.extend_from_slice(&encrypted.outgoing_ciphertext);
    if result.len() != ENCRYPT_RESULT_BYTES {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    Ok(result)
}

struct OpenedNote {
    amount: u64,
    recipient_spend: [u8; 32],
    recipient_view: [u8; 32],
    spend_secret: [u8; 32],
    y: [u8; 32],
    mask: [u8; 32],
    key_image: [u8; 32],
}

#[allow(clippy::type_complexity)]
fn parse_plaintext(
    plaintext: &[u8],
    network: u8,
    address_type: u8,
    output_index: u32,
) -> Result<([u8; 32], [u8; 32], u64, [u8; 32], [u8; 32]), NoteError> {
    let mut reader = Reader::new(plaintext);
    if reader.u16()? != PAYLOAD_SCHEMA_U16
        || reader.u8()? != network
        || reader.u8()? != address_type
        || reader.u32()? != output_index
    {
        return Err(NoteError::InvalidProof);
    }
    let spend = reader.array()?;
    let view = reader.array()?;
    let amount = reader.u64()?;
    let y = reader.array()?;
    let mask = reader.array()?;
    if plaintext.len() == RECIPIENT_PLAINTEXT_BYTES {
        reader.finish()?;
    }
    Ok((spend, view, amount, y, mask))
}

#[allow(clippy::similar_names, clippy::too_many_arguments)]
fn scan_receiver(
    full: bool,
    network: u8,
    address_type: u8,
    output_index: u32,
    genesis: &[u8; 32],
    view_secret_bytes: &[u8; 32],
    spend_material: &[u8; 32],
    output_o_bytes: &[u8; 32],
    output_c_bytes: &[u8; 32],
    note_ephemeral_bytes: &[u8; 32],
    tweak_ephemeral_bytes: &[u8; 32],
    ciphertext: &[u8],
) -> Result<OpenedNote, NoteError> {
    let view_secret = canonical_scalar(view_secret_bytes, true)?;
    canonical_point(output_c_bytes)?;
    let note_ephemeral = canonical_point(note_ephemeral_bytes)?;
    let tweak_ephemeral = canonical_point(tweak_ephemeral_bytes)?;
    // Only the note key is needed to decide whether this output is ours, so the second
    // multiplication is paid on a match rather than on every candidate.
    let mut note_shared = (note_ephemeral * view_secret).compress().to_bytes();
    let output_i_bytes = key_image_base(output_o_bytes)?;
    let associated_data = associated_data(
        network,
        address_type,
        output_index,
        genesis,
        output_o_bytes,
        &output_i_bytes,
        output_c_bytes,
        note_ephemeral_bytes,
        tweak_ephemeral_bytes,
    );
    let plaintext = decrypt(
        b"Innova/IV5/NoteEncryption/Recipient/v1",
        &note_shared,
        &associated_data,
        ciphertext,
        RECIPIENT_PLAINTEXT_BYTES,
    );
    note_shared.zeroize();
    let mut plaintext = plaintext?;
    let (recipient_spend, recipient_view, amount, y_bytes, mask) =
        parse_plaintext(&plaintext, network, address_type, output_index)?;
    plaintext.zeroize();
    let view_public = (ED25519_BASEPOINT_POINT * view_secret)
        .compress()
        .to_bytes();
    if view_public != recipient_view {
        return Err(NoteError::InvalidProof);
    }
    let spend = canonical_point(&recipient_spend)?;
    let y = canonical_scalar(&y_bytes, true)?;
    let tweak_shared = (tweak_ephemeral * view_secret).compress().to_bytes();
    let tweak = disclosure::receiver_tweak(
        &tweak_shared,
        tweak_ephemeral_bytes,
        &recipient_spend,
        &recipient_view,
        output_index,
    );
    let expected_o = spend + (ED25519_BASEPOINT_POINT * tweak) + (monero_t() * y);
    if expected_o.compress().to_bytes() != *output_o_bytes
        || value::commitment(amount, &mask).map_err(|_| NoteError::InvalidEncoding)?
            != *output_c_bytes
    {
        return Err(NoteError::InvalidProof);
    }
    let output_i = canonical_point(&output_i_bytes)?;
    let (spend_secret, key_image) = if full {
        let base_spend = canonical_scalar(spend_material, true)?;
        if (ED25519_BASEPOINT_POINT * base_spend).compress().to_bytes() != recipient_spend {
            return Err(NoteError::InvalidProof);
        }
        let spend_secret = base_spend + tweak;
        if spend_secret == Scalar::ZERO {
            return Err(NoteError::InvalidProof);
        }
        (
            spend_secret.to_bytes(),
            (output_i * spend_secret).compress().to_bytes(),
        )
    } else {
        if spend_material.iter().any(|byte| *byte != 0) {
            return Err(NoteError::InvalidEncoding);
        }
        ([0_u8; 32], [0_u8; 32])
    };
    Ok(OpenedNote {
        amount,
        recipient_spend,
        recipient_view,
        spend_secret,
        y: y_bytes,
        mask,
        key_image,
    })
}

#[allow(clippy::similar_names, clippy::too_many_arguments)]
fn scan_outgoing(
    network: u8,
    address_type: u8,
    output_index: u32,
    genesis: &[u8; 32],
    outgoing_secret_bytes: &[u8; 32],
    spend_material: &[u8; 32],
    output_o_bytes: &[u8; 32],
    output_c_bytes: &[u8; 32],
    note_ephemeral_bytes: &[u8; 32],
    tweak_ephemeral_bytes: &[u8; 32],
    ciphertext: &[u8],
) -> Result<OpenedNote, NoteError> {
    if spend_material.iter().any(|byte| *byte != 0) {
        return Err(NoteError::InvalidEncoding);
    }
    canonical_scalar(outgoing_secret_bytes, true)?;
    canonical_point(output_c_bytes)?;
    let output_i_bytes = key_image_base(output_o_bytes)?;
    let associated_data = associated_data(
        network,
        address_type,
        output_index,
        genesis,
        output_o_bytes,
        &output_i_bytes,
        output_c_bytes,
        note_ephemeral_bytes,
        tweak_ephemeral_bytes,
    );
    let mut plaintext = decrypt(
        b"Innova/IV5/NoteEncryption/Outgoing/v1",
        outgoing_secret_bytes,
        &associated_data,
        ciphertext,
        OUTGOING_PLAINTEXT_BYTES,
    )?;
    let (recipient_spend, recipient_view, amount, y_bytes, mask) =
        parse_plaintext(&plaintext, network, address_type, output_index)?;
    let mut note_ephemeral_secret_bytes: [u8; 32] = plaintext
        [RECIPIENT_PLAINTEXT_BYTES..RECIPIENT_PLAINTEXT_BYTES + 32]
        .try_into()
        .map_err(|_| NoteError::BadLength)?;
    let mut tweak_ephemeral_secret_bytes: [u8; 32] = plaintext
        [RECIPIENT_PLAINTEXT_BYTES + 32..]
        .try_into()
        .map_err(|_| NoteError::BadLength)?;
    plaintext.zeroize();
    let note_ephemeral_secret = canonical_scalar(&note_ephemeral_secret_bytes, true)?;
    let tweak_ephemeral_secret = canonical_scalar(&tweak_ephemeral_secret_bytes, true)?;
    note_ephemeral_secret_bytes.zeroize();
    tweak_ephemeral_secret_bytes.zeroize();
    // Both must open, or the sender's own record does not describe an output the
    // recipient can find and spend.
    if (ED25519_BASEPOINT_POINT * note_ephemeral_secret)
        .compress()
        .to_bytes()
        != *note_ephemeral_bytes
        || (ED25519_BASEPOINT_POINT * tweak_ephemeral_secret)
            .compress()
            .to_bytes()
            != *tweak_ephemeral_bytes
        || note_ephemeral_secret == tweak_ephemeral_secret
    {
        return Err(NoteError::InvalidProof);
    }
    let spend = canonical_point(&recipient_spend)?;
    let view = canonical_point(&recipient_view)?;
    let y = canonical_scalar(&y_bytes, true)?;
    let tweak_shared = (view * tweak_ephemeral_secret).compress().to_bytes();
    let tweak = disclosure::receiver_tweak(
        &tweak_shared,
        tweak_ephemeral_bytes,
        &recipient_spend,
        &recipient_view,
        output_index,
    );
    let expected_o = spend + (ED25519_BASEPOINT_POINT * tweak) + (monero_t() * y);
    if expected_o.compress().to_bytes() != *output_o_bytes
        || value::commitment(amount, &mask).map_err(|_| NoteError::InvalidEncoding)?
            != *output_c_bytes
    {
        return Err(NoteError::InvalidProof);
    }
    Ok(OpenedNote {
        amount,
        recipient_spend,
        recipient_view,
        spend_secret: [0_u8; 32],
        y: y_bytes,
        mask,
        key_image: [0_u8; 32],
    })
}

fn encode_result(
    scan_kind: u8,
    network: u8,
    address_type: u8,
    output_index: u32,
    opened: &OpenedNote,
) -> Vec<u8> {
    let mut result = Vec::with_capacity(SCAN_RESULT_BYTES);
    result.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    result.push(scan_kind);
    result.push(network);
    result.push(address_type);
    result.extend_from_slice(&[0_u8; 3]);
    result.extend_from_slice(&output_index.to_le_bytes());
    result.extend_from_slice(&opened.amount.to_le_bytes());
    result.extend_from_slice(&opened.recipient_spend);
    result.extend_from_slice(&opened.recipient_view);
    result.extend_from_slice(&opened.spend_secret);
    result.extend_from_slice(&opened.y);
    result.extend_from_slice(&opened.mask);
    result.extend_from_slice(&opened.key_image);
    debug_assert_eq!(result.len(), SCAN_RESULT_BYTES);
    result
}

/// Attempt a recipient ciphertext with one candidate KDF secret and public leaf
/// fields only, i.e. what an observer holding a published point can run.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn try_open_recipient(
    network: u8,
    address_type: u8,
    output_index: u32,
    genesis: &[u8; 32],
    output_o: &[u8; 32],
    output_c: &[u8; 32],
    note_ephemeral: &[u8; 32],
    tweak_ephemeral: &[u8; 32],
    ciphertext: &[u8],
    candidate_secret: &[u8; 32],
) -> Option<u64> {
    let output_i = key_image_base(output_o).ok()?;
    let associated_data = associated_data(
        network,
        address_type,
        output_index,
        genesis,
        output_o,
        &output_i,
        output_c,
        note_ephemeral,
        tweak_ephemeral,
    );
    let plaintext = decrypt(
        b"Innova/IV5/NoteEncryption/Recipient/v1",
        candidate_secret,
        &associated_data,
        ciphertext,
        RECIPIENT_PLAINTEXT_BYTES,
    )
    .ok()?;
    let (_, _, amount, _, _) =
        parse_plaintext(&plaintext, network, address_type, output_index).ok()?;
    Some(amount)
}

pub(crate) fn scan(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    if request.len() < SCAN_PREFIX_BYTES + 1 {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    if reader.u16().map_err(ResultCode::from)? != PAYLOAD_SCHEMA_U16 {
        return Err(ResultCode::UnsupportedFormat);
    }
    let scan_kind = reader.u8().map_err(ResultCode::from)?;
    let network = reader.u8().map_err(ResultCode::from)?;
    let address_type = reader.u8().map_err(ResultCode::from)?;
    if network > NETWORK_ID_MAX
        || address_type > ADDRESS_TYPE_MAX
        || reader.take(3).map_err(ResultCode::from)? != [0_u8; 3]
    {
        return Err(ResultCode::ConsensusInvalid);
    }
    let output_index = reader.u32().map_err(ResultCode::from)?;
    let genesis = reader.array().map_err(ResultCode::from)?;
    if genesis.iter().all(|byte| *byte == 0) {
        return Err(ResultCode::ConsensusInvalid);
    }
    let scan_secret = reader.array().map_err(ResultCode::from)?;
    let spend_material = reader.array().map_err(ResultCode::from)?;
    let output_o = reader.array().map_err(ResultCode::from)?;
    let output_c = reader.array().map_err(ResultCode::from)?;
    let note_ephemeral = reader.array().map_err(ResultCode::from)?;
    let tweak_ephemeral = reader.array().map_err(ResultCode::from)?;
    let ciphertext = reader
        .take(request.len() - SCAN_PREFIX_BYTES)
        .map_err(ResultCode::from)?;
    reader.finish().map_err(ResultCode::from)?;
    let expected_ciphertext_bytes = match scan_kind {
        SCAN_FULL | SCAN_VIEW_ONLY => RECIPIENT_CIPHERTEXT_BYTES,
        SCAN_OUTGOING => OUTGOING_CIPHERTEXT_BYTES,
        _ => return Err(ResultCode::UnsupportedFormat),
    };
    if ciphertext.len() != expected_ciphertext_bytes {
        return Err(ResultCode::BadLength);
    }
    let opened = match scan_kind {
        SCAN_FULL | SCAN_VIEW_ONLY => scan_receiver(
            scan_kind == SCAN_FULL,
            network,
            address_type,
            output_index,
            &genesis,
            &scan_secret,
            &spend_material,
            &output_o,
            &output_c,
            &note_ephemeral,
            &tweak_ephemeral,
            ciphertext,
        ),
        SCAN_OUTGOING => scan_outgoing(
            network,
            address_type,
            output_index,
            &genesis,
            &scan_secret,
            &spend_material,
            &output_o,
            &output_c,
            &note_ephemeral,
            &tweak_ephemeral,
            ciphertext,
        ),
        _ => Err(NoteError::Unsupported),
    }
    .map_err(ResultCode::from)?;
    Ok(encode_result(
        scan_kind,
        network,
        address_type,
        output_index,
        &opened,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_request(
        kind: u8,
        scan_secret: [u8; 32],
        spend_material: [u8; 32],
        note: &EncryptedNote,
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.extend_from_slice(&[kind, 1, 0, 0, 0, 0]);
        request.extend_from_slice(&7_u32.to_le_bytes());
        request.extend_from_slice(&[0x71; 32]);
        request.extend_from_slice(&scan_secret);
        request.extend_from_slice(&spend_material);
        request.extend_from_slice(&note.output_o);
        request.extend_from_slice(&note.output_c);
        request.extend_from_slice(&note.note_ephemeral);
        request.extend_from_slice(&note.tweak_ephemeral);
        request.extend_from_slice(ciphertext);
        request
    }

    fn note_to(ephemeral_secret: u64, spend_secret: Scalar, view_secret: Scalar) -> EncryptedNote {
        encrypt_note(
            1,
            0,
            7,
            &[0x71; 32],
            &(ED25519_BASEPOINT_POINT * spend_secret).compress().to_bytes(),
            &(ED25519_BASEPOINT_POINT * view_secret).compress().to_bytes(),
            &Scalar::from(7_u64).to_bytes(),
            &Scalar::from(ephemeral_secret).to_bytes(),
            &Scalar::from(ephemeral_secret + 1).to_bytes(),
            99,
            &Scalar::from(17_u64).to_bytes(),
            &Scalar::from(19_u64).to_bytes(),
        )
        .unwrap()
    }

    fn test_note() -> (EncryptedNote, Scalar, Scalar, Scalar) {
        let spend_secret = Scalar::from(3_u64);
        let view_secret = Scalar::from(5_u64);
        let outgoing_secret = Scalar::from(7_u64);
        let note = note_to(13, spend_secret, view_secret);
        (note, spend_secret, view_secret, outgoing_secret)
    }

    #[test]
    fn canonical_encryption_request_is_fixed_and_self_checked() {
        let spend_secret = Scalar::from(3_u64);
        let view_secret = Scalar::from(5_u64);
        let mut request = Vec::new();
        request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.extend_from_slice(&[1, 0]);
        request.extend_from_slice(&7_u32.to_le_bytes());
        request.extend_from_slice(&[0x71; 32]);
        request.extend_from_slice(
            &(ED25519_BASEPOINT_POINT * spend_secret)
                .compress()
                .to_bytes(),
        );
        request.extend_from_slice(
            &(ED25519_BASEPOINT_POINT * view_secret)
                .compress()
                .to_bytes(),
        );
        request.extend_from_slice(&Scalar::from(7_u64).to_bytes());
        request.extend_from_slice(&Scalar::from(13_u64).to_bytes());
        request.extend_from_slice(&Scalar::from(14_u64).to_bytes());
        request.extend_from_slice(&99_u64.to_le_bytes());
        request.extend_from_slice(&Scalar::from(17_u64).to_bytes());
        request.extend_from_slice(&Scalar::from(19_u64).to_bytes());
        assert_eq!(request.len(), ENCRYPT_REQUEST_BYTES);
        let response = encrypt_request(&request).unwrap();
        assert_eq!(response.len(), ENCRYPT_RESULT_BYTES);
        request.push(0);
        assert_eq!(encrypt_request(&request), Err(ResultCode::BadLength));
    }

    #[test]
    fn full_view_only_and_outgoing_scans_agree() {
        let (note, spend_secret, view_secret, outgoing_secret) = test_note();
        let full = scan(&scan_request(
            SCAN_FULL,
            view_secret.to_bytes(),
            spend_secret.to_bytes(),
            &note,
            &note.recipient_ciphertext,
        ))
        .unwrap();
        let view_only = scan(&scan_request(
            SCAN_VIEW_ONLY,
            view_secret.to_bytes(),
            [0_u8; 32],
            &note,
            &note.recipient_ciphertext,
        ))
        .unwrap();
        let outgoing = scan(&scan_request(
            SCAN_OUTGOING,
            outgoing_secret.to_bytes(),
            [0_u8; 32],
            &note,
            &note.outgoing_ciphertext,
        ))
        .unwrap();
        assert_eq!(&full[12..84], &view_only[12..84]);
        assert_eq!(&full[12..84], &outgoing[12..84]);
        assert!(full[84..116].iter().any(|byte| *byte != 0));
        assert!(view_only[84..116].iter().all(|byte| *byte == 0));
        assert!(outgoing[84..116].iter().all(|byte| *byte == 0));
        assert!(full[180..212].iter().any(|byte| *byte != 0));

        // The full scanner's production key-image derivation must feed the
        // exact consensus nullifier accumulator without reinterpretation.
        let key_image: [u8; 32] = full[180..212]
            .try_into()
            .expect("scan result contains one exact key image");
        let mut nullifier_request = vec![1, 0, 1, 0];
        nullifier_request.extend_from_slice(&1_u32.to_le_bytes());
        nullifier_request.extend_from_slice(&key_image);
        assert!(crate::nullifier::update(&nullifier_request).is_ok());
    }

    // I is cleartext in every leaf. Two notes paid to one address must not share it, or
    // anyone holding that address could enumerate every note ever sent to it.
    #[test]
    fn same_address_outputs_get_distinct_recomputable_key_image_bases() {
        let spend_secret = Scalar::from(3_u64);
        let view_secret = Scalar::from(5_u64);
        let recipient_spend = (ED25519_BASEPOINT_POINT * spend_secret)
            .compress()
            .to_bytes();

        let mut seen = std::collections::BTreeSet::new();
        for ephemeral_secret in [13_u64, 23, 29, 31, 37] {
            let note = note_to(ephemeral_secret, spend_secret, view_secret);

            // Nothing owner-derived may appear in the leaf's I.
            assert_ne!(note.output_i, recipient_spend);
            assert_ne!(
                note.output_i,
                (ED25519_BASEPOINT_POINT * view_secret).compress().to_bytes()
            );
            // Anyone holding the leaf recomputes I from O alone.
            assert_eq!(key_image_base(&note.output_o).unwrap(), note.output_i);
            assert!(seen.insert(note.output_i), "I repeated across outputs");
            assert!(seen.contains(&note.output_i));
        }
        assert_eq!(seen.len(), 5);
    }

    // The wallet spends with the I it recomputes from the leaf, so the scanner's key
    // image must be exactly x times that same derived point.
    #[test]
    fn scanned_key_image_uses_the_derived_base() {
        let (note, spend_secret, view_secret, _) = test_note();
        let full = scan(&scan_request(
            SCAN_FULL,
            view_secret.to_bytes(),
            spend_secret.to_bytes(),
            &note,
            &note.recipient_ciphertext,
        ))
        .unwrap();
        let derived_spend = canonical_scalar(&full[84..116].try_into().unwrap(), true).unwrap();
        let base = canonical_point(&key_image_base(&note.output_o).unwrap()).unwrap();
        assert_eq!(
            &full[180..212],
            (base * derived_spend).compress().to_bytes().as_slice()
        );
    }

    #[test]
    fn authentication_and_context_malleation_fail_closed() {
        let (note, spend_secret, view_secret, _) = test_note();
        let mut ciphertext = note.recipient_ciphertext.clone();
        ciphertext[20] ^= 1;
        assert_eq!(
            scan(&scan_request(
                SCAN_FULL,
                view_secret.to_bytes(),
                spend_secret.to_bytes(),
                &note,
                &ciphertext,
            )),
            Err(ResultCode::ConsensusInvalid)
        );
        assert_eq!(
            scan(&scan_request(
                SCAN_FULL,
                Scalar::from(23_u64).to_bytes(),
                spend_secret.to_bytes(),
                &note,
                &note.recipient_ciphertext,
            )),
            Err(ResultCode::ConsensusInvalid)
        );
        let clone_note = || EncryptedNote {
            output_o: note.output_o,
            output_i: note.output_i,
            output_c: note.output_c,
            note_ephemeral: note.note_ephemeral,
            tweak_ephemeral: note.tweak_ephemeral,
            recipient_ciphertext: note.recipient_ciphertext.clone(),
            outgoing_ciphertext: note.outgoing_ciphertext.clone(),
        };
        let mut wrong_note = clone_note();
        wrong_note.output_c[0] ^= 1;
        assert_eq!(
            scan(&scan_request(
                SCAN_FULL,
                view_secret.to_bytes(),
                spend_secret.to_bytes(),
                &wrong_note,
                &wrong_note.recipient_ciphertext,
            )),
            Err(ResultCode::ConsensusInvalid)
        );

        // Both ephemerals sit in the associated data, so exchanging them changes the
        // note key and the tweak at once and must fail on the tag.
        let mut swapped = clone_note();
        swapped.note_ephemeral = note.tweak_ephemeral;
        swapped.tweak_ephemeral = note.note_ephemeral;
        assert_eq!(
            scan(&scan_request(
                SCAN_FULL,
                view_secret.to_bytes(),
                spend_secret.to_bytes(),
                &swapped,
                &swapped.recipient_ciphertext,
            )),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    // The receiver disclosure publishes the tweak's shared point. If that point also
    // keyed the ciphertext, publishing it would open the note.
    #[test]
    fn the_disclosed_shared_point_is_not_the_note_key() {
        let (note, _, view_secret, _) = test_note();
        let tweak_ephemeral = canonical_point(&note.tweak_ephemeral).unwrap();
        let note_ephemeral = canonical_point(&note.note_ephemeral).unwrap();
        assert_ne!(note.note_ephemeral, note.tweak_ephemeral);

        // What a receiver disclosure publishes.
        let disclosed = (tweak_ephemeral * view_secret).compress().to_bytes();
        // What the ciphertext is keyed under.
        let note_shared = (note_ephemeral * view_secret).compress().to_bytes();
        assert_ne!(disclosed, note_shared);

        // The disclosed point still determines the tweak, so the address linkage the
        // disclosure proves is unchanged.
        let spend = (ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
            .compress()
            .to_bytes();
        let view = (ED25519_BASEPOINT_POINT * view_secret).compress().to_bytes();
        let tweak =
            disclosure::receiver_tweak(&disclosed, &note.tweak_ephemeral, &spend, &view, 7);
        let expected = canonical_point(&spend).unwrap()
            + (ED25519_BASEPOINT_POINT * tweak)
            + (monero_t() * Scalar::from(17_u64));
        assert_eq!(expected.compress().to_bytes(), note.output_o);
    }
}
