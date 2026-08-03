//! Fail-closed ABI boundary for Innova IV5. Witness creation and note scanning stay
//! fail-closed until reviewed implementations land. No export activates IV5 consensus.

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};

use blake2::Blake2b512;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use monero_fcmp_plus_plus::FcmpPlusPlus;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

mod disclosure;
mod fcmp;
mod note;
mod nullifier;
mod payload;
mod tree;
mod value;

const ABI_VERSION: u32 = 2;
const DIGEST_SIZE: usize = 32;
const CONTRACT_METADATA_SIZE: usize = 104;
const CONTRACT_METADATA_SIZE_U32: u32 = 104;
const TRANSACTION_VERSION: u32 = 2008;
const TREE_LAYERS: u32 = 8;
const MAX_INPUTS: u32 = 16;
const MAX_OUTPUTS: u32 = 16;
const MAX_PAYLOAD_BYTES: u32 = 256 * 1024;
const DISCLOSURE_MODE_MIN: u32 = 0;
const DISCLOSURE_MODE_MAX: u32 = 7;
const NULLSTAKE_GENERATION_MIN: u32 = 1;
const NULLSTAKE_GENERATION_MAX: u32 = 3;
const PAYLOAD_SCHEMA: u32 = 1;
const PAYLOAD_SCHEMA_U16: u16 = 1;
const ADDRESS_FORMAT: u8 = 1;
const ADDRESS_TYPE_MAX: u8 = 3;
const NETWORK_ID_MAX: u8 = 2;
const ADDRESS_COMPONENT_SIZE: usize = 70;
const KEY_DERIVATION_REQUEST_SIZE: usize = 72;
const KEY_DERIVATION_OUTPUT_SIZE: usize = 232;
const NOTE_ENCRYPT_REQUEST_SIZE: usize = 272;
const KEY_DERIVATION_LABELS: [&[u8]; 5] = [
    b"Innova/IV5/Key/spend/v1",
    b"Innova/IV5/Key/view/v1",
    b"Innova/IV5/Key/outgoing-view/v1",
    b"Innova/IV5/Key/nullifier/v1",
    b"Innova/IV5/Key/staking/v1",
];
pub const CAP_PROTOCOL_CONTRACT: u32 = 1 << 0;
pub const CAP_FCMP_PROOF_SIZE: u32 = 1 << 1;
pub const CAP_FCMP_PROVE: u32 = 1 << 2;
pub const CAP_FCMP_VERIFY: u32 = 1 << 3;
pub const CAP_FCMP_BATCH_VERIFY: u32 = 1 << 4;
pub const CAP_TREE_UPDATE: u32 = 1 << 5;
pub const CAP_TREE_ROOT: u32 = 1 << 6;
pub const CAP_TREE_WITNESS: u32 = 1 << 7;
pub const CAP_PAYLOAD_VALIDATE: u32 = 1 << 8;
pub const CAP_ADDRESS_CODEC: u32 = 1 << 9;
pub const CAP_KEY_DERIVATION: u32 = 1 << 10;
pub const CAP_NOTE_SCAN: u32 = 1 << 11;
pub const CAP_NOTE_ENCRYPT: u32 = 1 << 12;
pub const CAP_VALUE_PROVE: u32 = 1 << 13;
pub const CAP_PAYLOAD_EFFECTS: u32 = 1 << 14;
pub const CAP_NULLIFIER_ACCUMULATOR: u32 = 1 << 15;
const IMPLEMENTED_CAPABILITIES: u32 = CAP_PROTOCOL_CONTRACT
    | CAP_FCMP_PROOF_SIZE
    | CAP_FCMP_PROVE
    | CAP_FCMP_VERIFY
    | CAP_FCMP_BATCH_VERIFY
    | CAP_TREE_UPDATE
    | CAP_TREE_ROOT
    | CAP_PAYLOAD_VALIDATE
    | CAP_ADDRESS_CODEC
    | CAP_KEY_DERIVATION
    | CAP_NOTE_SCAN
    | CAP_NOTE_ENCRYPT
    | CAP_VALUE_PROVE
    | CAP_PAYLOAD_EFFECTS
    | CAP_NULLIFIER_ACCUMULATOR;
const CONSENSUS_CAPABILITIES: u32 = 0;
pub const NOTE_SHIELD: u8 = 0;
pub const NOTE_UNSHIELD: u8 = 1;
pub const NOTE_TRANSFER: u8 = 2;
pub const NOTE_NULLSEND: u8 = 3;
pub const NOTE_DELEGATION_CREATE: u8 = 4;
pub const NOTE_M_OF_N_MINT: u8 = 5;
pub const NOTE_RECLAIM: u8 = 6;
pub const NOTE_CONDITIONAL_MIGRATION: u8 = 7;
pub const NOTE_OPERATION_NONE: u8 = 255;
pub const FINALITY_NONE: u8 = 0;
pub const FINALITY_NULLSTAKE_V1: u8 = 1;
pub const FINALITY_NULLSTAKE_V2: u8 = 2;
pub const FINALITY_NULLSTAKE_V3: u8 = 3;
pub const AUTH_OWNER: u8 = 0;
pub const AUTH_COLD_STAKER: u8 = 1;
pub const AUTH_M_OF_N_PUBLIC_SIGNERS: u8 = 2;
pub const AUTH_M_OF_N_HIDDEN_SIGNERS: u8 = 3;
pub const FINALITY_OBJECT_NONE: u8 = 0;
pub const FINALITY_OBJECT_VOTE: u8 = 1;
pub const FINALITY_OBJECT_TALLY_SHARE: u8 = 2;
pub const FINALITY_OBJECT_CERTIFICATE: u8 = 3;
pub const FINALITY_OBJECT_COMMITTEE_ROTATION: u8 = 4;
const OP_SHIELD: u32 = 1 << 0;
const OP_UNSHIELD: u32 = 1 << 1;
const OP_TRANSFER: u32 = 1 << 2;
const OP_NULLSEND: u32 = 1 << 3;
const OP_NULLSTAKE_V1: u32 = 1 << 4;
const OP_NULLSTAKE_V2: u32 = 1 << 5;
const OP_NULLSTAKE_V3_PRIVATE_COLD: u32 = 1 << 6;
const OP_M_OF_N_PUBLIC_SIGNER: u32 = 1 << 7;
const OP_M_OF_N_HIDDEN_SIGNER: u32 = 1 << 8;
const OP_RECLAIM: u32 = 1 << 9;
const OP_PRIVATE_FINALITY: u32 = 1 << 10;
const REQUIRED_OPERATIONS: u32 = OP_SHIELD
    | OP_UNSHIELD
    | OP_TRANSFER
    | OP_NULLSEND
    | OP_NULLSTAKE_V1
    | OP_NULLSTAKE_V2
    | OP_NULLSTAKE_V3_PRIVATE_COLD
    | OP_M_OF_N_PUBLIC_SIGNER
    | OP_M_OF_N_HIDDEN_SIGNER
    | OP_RECLAIM
    | OP_PRIVATE_FINALITY;
const UPSTREAM_REVISION: [u8; 40] = *b"76399e58bfc7e652d900936f84b3785ea59ab4cd";
const ABI_SCHEMA: &[u8] = include_bytes!("../abi/innova_privacy_vnext_v2.txt");
const PRODUCT_CONTRACT: &[u8] = include_bytes!("../../contract/iv5_protocol_v1.json");
const PROVENANCE: &[u8] = include_bytes!("../provenance.json");

#[must_use]
pub const fn envelope_allows(
    wire_version: u32,
    operation: u8,
    profile: u8,
    authorization: u8,
    finality_object: u8,
    disclosure_mask: u8,
) -> bool {
    let known_operation =
        operation <= NOTE_CONDITIONAL_MIGRATION || operation == NOTE_OPERATION_NONE;
    if !known_operation
        || profile > FINALITY_NULLSTAKE_V3
        || authorization > AUTH_M_OF_N_HIDDEN_SIGNERS
        || finality_object > FINALITY_OBJECT_COMMITTEE_ROTATION
        || disclosure_mask > 7
    {
        return false;
    }
    let is_finality = finality_object != FINALITY_OBJECT_NONE;
    if (is_finality && (operation != NOTE_OPERATION_NONE || profile == FINALITY_NONE))
        || (!is_finality && (operation == NOTE_OPERATION_NONE || profile != FINALITY_NONE))
    {
        return false;
    }
    match wire_version {
        2000 => {
            matches!(operation, NOTE_SHIELD | NOTE_UNSHIELD | NOTE_TRANSFER)
                && disclosure_mask == 7
                && authorization == AUTH_OWNER
        }
        2001 => {
            matches!(operation, NOTE_SHIELD | NOTE_UNSHIELD | NOTE_TRANSFER)
                && authorization == AUTH_OWNER
        }
        2002 => matches!(operation, NOTE_TRANSFER | NOTE_NULLSEND) && authorization == AUTH_OWNER,
        2003 => profile == FINALITY_NULLSTAKE_V1 && authorization == AUTH_OWNER,
        2004 => profile == FINALITY_NULLSTAKE_V2 && authorization == AUTH_OWNER,
        2005 => profile == FINALITY_NULLSTAKE_V3 || operation == NOTE_DELEGATION_CREATE,
        2006 => {
            operation == NOTE_M_OF_N_MINT
                && matches!(
                    authorization,
                    AUTH_M_OF_N_PUBLIC_SIGNERS | AUTH_M_OF_N_HIDDEN_SIGNERS
                )
        }
        2007 => operation == NOTE_RECLAIM && authorization == AUTH_OWNER,
        2008 => true,
        _ => false,
    }
}

/// Fixed, non-consensus product parameters returned through caller storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ContractMetadata {
    /// Exact byte size of this structure.
    pub struct_size: u32,
    /// C ABI version.
    pub abi_version: u32,
    /// Reserved transaction version; still consensus-inactive.
    pub transaction_version: u32,
    /// Zero until a separately reviewed activation enables version 2008.
    pub consensus_active: u32,
    /// Fixed FCMP++ tree depth.
    pub tree_layers: u32,
    /// Maximum FCMP++ inputs per transaction.
    pub max_inputs: u32,
    /// Maximum privacy outputs per transaction.
    pub max_outputs: u32,
    /// Maximum canonical vNext payload size.
    pub max_payload_bytes: u32,
    /// First supported selective-disclosure mode.
    pub disclosure_mode_min: u32,
    /// Last supported selective-disclosure mode.
    pub disclosure_mode_max: u32,
    /// First required `NullStake` generation.
    pub nullstake_generation_min: u32,
    /// Last required `NullStake` generation.
    pub nullstake_generation_max: u32,
    /// Bitset of every required product operation.
    pub required_operations: u32,
    /// Canonical payload schema exposed by this ABI.
    pub payload_schema: u32,
    /// Operations with a complete implementation in this binary.
    pub implemented_capabilities: u32,
    /// Implemented operations authorized for consensus use.
    pub consensus_capabilities: u32,
    /// Lowercase hexadecimal pinned upstream Git revision, without a terminator.
    pub upstream_revision: [u8; 40],
}

const _: [(); CONTRACT_METADATA_SIZE] = [(); std::mem::size_of::<ContractMetadata>()];

const CONTRACT_METADATA: ContractMetadata = ContractMetadata {
    struct_size: CONTRACT_METADATA_SIZE_U32,
    abi_version: ABI_VERSION,
    transaction_version: TRANSACTION_VERSION,
    consensus_active: 0,
    tree_layers: TREE_LAYERS,
    max_inputs: MAX_INPUTS,
    max_outputs: MAX_OUTPUTS,
    max_payload_bytes: MAX_PAYLOAD_BYTES,
    disclosure_mode_min: DISCLOSURE_MODE_MIN,
    disclosure_mode_max: DISCLOSURE_MODE_MAX,
    nullstake_generation_min: NULLSTAKE_GENERATION_MIN,
    nullstake_generation_max: NULLSTAKE_GENERATION_MAX,
    required_operations: REQUIRED_OPERATIONS,
    payload_schema: PAYLOAD_SCHEMA,
    implemented_capabilities: IMPLEMENTED_CAPABILITIES,
    consensus_capabilities: CONSENSUS_CAPABILITIES,
    upstream_revision: UPSTREAM_REVISION,
};

/// Stable result taxonomy shared by all future privacy-vNext ABI functions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ResultCode {
    /// The requested operation completed successfully.
    Valid = 0,
    /// Peer-controlled data is well-formed but consensus-invalid.
    ConsensusInvalid = 1,
    /// A pointer is null or a caller-owned buffer has the wrong length.
    BadLength = 2,
    /// The requested format or protocol operation is not implemented.
    UnsupportedFormat = 3,
    /// A declared resource bound would be exceeded.
    ResourceLimit = 4,
    /// A Rust panic was contained at the ABI boundary.
    ContainedPanic = 5,
    /// Local state, allocation, or another internal requirement failed.
    InternalLocalStateFailure = 6,
}

fn ffi_boundary(operation: impl FnOnce() -> Result<(), ResultCode>) -> i32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => ResultCode::Valid as i32,
        Ok(Err(code)) => code as i32,
        Err(_) => ResultCode::ContainedPanic as i32,
    }
}

fn copy_digest(input: &[u8], out: *mut u8, out_len: usize) -> Result<(), ResultCode> {
    if out.is_null() || out_len != DIGEST_SIZE {
        return Err(ResultCode::BadLength);
    }
    let digest = Sha256::digest(input);
    // SAFETY: null and exact length were checked above. The C contract requires
    // `out` to identify writable caller-owned storage of `out_len` bytes.
    unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), out, DIGEST_SIZE) };
    Ok(())
}

fn validate_request(request: *const u8, request_len: usize) -> Result<(), ResultCode> {
    if request.is_null() || request_len == 0 {
        return Err(ResultCode::BadLength);
    }
    if request_len > MAX_PAYLOAD_BYTES as usize {
        return Err(ResultCode::ResourceLimit);
    }
    Ok(())
}

fn validate_optional_output(
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> Result<(), ResultCode> {
    if out_written.is_null() || (out.is_null() != (out_capacity == 0)) {
        return Err(ResultCode::BadLength);
    }
    if out_capacity > MAX_PAYLOAD_BYTES as usize {
        return Err(ResultCode::ResourceLimit);
    }
    Ok(())
}

fn unsupported_transform(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> Result<(), ResultCode> {
    validate_request(request, request_len)?;
    validate_optional_output(out, out_capacity, out_written)?;
    Err(ResultCode::UnsupportedFormat)
}

fn write_variable_output(
    bytes: &[u8],
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> Result<(), ResultCode> {
    validate_optional_output(out, out_capacity, out_written)?;
    // SAFETY: validation requires writable caller-owned size storage.
    unsafe { out_written.write(bytes.len()) };
    if out.is_null() {
        return Ok(());
    }
    if out_capacity < bytes.len() {
        return Err(ResultCode::ResourceLimit);
    }
    // SAFETY: the non-null caller buffer has at least `bytes.len()` bytes.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    Ok(())
}

fn double_sha256_checksum(bytes: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

fn base58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let leading_zeroes = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits = vec![0_u8];
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            let value = (u32::from(*digit) * 256) + carry;
            *digit = u8::try_from(value % 58).expect("base58 digit is bounded");
            carry = value / 58;
        }
        while carry != 0 {
            digits.push(u8::try_from(carry % 58).expect("base58 digit is bounded"));
            carry /= 58;
        }
    }

    let mut encoded = String::with_capacity(leading_zeroes + digits.len());
    encoded.extend(std::iter::repeat_n('1', leading_zeroes));
    for digit in digits.iter().rev() {
        encoded.push(char::from(ALPHABET[usize::from(*digit)]));
    }
    encoded
}

fn base58_value(byte: u8) -> Option<u8> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .and_then(|position| u8::try_from(position).ok())
}

fn base58_decode(encoded: &[u8]) -> Result<Vec<u8>, ResultCode> {
    if encoded.is_empty() || !encoded.is_ascii() {
        return Err(ResultCode::ConsensusInvalid);
    }
    let leading_zeroes = encoded.iter().take_while(|byte| **byte == b'1').count();
    let mut bytes = vec![0_u8];
    for encoded_byte in encoded {
        let mut carry = u32::from(base58_value(*encoded_byte).ok_or(ResultCode::ConsensusInvalid)?);
        for byte in &mut bytes {
            let value = (u32::from(*byte) * 58) + carry;
            *byte = u8::try_from(value & 0xff).expect("base256 digit is bounded");
            carry = value >> 8;
        }
        while carry != 0 {
            bytes.push(u8::try_from(carry & 0xff).expect("base256 digit is bounded"));
            carry >>= 8;
        }
        if bytes.len() > ADDRESS_COMPONENT_SIZE + 4 {
            return Err(ResultCode::ConsensusInvalid);
        }
    }

    let mut decoded = Vec::with_capacity(leading_zeroes + bytes.len());
    decoded.resize(leading_zeroes, 0);
    decoded.extend(bytes.iter().rev());
    if base58_encode(&decoded).as_bytes() != encoded {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(decoded)
}

fn validate_public_key(bytes: [u8; 32]) -> Result<(), ResultCode> {
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or(ResultCode::ConsensusInvalid)?;
    if point == EdwardsPoint::identity()
        || !point.is_torsion_free()
        || point.compress().to_bytes() != bytes
    {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(())
}

fn parse_address_components(request: &[u8]) -> Result<[u8; ADDRESS_COMPONENT_SIZE], ResultCode> {
    let components: [u8; ADDRESS_COMPONENT_SIZE] =
        request.try_into().map_err(|_| ResultCode::BadLength)?;
    if u16::from_le_bytes([components[0], components[1]]) != PAYLOAD_SCHEMA_U16 {
        return Err(ResultCode::UnsupportedFormat);
    }
    if components[2] > NETWORK_ID_MAX
        || components[3] != ADDRESS_FORMAT
        || components[4] > ADDRESS_TYPE_MAX
        || components[5] != 0
    {
        return Err(ResultCode::ConsensusInvalid);
    }
    validate_public_key(
        components[6..38]
            .try_into()
            .map_err(|_| ResultCode::InternalLocalStateFailure)?,
    )?;
    validate_public_key(
        components[38..70]
            .try_into()
            .map_err(|_| ResultCode::InternalLocalStateFailure)?,
    )?;
    Ok(components)
}

fn encode_address_components(components: &[u8; ADDRESS_COMPONENT_SIZE]) -> String {
    let mut raw = Vec::with_capacity(ADDRESS_COMPONENT_SIZE + 4);
    raw.extend_from_slice(b"IV5");
    raw.extend_from_slice(&components[2..5]);
    raw.extend_from_slice(&components[6..]);
    raw.extend_from_slice(&double_sha256_checksum(&raw));
    base58_encode(&raw)
}

fn derive_scalar(
    label: &[u8],
    seed: &[u8; 32],
    genesis: &[u8; 32],
    index: u32,
    network: u8,
    address_type: u8,
) -> Scalar {
    let mut counter = 0_u32;
    loop {
        let mut hash = Blake2b512::new();
        hash.update(label);
        hash.update(genesis);
        hash.update(index.to_le_bytes());
        hash.update([network, address_type]);
        hash.update(seed);
        hash.update(counter.to_le_bytes());
        let digest = hash.finalize();
        let mut wide = [0_u8; 64];
        wide.copy_from_slice(&digest);
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        if scalar != Scalar::ZERO {
            return scalar;
        }
        counter = counter
            .checked_add(1)
            .expect("scalar retry counter exhausted");
    }
}

// Force the pinned FCMP++ package and all of its cryptographic path
// dependencies to compile even though no proof semantics cross this ABI yet.
fn upstream_compile_marker() -> usize {
    std::mem::size_of::<monero_fcmp_plus_plus::Input>()
}

/// Return the metadata ABI version through caller-owned storage.
///
/// # Safety
///
/// `out_version` must point to writable caller-owned storage for one `u32`.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_abi_version(out_version: *mut u32) -> i32 {
    ffi_boundary(|| {
        if out_version.is_null() {
            return Err(ResultCode::BadLength);
        }
        let _ = upstream_compile_marker();
        // SAFETY: null was checked and the C contract requires a writable u32.
        unsafe { out_version.write(ABI_VERSION) };
        Ok(())
    })
}

/// Return SHA-256 of the canonical ABI schema through caller-owned storage.
///
/// # Safety
///
/// `out` must point to `out_len` writable caller-owned bytes.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_abi_hash(out: *mut u8, out_len: usize) -> i32 {
    ffi_boundary(|| copy_digest(ABI_SCHEMA, out, out_len))
}

/// Return SHA-256 of the checked-in provenance manifest.
///
/// # Safety
///
/// `out` must point to `out_len` writable caller-owned bytes.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_provenance_digest(
    out: *mut u8,
    out_len: usize,
) -> i32 {
    ffi_boundary(|| copy_digest(PROVENANCE, out, out_len))
}

/// Return SHA-256 of the fixed, non-consensus product contract (not an activation signal).
/// # Safety
///
/// `out` must point to `out_len` writable caller-owned bytes.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_parameter_digest(
    out: *mut u8,
    out_len: usize,
) -> i32 {
    ffi_boundary(|| copy_digest(PRODUCT_CONTRACT, out, out_len))
}

/// Copy the fixed, non-consensus product contract into caller-owned storage.
///
/// # Safety
/// `out` must point to `sizeof(ContractMetadata)` writable bytes aligned for `ContractMetadata`.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_contract_metadata(
    out: *mut ContractMetadata,
    out_len: usize,
) -> i32 {
    ffi_boundary(|| {
        if out.is_null() || out_len != CONTRACT_METADATA_SIZE {
            return Err(ResultCode::BadLength);
        }
        // SAFETY: null and exact length were checked above. The typed pointer
        // carries the alignment requirement documented by the C ABI.
        unsafe { out.write(CONTRACT_METADATA) };
        Ok(())
    })
}

/// Copy or size-query (`out == NULL`, `out_capacity == 0`) the normative IV5 protocol contract.
/// # Safety
/// `out_written` must be writable `usize` storage; a non-null `out` needs `out_capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_protocol_contract(
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        if out_written.is_null() || (out.is_null() != (out_capacity == 0)) {
            return Err(ResultCode::BadLength);
        }
        let required = PRODUCT_CONTRACT.len();
        // SAFETY: null was checked and the C contract requires writable storage.
        unsafe { out_written.write(required) };
        if out.is_null() {
            return Ok(());
        }
        if out_capacity < required {
            return Err(ResultCode::ResourceLimit);
        }
        // SAFETY: the non-null caller buffer is at least `required` bytes.
        unsafe { ptr::copy_nonoverlapping(PRODUCT_CONTRACT.as_ptr(), out, required) };
        Ok(())
    })
}

/// Serialized FCMP++ proof size for 1 through 16 inputs and exactly eight layers.
/// # Safety
///
/// `out_size` must point to writable caller-owned storage for one `usize`.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_fcmp_proof_size(
    inputs: u32,
    layers: u32,
    out_size: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        if out_size.is_null() || inputs == 0 || layers != TREE_LAYERS {
            return Err(ResultCode::BadLength);
        }
        if inputs > MAX_INPUTS {
            return Err(ResultCode::ResourceLimit);
        }
        let inputs = usize::try_from(inputs).map_err(|_| ResultCode::ResourceLimit)?;
        let layers = usize::try_from(layers).map_err(|_| ResultCode::ResourceLimit)?;
        let proof_size = FcmpPlusPlus::proof_size(inputs, layers);
        // SAFETY: null was checked and the C contract requires a writable size_t.
        unsafe { out_size.write(proof_size) };
        Ok(())
    })
}

/// Construct an FCMP++ proof from a canonical ABI-v2 proving request.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_fcmp_prove(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let response = fcmp::prove(request)?;
        write_variable_output(&response, out, out_capacity, out_written)
    })
}

/// Verify one canonical ABI-v2 FCMP++ request.
///
/// # Safety
///
/// `request` must identify `request_len` readable caller-owned bytes.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_fcmp_verify(
    request: *const u8,
    request_len: usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        fcmp::verify(request)
    })
}

/// Verify a canonical batch of FCMP++ requests.
///
/// # Safety
///
/// `request` must identify `request_len` readable caller-owned bytes.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_fcmp_batch_verify(
    request: *const u8,
    request_len: usize,
    request_count: u32,
) -> i32 {
    ffi_boundary(|| {
        if request_count == 0 {
            return Err(ResultCode::BadLength);
        }
        if request_count > MAX_INPUTS {
            return Err(ResultCode::ResourceLimit);
        }
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        fcmp::verify_batch(request, request_count)
    })
}

macro_rules! unavailable_transform_export {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        ///
        /// # Safety
        ///
        /// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            request: *const u8,
            request_len: usize,
            out: *mut u8,
            out_capacity: usize,
            out_written: *mut usize,
        ) -> i32 {
            ffi_boundary(|| {
                unsupported_transform(request, request_len, out, out_capacity, out_written)
            })
        }
    };
}

unavailable_transform_export!(
    innova_privacy_vnext_tree_witness,
    "Produce a canonical membership witness from caller-owned tree state."
);

/// Scan one canonical IV5 output with full, view-only, or outgoing material.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_note_scan(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let result = note::scan(request)?;
        write_variable_output(&result, out, out_capacity, out_written)
    })
}

/// Encrypt one canonical IV5 note for its recipient and outgoing scanner.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_note_encrypt(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        if request_len != NOTE_ENCRYPT_REQUEST_SIZE {
            return Err(ResultCode::BadLength);
        }
        // SAFETY: request validation and the exact length check precede this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let result = note::encrypt_request(request)?;
        write_variable_output(&result, out, out_capacity, out_written)
    })
}

/// Construct and self-verify canonical IV5 range, balance, and binding proofs.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_value_prove(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let result = value::prove_request(request)?;
        write_variable_output(&result, out, out_capacity, out_written)
    })
}

/// Initialize or update the canonical eight-layer IV5 FCMP++ frontier.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_tree_update(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let state = tree::update(request)?;
        write_variable_output(&state, out, out_capacity, out_written)
    })
}

/// Calculate the fixed-depth root for a canonical IV5 FCMP++ frontier.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_tree_root(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let root = tree::root(request)?;
        write_variable_output(&root, out, out_capacity, out_written)
    })
}

/// Append canonical spent key images to the bounded IV5 nullifier accumulator.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_nullifier_update(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let state = nullifier::update(request)?;
        write_variable_output(&state, out, out_capacity, out_written)
    })
}

/// Decode and return one canonical IV5 nullifier accumulator state/root.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_nullifier_root(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let root = nullifier::root(request)?;
        write_variable_output(&root, out, out_capacity, out_written)
    })
}

/// Encode one canonical IV5 `Base58Check` address component record.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_address_encode(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        if request_len != ADDRESS_COMPONENT_SIZE {
            return Err(ResultCode::BadLength);
        }
        // SAFETY: request validation and the exact length check precede this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let components = parse_address_components(request)?;
        let encoded = encode_address_components(&components);
        write_variable_output(encoded.as_bytes(), out, out_capacity, out_written)
    })
}

/// Decode one strict IV5 `Base58Check` address for an expected network.
///
/// The request is `schema_u16 || expected_network_u8 || reserved_zero_u8 ||
/// address_ascii`. The output is the canonical 70-byte component record.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_address_decode(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        validate_optional_output(out, out_capacity, out_written)?;
        if request_len <= 4 {
            return Err(ResultCode::BadLength);
        }
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        if u16::from_le_bytes([request[0], request[1]]) != PAYLOAD_SCHEMA_U16 {
            return Err(ResultCode::UnsupportedFormat);
        }
        let expected_network = request[2];
        if expected_network > NETWORK_ID_MAX || request[3] != 0 {
            return Err(ResultCode::ConsensusInvalid);
        }
        let decoded = base58_decode(&request[4..])?;
        if decoded.len() != ADDRESS_COMPONENT_SIZE + 4 {
            return Err(ResultCode::ConsensusInvalid);
        }
        let (raw, checksum) = decoded.split_at(ADDRESS_COMPONENT_SIZE);
        if checksum != double_sha256_checksum(raw) {
            return Err(ResultCode::ConsensusInvalid);
        }
        if &raw[..3] != b"IV5" || raw[3] != expected_network {
            return Err(ResultCode::ConsensusInvalid);
        }

        let mut components = [0_u8; ADDRESS_COMPONENT_SIZE];
        components[..2].copy_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        components[2..5].copy_from_slice(&raw[3..6]);
        components[5] = 0;
        components[6..].copy_from_slice(&raw[6..]);
        parse_address_components(&components)?;
        if encode_address_components(&components).as_bytes() != &request[4..] {
            return Err(ResultCode::ConsensusInvalid);
        }
        write_variable_output(&components, out, out_capacity, out_written)
    })
}

/// Derive the five IV5 secret domains and spend/view public keys.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_key_derive(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        if request_len != KEY_DERIVATION_REQUEST_SIZE {
            return Err(ResultCode::BadLength);
        }
        // SAFETY: request validation and the exact length check precede this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        if u16::from_le_bytes([request[0], request[1]]) != PAYLOAD_SCHEMA_U16 {
            return Err(ResultCode::UnsupportedFormat);
        }
        let network = request[2];
        let address_type = request[3];
        if network > NETWORK_ID_MAX || address_type > ADDRESS_TYPE_MAX {
            return Err(ResultCode::ConsensusInvalid);
        }
        let index = u32::from_le_bytes(
            request[4..8]
                .try_into()
                .map_err(|_| ResultCode::InternalLocalStateFailure)?,
        );
        let seed: &[u8; 32] = request[8..40]
            .try_into()
            .map_err(|_| ResultCode::InternalLocalStateFailure)?;
        let genesis: &[u8; 32] = request[40..72]
            .try_into()
            .map_err(|_| ResultCode::InternalLocalStateFailure)?;
        if seed.iter().all(|byte| *byte == 0) || genesis.iter().all(|byte| *byte == 0) {
            return Err(ResultCode::ConsensusInvalid);
        }

        let mut scalars = KEY_DERIVATION_LABELS
            .map(|label| derive_scalar(label, seed, genesis, index, network, address_type));
        let mut result = [0_u8; KEY_DERIVATION_OUTPUT_SIZE];
        result[..2].copy_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        result[2] = network;
        result[3] = address_type;
        result[4..8].copy_from_slice(&index.to_le_bytes());
        for (position, scalar) in scalars.iter().enumerate() {
            let start = 8 + (position * 32);
            result[start..start + 32].copy_from_slice(&scalar.to_bytes());
        }
        result[168..200]
            .copy_from_slice((ED25519_BASEPOINT_POINT * scalars[0]).compress().as_bytes());
        result[200..232]
            .copy_from_slice((ED25519_BASEPOINT_POINT * scalars[1]).compress().as_bytes());
        let write_result = write_variable_output(&result, out, out_capacity, out_written);
        for scalar in &mut scalars {
            scalar.zeroize();
        }
        result.zeroize();
        write_result
    })
}

/// Validate one canonical IV5 payload and its contextual commitments.
///
/// # Safety
///
/// `request` must identify `request_len` readable caller-owned bytes.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_payload_validate(
    request: *const u8,
    request_len: usize,
) -> i32 {
    ffi_boundary(|| {
        if request.is_null() {
            return Err(ResultCode::BadLength);
        }
        // SAFETY: null was checked and the caller guarantees `request_len`
        // readable bytes. The payload parser performs all framing checks.
        payload::validate(unsafe { slice::from_raw_parts(request, request_len) })
    })
}

/// Validate a canonical IV5 payload and extract its ordered state effects.
///
/// # Safety
///
/// Input and output pointers must satisfy the ABI-v2 caller-ownership contract.
#[no_mangle]
pub unsafe extern "C" fn innova_privacy_vnext_payload_effects(
    request: *const u8,
    request_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_written: *mut usize,
) -> i32 {
    ffi_boundary(|| {
        validate_request(request, request_len)?;
        // SAFETY: request validation precedes this read.
        let request = unsafe { slice::from_raw_parts(request, request_len) };
        let effects = payload::effects(request)?;
        write_variable_output(&effects, out, out_capacity, out_written)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_codes_are_stable() {
        assert_eq!(ResultCode::Valid as i32, 0);
        assert_eq!(ResultCode::ConsensusInvalid as i32, 1);
        assert_eq!(ResultCode::BadLength as i32, 2);
        assert_eq!(ResultCode::UnsupportedFormat as i32, 3);
        assert_eq!(ResultCode::ResourceLimit as i32, 4);
        assert_eq!(ResultCode::ContainedPanic as i32, 5);
        assert_eq!(ResultCode::InternalLocalStateFailure as i32, 6);
    }

    #[test]
    fn canonical_typed_contract_and_envelope_matrix_are_stable() {
        assert!(envelope_allows(
            2000,
            NOTE_TRANSFER,
            FINALITY_NONE,
            AUTH_OWNER,
            FINALITY_OBJECT_NONE,
            7
        ));
        assert!(!envelope_allows(
            2000,
            NOTE_TRANSFER,
            FINALITY_NONE,
            AUTH_OWNER,
            FINALITY_OBJECT_NONE,
            6
        ));
        assert!(envelope_allows(
            2003,
            NOTE_OPERATION_NONE,
            FINALITY_NULLSTAKE_V1,
            AUTH_OWNER,
            FINALITY_OBJECT_VOTE,
            7
        ));
        assert!(envelope_allows(
            2008,
            NOTE_CONDITIONAL_MIGRATION,
            FINALITY_NONE,
            AUTH_OWNER,
            FINALITY_OBJECT_NONE,
            0
        ));
        assert!(!envelope_allows(
            2008,
            NOTE_OPERATION_NONE,
            FINALITY_NONE,
            AUTH_OWNER,
            FINALITY_OBJECT_NONE,
            7
        ));
    }

    #[test]
    fn panic_is_contained() {
        let result = ffi_boundary(|| -> Result<(), ResultCode> { panic!("test panic") });
        assert_eq!(result, ResultCode::ContainedPanic as i32);
    }

    #[test]
    fn caller_owned_buffers_are_exact() {
        let mut digest = [0_u8; DIGEST_SIZE];
        // SAFETY: every call supplies the exact writable storage described by
        // the ABI, except the intentional null/short negative cases.
        assert_eq!(
            unsafe { innova_privacy_vnext_abi_hash(digest.as_mut_ptr(), digest.len()) },
            ResultCode::Valid as i32
        );
        assert_eq!(digest.as_slice(), Sha256::digest(ABI_SCHEMA).as_slice());
        assert_eq!(
            unsafe { innova_privacy_vnext_abi_hash(digest.as_mut_ptr(), digest.len() - 1) },
            ResultCode::BadLength as i32
        );
        assert_eq!(
            unsafe { innova_privacy_vnext_abi_hash(ptr::null_mut(), digest.len()) },
            ResultCode::BadLength as i32
        );
    }

    #[test]
    fn parameter_digest_identifies_the_inactive_product_contract() {
        let mut digest = [0_u8; DIGEST_SIZE];
        // SAFETY: the call supplies an exact writable 32-byte buffer.
        assert_eq!(
            unsafe { innova_privacy_vnext_parameter_digest(digest.as_mut_ptr(), digest.len()) },
            ResultCode::Valid as i32
        );
        assert_eq!(
            digest.as_slice(),
            Sha256::digest(PRODUCT_CONTRACT).as_slice()
        );
    }

    #[test]
    fn metadata_fixes_the_complete_inactive_product_contract() {
        let mut metadata = ContractMetadata {
            struct_size: 0,
            abi_version: 0,
            transaction_version: 0,
            consensus_active: 1,
            tree_layers: 0,
            max_inputs: 0,
            max_outputs: 0,
            max_payload_bytes: 0,
            disclosure_mode_min: 99,
            disclosure_mode_max: 99,
            nullstake_generation_min: 0,
            nullstake_generation_max: 0,
            required_operations: 0,
            payload_schema: 0,
            implemented_capabilities: 0,
            consensus_capabilities: u32::MAX,
            upstream_revision: [0; 40],
        };
        // SAFETY: the call supplies a correctly aligned, exact-size structure.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_contract_metadata(
                    &raw mut metadata,
                    std::mem::size_of::<ContractMetadata>(),
                )
            },
            ResultCode::Valid as i32
        );
        assert_eq!(metadata, CONTRACT_METADATA);
        assert_eq!(metadata.struct_size, 104);
        assert_eq!(metadata.transaction_version, 2008);
        assert_eq!(metadata.consensus_active, 0);
        assert_eq!(metadata.tree_layers, 8);
        assert_eq!((metadata.max_inputs, metadata.max_outputs), (16, 16));
        assert_eq!(metadata.max_payload_bytes, 256 * 1024);
        assert_eq!(metadata.payload_schema, 1);
        assert_eq!(metadata.implemented_capabilities, IMPLEMENTED_CAPABILITIES);
        assert_eq!(metadata.consensus_capabilities, 0);
        assert_eq!(
            (metadata.disclosure_mode_min, metadata.disclosure_mode_max),
            (0, 7)
        );
        assert_eq!(
            (
                metadata.nullstake_generation_min,
                metadata.nullstake_generation_max
            ),
            (1, 3)
        );
        assert_eq!(metadata.required_operations, (1 << 11) - 1);
        assert_eq!(metadata.upstream_revision, UPSTREAM_REVISION);
    }

    #[test]
    fn proof_size_is_upstream_exact_for_every_permitted_input_count() {
        for inputs in 1..=MAX_INPUTS {
            let mut actual = 0_usize;
            // SAFETY: `actual` is writable caller-owned size_t storage.
            assert_eq!(
                unsafe {
                    innova_privacy_vnext_fcmp_proof_size(inputs, TREE_LAYERS, &raw mut actual)
                },
                ResultCode::Valid as i32
            );
            assert_eq!(
                actual,
                FcmpPlusPlus::proof_size(inputs as usize, TREE_LAYERS as usize)
            );
        }
    }

    #[test]
    fn proof_size_rejects_bad_dimensions_and_resource_excess_without_writing() {
        let mut output = usize::MAX;
        // SAFETY: `output` is writable caller-owned size_t storage.
        assert_eq!(
            unsafe { innova_privacy_vnext_fcmp_proof_size(0, TREE_LAYERS, &raw mut output) },
            ResultCode::BadLength as i32
        );
        assert_eq!(output, usize::MAX);
        assert_eq!(
            unsafe { innova_privacy_vnext_fcmp_proof_size(1, TREE_LAYERS - 1, &raw mut output) },
            ResultCode::BadLength as i32
        );
        assert_eq!(output, usize::MAX);
        assert_eq!(
            unsafe {
                innova_privacy_vnext_fcmp_proof_size(MAX_INPUTS + 1, TREE_LAYERS, &raw mut output)
            },
            ResultCode::ResourceLimit as i32
        );
        assert_eq!(output, usize::MAX);
        assert_eq!(
            unsafe { innova_privacy_vnext_fcmp_proof_size(1, TREE_LAYERS, ptr::null_mut()) },
            ResultCode::BadLength as i32
        );
    }

    #[test]
    fn protocol_contract_query_and_copy_are_exact() {
        let mut required = usize::MAX;
        // SAFETY: the size query supplies writable size storage and no output buffer.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_protocol_contract(ptr::null_mut(), 0, &raw mut required)
            },
            ResultCode::Valid as i32
        );
        assert_eq!(required, PRODUCT_CONTRACT.len());

        let mut contract = vec![0_u8; required];
        let mut written = 0;
        // SAFETY: the output buffer is exactly the queried size.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_protocol_contract(
                    contract.as_mut_ptr(),
                    contract.len(),
                    &raw mut written,
                )
            },
            ResultCode::Valid as i32
        );
        assert_eq!(written, PRODUCT_CONTRACT.len());
        assert_eq!(contract, PRODUCT_CONTRACT);
    }

    #[test]
    fn proof_operations_reject_malformed_frames_without_mutation() {
        let request = [1_u8];
        let mut output = [0xa5_u8; 8];
        let mut written = usize::MAX;
        // SAFETY: all pointers identify caller-owned buffers of the declared sizes.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_fcmp_prove(
                    request.as_ptr(),
                    request.len(),
                    output.as_mut_ptr(),
                    output.len(),
                    &raw mut written,
                )
            },
            ResultCode::BadLength as i32
        );
        assert_eq!(output, [0xa5; 8]);
        assert_eq!(written, usize::MAX);

        // SAFETY: the request is one readable caller-owned byte.
        let single = unsafe { innova_privacy_vnext_fcmp_verify(request.as_ptr(), request.len()) };
        // SAFETY: the request is one readable caller-owned byte and count is one.
        let batch =
            unsafe { innova_privacy_vnext_fcmp_batch_verify(request.as_ptr(), request.len(), 1) };
        assert_eq!(single, ResultCode::BadLength as i32);
        assert_eq!(batch, single);

        // SAFETY: no memory is read because the resource limit is checked first.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_fcmp_verify(request.as_ptr(), (MAX_PAYLOAD_BYTES as usize) + 1)
            },
            ResultCode::ResourceLimit as i32
        );
    }

    fn test_key_request(network: u8, index: u32) -> [u8; KEY_DERIVATION_REQUEST_SIZE] {
        let mut request = [0_u8; KEY_DERIVATION_REQUEST_SIZE];
        request[..2].copy_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request[2] = network;
        request[4..8].copy_from_slice(&index.to_le_bytes());
        for (position, byte) in request[8..40].iter_mut().enumerate() {
            *byte = u8::try_from(position + 1).expect("test seed position is bounded");
        }
        for (position, byte) in request[40..72].iter_mut().enumerate() {
            *byte = 0xa0_u8
                .checked_add(u8::try_from(position).expect("test genesis position is bounded"))
                .expect("test genesis byte is bounded");
        }
        request
    }

    fn derive_test_keys(network: u8, index: u32) -> [u8; KEY_DERIVATION_OUTPUT_SIZE] {
        let request = test_key_request(network, index);
        let mut output = [0_u8; KEY_DERIVATION_OUTPUT_SIZE];
        let mut written = 0;
        // SAFETY: all pointers identify exact caller-owned request/output storage.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_key_derive(
                    request.as_ptr(),
                    request.len(),
                    output.as_mut_ptr(),
                    output.len(),
                    &raw mut written,
                )
            },
            ResultCode::Valid as i32
        );
        assert_eq!(written, output.len());
        output
    }

    #[test]
    fn key_derivation_is_deterministic_and_separated_by_context() {
        let first = derive_test_keys(1, 7);
        assert_eq!(first, derive_test_keys(1, 7));
        assert_ne!(first, derive_test_keys(1, 8));
        assert_ne!(first, derive_test_keys(2, 7));
        validate_public_key(first[168..200].try_into().expect("fixed spend key"))
            .expect("derived spend public key is valid");
        validate_public_key(first[200..232].try_into().expect("fixed view key"))
            .expect("derived view public key is valid");
    }

    #[test]
    fn address_codec_round_trips_and_rejects_malformed_inputs() {
        let keys = derive_test_keys(1, 7);
        let mut components = [0_u8; ADDRESS_COMPONENT_SIZE];
        components[..2].copy_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        components[2] = 1;
        components[3] = ADDRESS_FORMAT;
        components[6..38].copy_from_slice(&keys[168..200]);
        components[38..70].copy_from_slice(&keys[200..232]);

        let mut address = [0_u8; 128];
        let mut address_len = 0;
        // SAFETY: all pointers identify caller-owned request/output storage.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_address_encode(
                    components.as_ptr(),
                    components.len(),
                    address.as_mut_ptr(),
                    address.len(),
                    &raw mut address_len,
                )
            },
            ResultCode::Valid as i32
        );
        assert!(address_len > 90 && address_len < address.len());

        let mut decode_request = Vec::with_capacity(4 + address_len);
        decode_request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        decode_request.extend_from_slice(&[1, 0]);
        decode_request.extend_from_slice(&address[..address_len]);
        let mut decoded = [0_u8; ADDRESS_COMPONENT_SIZE];
        let mut decoded_len = 0;
        // SAFETY: all pointers identify caller-owned request/output storage.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_address_decode(
                    decode_request.as_ptr(),
                    decode_request.len(),
                    decoded.as_mut_ptr(),
                    decoded.len(),
                    &raw mut decoded_len,
                )
            },
            ResultCode::Valid as i32
        );
        assert_eq!(decoded_len, components.len());
        assert_eq!(decoded, components);

        let mut wrong_network = decode_request.clone();
        wrong_network[2] = 2;
        // SAFETY: all pointers identify caller-owned request/output storage.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_address_decode(
                    wrong_network.as_ptr(),
                    wrong_network.len(),
                    decoded.as_mut_ptr(),
                    decoded.len(),
                    &raw mut decoded_len,
                )
            },
            ResultCode::ConsensusInvalid as i32
        );

        let mut trailing = decode_request.clone();
        trailing.push(b'1');
        // SAFETY: all pointers identify caller-owned request/output storage.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_address_decode(
                    trailing.as_ptr(),
                    trailing.len(),
                    decoded.as_mut_ptr(),
                    decoded.len(),
                    &raw mut decoded_len,
                )
            },
            ResultCode::ConsensusInvalid as i32
        );

        let mut identity = components;
        identity[6..38].fill(0);
        identity[6] = 1;
        // SAFETY: all pointers identify caller-owned request/output storage.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_address_encode(
                    identity.as_ptr(),
                    identity.len(),
                    address.as_mut_ptr(),
                    address.len(),
                    &raw mut address_len,
                )
            },
            ResultCode::ConsensusInvalid as i32
        );

        let mut torsion = components;
        torsion[6..38].fill(0);
        // SAFETY: all pointers identify caller-owned request/output storage.
        assert_eq!(
            unsafe {
                innova_privacy_vnext_address_encode(
                    torsion.as_ptr(),
                    torsion.len(),
                    address.as_mut_ptr(),
                    address.len(),
                    &raw mut address_len,
                )
            },
            ResultCode::ConsensusInvalid as i32
        );
    }
}
