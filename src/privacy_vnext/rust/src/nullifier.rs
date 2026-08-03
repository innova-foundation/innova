//! Canonical bounded rolling accumulator for spent IV5 key images.

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    traits::Identity,
};
use std::collections::BTreeSet;

use crate::ResultCode;

pub(crate) const STATE_SIZE: usize = 44;
pub(crate) const ROOT_SIZE: usize = 44;
const SCHEMA: u16 = 1;
const ACCUMULATOR_VERSION: u8 = 1;
const UPDATE_HEADER_SIZE: usize = 4;
const COUNT_SIZE: usize = 4;
const KEY_IMAGE_SIZE: usize = 32;
const MAX_UPDATE_KEY_IMAGES: usize = 16;
const EMPTY_DOMAIN: &[u8] = b"Innova/IV5/NullifierAccumulator/Empty/v1";
const STEP_DOMAIN: &[u8] = b"Innova/IV5/NullifierAccumulator/Step/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct State {
    count: u64,
    root: [u8; 32],
}

fn hash256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut result = [0_u8; 32];
    result.copy_from_slice(&digest[..32]);
    result
}

fn empty_state() -> State {
    State {
        count: 0,
        root: hash256(&[EMPTY_DOMAIN]),
    }
}

fn parse_state(bytes: &[u8]) -> Result<State, ResultCode> {
    if bytes.len() != STATE_SIZE {
        return Err(ResultCode::BadLength);
    }
    if u16::from_le_bytes([bytes[0], bytes[1]]) != SCHEMA
        || bytes[2] != ACCUMULATOR_VERSION
        || bytes[3] != 0
    {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    let count = u64::from_le_bytes(
        bytes[4..12]
            .try_into()
            .map_err(|_| ResultCode::InternalLocalStateFailure)?,
    );
    let root = bytes[12..44]
        .try_into()
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
    if count == 0 && root != empty_state().root {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    Ok(State { count, root })
}

fn serialize_state(state: &State) -> [u8; STATE_SIZE] {
    let mut result = [0_u8; STATE_SIZE];
    result[..2].copy_from_slice(&SCHEMA.to_le_bytes());
    result[2] = ACCUMULATOR_VERSION;
    result[4..12].copy_from_slice(&state.count.to_le_bytes());
    result[12..44].copy_from_slice(&state.root);
    result
}

fn parse_key_image(bytes: &[u8]) -> Result<[u8; KEY_IMAGE_SIZE], ResultCode> {
    let encoded: [u8; KEY_IMAGE_SIZE] = bytes.try_into().map_err(|_| ResultCode::BadLength)?;
    let point = CompressedEdwardsY(encoded)
        .decompress()
        .ok_or(ResultCode::ConsensusInvalid)?;
    if point.compress().to_bytes() != encoded
        || !point.is_torsion_free()
        || point == EdwardsPoint::identity()
    {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(encoded)
}

pub(crate) fn update(request: &[u8]) -> Result<[u8; STATE_SIZE], ResultCode> {
    if request.len() < UPDATE_HEADER_SIZE + COUNT_SIZE {
        return Err(ResultCode::BadLength);
    }
    if u16::from_le_bytes([request[0], request[1]]) != SCHEMA || request[3] != 0 {
        return Err(ResultCode::UnsupportedFormat);
    }
    let initialize = match request[2] {
        0 => false,
        1 => true,
        _ => return Err(ResultCode::UnsupportedFormat),
    };
    let state_end = if initialize {
        UPDATE_HEADER_SIZE
    } else {
        UPDATE_HEADER_SIZE + STATE_SIZE
    };
    if request.len() < state_end + COUNT_SIZE {
        return Err(ResultCode::BadLength);
    }
    let mut state = if initialize {
        empty_state()
    } else {
        parse_state(&request[UPDATE_HEADER_SIZE..state_end])?
    };
    let key_image_count = usize::try_from(u32::from_le_bytes(
        request[state_end..state_end + COUNT_SIZE]
            .try_into()
            .map_err(|_| ResultCode::BadLength)?,
    ))
    .map_err(|_| ResultCode::ResourceLimit)?;
    if key_image_count > MAX_UPDATE_KEY_IMAGES {
        return Err(ResultCode::ResourceLimit);
    }
    let key_images_start = state_end + COUNT_SIZE;
    let key_images_size = key_image_count
        .checked_mul(KEY_IMAGE_SIZE)
        .ok_or(ResultCode::ResourceLimit)?;
    if request.len() != key_images_start + key_images_size {
        return Err(ResultCode::BadLength);
    }

    let mut request_key_images = BTreeSet::new();
    for encoded in request[key_images_start..].chunks_exact(KEY_IMAGE_SIZE) {
        let key_image = parse_key_image(encoded)?;
        if !request_key_images.insert(key_image) {
            return Err(ResultCode::ConsensusInvalid);
        }
        let count = state.count.to_le_bytes();
        state.root = hash256(&[STEP_DOMAIN, &state.root, &count, &key_image]);
        state.count = state
            .count
            .checked_add(1)
            .ok_or(ResultCode::ResourceLimit)?;
    }
    Ok(serialize_state(&state))
}

pub(crate) fn root(request: &[u8]) -> Result<[u8; ROOT_SIZE], ResultCode> {
    Ok(serialize_state(&parse_state(request)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};

    fn key_image(index: u64) -> [u8; 32] {
        (ED25519_BASEPOINT_POINT * Scalar::from(index + 1))
            .compress()
            .to_bytes()
    }

    fn initialize(key_images: &[[u8; 32]]) -> [u8; STATE_SIZE] {
        let mut request = vec![1, 0, 1, 0];
        request.extend_from_slice(
            &u32::try_from(key_images.len())
                .expect("test key-image count is bounded")
                .to_le_bytes(),
        );
        for key_image in key_images {
            request.extend_from_slice(key_image);
        }
        update(&request).expect("valid nullifier initialization")
    }

    #[test]
    fn empty_serial_and_batch_states_are_canonical() {
        let empty = initialize(&[]);
        assert_eq!(root(&empty), Ok(empty));
        assert_eq!(&empty[4..12], &0_u64.to_le_bytes());

        let key_images: Vec<_> = (0..16).map(key_image).collect();
        let batch = initialize(&key_images);
        let mut serial = empty;
        for key_image in key_images {
            let mut request = vec![1, 0, 0, 0];
            request.extend_from_slice(&serial);
            request.extend_from_slice(&1_u32.to_le_bytes());
            request.extend_from_slice(&key_image);
            serial = update(&request).expect("valid serial nullifier append");
        }
        assert_eq!(serial, batch);
        assert_eq!(&serial[4..12], &16_u64.to_le_bytes());
    }

    #[test]
    fn cross_language_key_image_vectors_are_canonical_and_frozen() {
        let mut basepoint_vector = [0x66_u8; 32];
        basepoint_vector[0] = 0x58;
        let mut negative_basepoint_vector = basepoint_vector;
        negative_basepoint_vector[31] = 0xe6;

        assert_eq!(key_image(0), basepoint_vector);
        assert_eq!(
            (-ED25519_BASEPOINT_POINT).compress().to_bytes(),
            negative_basepoint_vector
        );
        let state = initialize(&[basepoint_vector, negative_basepoint_vector]);
        assert_eq!(&state[4..12], &2_u64.to_le_bytes());
        assert_eq!(root(&state), Ok(state));
    }

    #[test]
    fn malformed_state_and_duplicate_key_images_fail_closed() {
        let mut malformed = initialize(&[]);
        malformed[12] ^= 1;
        assert_eq!(root(&malformed), Err(ResultCode::InternalLocalStateFailure));

        let duplicate = key_image(0);
        let mut request = vec![1, 0, 1, 0];
        request.extend_from_slice(&2_u32.to_le_bytes());
        request.extend_from_slice(&duplicate);
        request.extend_from_slice(&duplicate);
        assert_eq!(update(&request), Err(ResultCode::ConsensusInvalid));
    }
}
