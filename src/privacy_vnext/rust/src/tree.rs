//! Canonical append frontier for the fixed eight-layer IV5 FCMP++ tree.

use ciphersuite::{
    group::{ff::Field, prime::PrimeGroup, GroupEncoding},
    Ciphersuite,
};
use dalek_ff_group::Ed25519;
use ec_divisors::DivisorCurve;
use generalized_bulletproofs::Generators;
use helioselene::{Helios, Selene};
use monero_fcmp_plus_plus::fcmps::{tree::hash_grow, Output, LAYER_ONE_LEN, LAYER_TWO_LEN};
use monero_fcmp_plus_plus_generators::{HELIOS_HASH_INIT, SELENE_HASH_INIT};
use monero_primitives::keccak256;
use std::sync::LazyLock;

use crate::ResultCode;

pub(crate) const STATE_SIZE: usize = 300;
pub(crate) const ROOT_SIZE: usize = 44;
const TREE_SCHEMA: u16 = 1;
const TREE_LAYERS: usize = 8;
const UPDATE_HEADER_SIZE: usize = 4;
const LEAF_COUNT_SIZE: usize = 4;
const LEAF_SIZE: usize = 96;
const MAX_UPDATE_LEAVES: usize = 16;
const LEVEL_SIZE: usize = 36;
const MAX_LEAVES: u64 = 38 * 18 * 38 * 18 * 38 * 18 * 38 * 18;

type SelenePoint = <Selene as Ciphersuite>::G;
type SeleneScalar = <Selene as Ciphersuite>::F;
type HeliosPoint = <Helios as Ciphersuite>::G;
type HeliosScalar = <Helios as Ciphersuite>::F;
type EdPoint = <Ed25519 as Ciphersuite>::G;

fn rejection_sampling_hash_to_curve<G>(input: &[u8]) -> G
where
    G: PrimeGroup + GroupEncoding<Repr = [u8; 32]>,
{
    let mut candidate = keccak256(input);
    loop {
        if let Some(point) = Option::<G>::from(G::from_bytes(&candidate)) {
            if point.to_bytes() == candidate && !bool::from(point.is_identity()) {
                return point;
            }
        }
        candidate = keccak256(candidate);
    }
}

fn tree_generators<C>(count: usize) -> Generators<C>
where
    C: Ciphersuite,
    C::G: PrimeGroup + GroupEncoding<Repr = [u8; 32]>,
{
    let id = String::from_utf8(C::ID.to_vec()).expect("curve identifier is UTF-8");
    let g = rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} G").as_bytes());
    let h = rejection_sampling_hash_to_curve::<C::G>(format!("Monero {id} H").as_bytes());
    let mut g_bold = Vec::with_capacity(count);
    let mut h_bold = Vec::with_capacity(count);
    for index in 0..count {
        g_bold.push(rejection_sampling_hash_to_curve::<C::G>(
            format!("Monero {id} G {index}").as_bytes(),
        ));
        h_bold.push(rejection_sampling_hash_to_curve::<C::G>(
            format!("Monero {id} H {index}").as_bytes(),
        ));
    }
    Generators::new(g, h, g_bold, h_bold).expect("tree generator set is canonical")
}

static SELENE_TREE_GENERATORS: LazyLock<Generators<Selene>> =
    LazyLock::new(|| tree_generators::<Selene>(256));
static HELIOS_TREE_GENERATORS: LazyLock<Generators<Helios>> =
    LazyLock::new(|| tree_generators::<Helios>(32));

#[derive(Clone, Copy)]
enum LevelHash {
    Selene(SelenePoint),
    Helios(HeliosPoint),
}

#[derive(Clone)]
struct TreeState {
    size: u64,
    counts: [u8; TREE_LAYERS],
    hashes: [LevelHash; TREE_LAYERS],
}

fn capacity(level: usize) -> usize {
    if level.is_multiple_of(2) {
        LAYER_ONE_LEN
    } else {
        LAYER_TWO_LEN
    }
}

fn empty_hash(level: usize) -> LevelHash {
    if level.is_multiple_of(2) {
        LevelHash::Selene(*SELENE_HASH_INIT)
    } else {
        LevelHash::Helios(*HELIOS_HASH_INIT)
    }
}

fn empty_state() -> TreeState {
    TreeState {
        size: 0,
        counts: [0; TREE_LAYERS],
        hashes: std::array::from_fn(empty_hash),
    }
}

fn point_bytes(hash: LevelHash) -> [u8; 32] {
    let mut result = [0_u8; 32];
    match hash {
        LevelHash::Selene(point) => result.copy_from_slice(point.to_bytes().as_ref()),
        LevelHash::Helios(point) => result.copy_from_slice(point.to_bytes().as_ref()),
    }
    result
}

fn parse_selene(bytes: &[u8]) -> Result<SelenePoint, ResultCode> {
    let mut reader = bytes;
    let point = Selene::read_G(&mut reader).map_err(|_| ResultCode::InternalLocalStateFailure)?;
    if !reader.is_empty() || point.to_bytes().as_ref() != bytes {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    Ok(point)
}

fn parse_helios(bytes: &[u8]) -> Result<HeliosPoint, ResultCode> {
    let mut reader = bytes;
    let point = Helios::read_G(&mut reader).map_err(|_| ResultCode::InternalLocalStateFailure)?;
    if !reader.is_empty() || point.to_bytes().as_ref() != bytes {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    Ok(point)
}

fn expected_counts(size: u64) -> [u8; TREE_LAYERS] {
    let mut counts = [0_u8; TREE_LAYERS];
    let mut remaining = size;
    for (level, count) in counts.iter_mut().enumerate() {
        let radix = u64::try_from(capacity(level)).expect("tree radix fits u64");
        if level == TREE_LAYERS - 1 {
            *count = u8::try_from(remaining).expect("bounded tree top count");
        } else {
            *count = u8::try_from(remaining % radix).expect("bounded tree digit");
            remaining /= radix;
        }
    }
    counts
}

fn parse_state(bytes: &[u8]) -> Result<TreeState, ResultCode> {
    if bytes.len() != STATE_SIZE {
        return Err(ResultCode::BadLength);
    }
    if u16::from_le_bytes([bytes[0], bytes[1]]) != TREE_SCHEMA
        || usize::from(bytes[2]) != TREE_LAYERS
        || bytes[3] != 0
    {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    let size = u64::from_le_bytes(
        bytes[4..12]
            .try_into()
            .map_err(|_| ResultCode::InternalLocalStateFailure)?,
    );
    if size > MAX_LEAVES {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let mut counts = [0_u8; TREE_LAYERS];
    let mut hashes = std::array::from_fn(empty_hash);
    for level in 0..TREE_LAYERS {
        let offset = 12 + (level * LEVEL_SIZE);
        counts[level] = bytes[offset];
        if bytes[offset + 1..offset + 4] != [0, 0, 0]
            || usize::from(counts[level]) > capacity(level)
        {
            return Err(ResultCode::InternalLocalStateFailure);
        }
        let encoded = &bytes[offset + 4..offset + LEVEL_SIZE];
        hashes[level] = if level.is_multiple_of(2) {
            LevelHash::Selene(parse_selene(encoded)?)
        } else {
            LevelHash::Helios(parse_helios(encoded)?)
        };
        if counts[level] == 0 && point_bytes(hashes[level]) != point_bytes(empty_hash(level)) {
            return Err(ResultCode::InternalLocalStateFailure);
        }
    }
    if counts != expected_counts(size) {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    Ok(TreeState {
        size,
        counts,
        hashes,
    })
}

fn serialize_state(state: &TreeState) -> [u8; STATE_SIZE] {
    let mut result = [0_u8; STATE_SIZE];
    result[..2].copy_from_slice(&TREE_SCHEMA.to_le_bytes());
    result[2] = u8::try_from(TREE_LAYERS).expect("tree layer count fits u8");
    result[4..12].copy_from_slice(&state.size.to_le_bytes());
    for level in 0..TREE_LAYERS {
        let offset = 12 + (level * LEVEL_SIZE);
        result[offset] = state.counts[level];
        result[offset + 4..offset + LEVEL_SIZE].copy_from_slice(&point_bytes(state.hashes[level]));
    }
    result
}

fn read_ed_point(bytes: &[u8]) -> Result<EdPoint, ResultCode> {
    let mut reader = bytes;
    let point = Ed25519::read_G(&mut reader).map_err(|_| ResultCode::ConsensusInvalid)?;
    if !reader.is_empty() || point.to_bytes().as_ref() != bytes {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(point)
}

fn leaf_scalars(bytes: &[u8]) -> Result<[SeleneScalar; 6], ResultCode> {
    if bytes.len() != LEAF_SIZE {
        return Err(ResultCode::BadLength);
    }
    let output = Output::new(
        read_ed_point(&bytes[..32])?,
        read_ed_point(&bytes[32..64])?,
        read_ed_point(&bytes[64..96])?,
    )
    .map_err(|_| ResultCode::ConsensusInvalid)?;
    let o = EdPoint::to_xy(output.O()).ok_or(ResultCode::ConsensusInvalid)?;
    let i = EdPoint::to_xy(output.I()).ok_or(ResultCode::ConsensusInvalid)?;
    let c = EdPoint::to_xy(output.C()).ok_or(ResultCode::ConsensusInvalid)?;
    Ok([o.0, o.1, i.0, i.1, c.0, c.1])
}

fn grow_parent(
    level: usize,
    existing: LevelHash,
    offset: usize,
    child: LevelHash,
) -> Result<LevelHash, ResultCode> {
    if level >= TREE_LAYERS || offset >= capacity(level) {
        return Err(ResultCode::ResourceLimit);
    }
    match (existing, child) {
        (LevelHash::Helios(existing), LevelHash::Selene(child)) => {
            let x = SelenePoint::to_xy(child)
                .ok_or(ResultCode::InternalLocalStateFailure)?
                .0;
            Ok(LevelHash::Helios(
                hash_grow::<Helios>(
                    &HELIOS_TREE_GENERATORS,
                    existing,
                    offset,
                    HeliosScalar::ZERO,
                    &[x],
                )
                .ok_or(ResultCode::InternalLocalStateFailure)?,
            ))
        }
        (LevelHash::Selene(existing), LevelHash::Helios(child)) => {
            let x = HeliosPoint::to_xy(child)
                .ok_or(ResultCode::InternalLocalStateFailure)?
                .0;
            Ok(LevelHash::Selene(
                hash_grow::<Selene>(
                    &SELENE_TREE_GENERATORS,
                    existing,
                    offset,
                    SeleneScalar::ZERO,
                    &[x],
                )
                .ok_or(ResultCode::InternalLocalStateFailure)?,
            ))
        }
        _ => Err(ResultCode::InternalLocalStateFailure),
    }
}

fn append_parent(state: &mut TreeState, level: usize, child: LevelHash) -> Result<(), ResultCode> {
    if level >= TREE_LAYERS {
        return Err(ResultCode::ResourceLimit);
    }
    let offset = usize::from(state.counts[level]);
    state.hashes[level] = grow_parent(level, state.hashes[level], offset, child)?;
    state.counts[level] = state.counts[level]
        .checked_add(1)
        .ok_or(ResultCode::InternalLocalStateFailure)?;
    if usize::from(state.counts[level]) == capacity(level) && level + 1 < TREE_LAYERS {
        let completed = state.hashes[level];
        state.counts[level] = 0;
        state.hashes[level] = empty_hash(level);
        append_parent(state, level + 1, completed)?;
    }
    Ok(())
}

fn append_leaf(state: &mut TreeState, bytes: &[u8]) -> Result<(), ResultCode> {
    if state.size == MAX_LEAVES {
        return Err(ResultCode::ResourceLimit);
    }
    let scalars = leaf_scalars(bytes)?;
    let offset = usize::from(state.counts[0]) * 6;
    let existing = match state.hashes[0] {
        LevelHash::Selene(point) => point,
        LevelHash::Helios(_) => return Err(ResultCode::InternalLocalStateFailure),
    };
    state.hashes[0] = LevelHash::Selene(
        hash_grow::<Selene>(
            &SELENE_TREE_GENERATORS,
            existing,
            offset,
            SeleneScalar::ZERO,
            &scalars,
        )
        .ok_or(ResultCode::InternalLocalStateFailure)?,
    );
    state.counts[0] = state.counts[0]
        .checked_add(1)
        .ok_or(ResultCode::InternalLocalStateFailure)?;
    state.size = state.size.checked_add(1).ok_or(ResultCode::ResourceLimit)?;
    if usize::from(state.counts[0]) == capacity(0) {
        let completed = state.hashes[0];
        state.counts[0] = 0;
        state.hashes[0] = empty_hash(0);
        append_parent(state, 1, completed)?;
    }
    Ok(())
}

fn fold_root(state: &TreeState) -> Result<HeliosPoint, ResultCode> {
    let mut current = None;
    for level in 0..TREE_LAYERS {
        current = match (current, state.counts[level] != 0) {
            (None, false) => None,
            (None, true) => Some(state.hashes[level]),
            (Some(child), has_existing) => {
                let existing = if has_existing {
                    state.hashes[level]
                } else {
                    empty_hash(level)
                };
                let offset = if has_existing {
                    usize::from(state.counts[level])
                } else {
                    0
                };
                Some(grow_parent(level, existing, offset, child)?)
            }
        };
    }
    match current.unwrap_or_else(|| empty_hash(TREE_LAYERS - 1)) {
        LevelHash::Helios(root) => Ok(root),
        LevelHash::Selene(_) => Err(ResultCode::InternalLocalStateFailure),
    }
}

pub(crate) fn update(request: &[u8]) -> Result<[u8; STATE_SIZE], ResultCode> {
    if request.len() < UPDATE_HEADER_SIZE + LEAF_COUNT_SIZE {
        return Err(ResultCode::BadLength);
    }
    if u16::from_le_bytes([request[0], request[1]]) != TREE_SCHEMA || request[3] != 0 {
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
    if request.len() < state_end + LEAF_COUNT_SIZE {
        return Err(ResultCode::BadLength);
    }
    let mut state = if initialize {
        empty_state()
    } else {
        parse_state(&request[UPDATE_HEADER_SIZE..state_end])?
    };
    let leaf_count = usize::try_from(u32::from_le_bytes(
        request[state_end..state_end + LEAF_COUNT_SIZE]
            .try_into()
            .map_err(|_| ResultCode::BadLength)?,
    ))
    .map_err(|_| ResultCode::ResourceLimit)?;
    if leaf_count > MAX_UPDATE_LEAVES {
        return Err(ResultCode::ResourceLimit);
    }
    let leaves_start = state_end + LEAF_COUNT_SIZE;
    let leaves_size = leaf_count
        .checked_mul(LEAF_SIZE)
        .ok_or(ResultCode::ResourceLimit)?;
    if request.len() != leaves_start + leaves_size {
        return Err(ResultCode::BadLength);
    }
    for leaf in request[leaves_start..].chunks_exact(LEAF_SIZE) {
        append_leaf(&mut state, leaf)?;
    }
    if state.counts != expected_counts(state.size) {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    Ok(serialize_state(&state))
}

pub(crate) fn root(request: &[u8]) -> Result<[u8; ROOT_SIZE], ResultCode> {
    let state = parse_state(request)?;
    let point = fold_root(&state)?;
    let mut result = [0_u8; ROOT_SIZE];
    result[..2].copy_from_slice(&TREE_SCHEMA.to_le_bytes());
    result[2] = u8::try_from(TREE_LAYERS).expect("tree layer count fits u8");
    result[3] = 2;
    result[4..12].copy_from_slice(&state.size.to_le_bytes());
    result[12..44].copy_from_slice(point.to_bytes().as_ref());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(index: u64) -> [u8; LEAF_SIZE] {
        let mut result = [0_u8; LEAF_SIZE];
        for point_index in 0..3_u64 {
            let scalar = <Ed25519 as Ciphersuite>::F::from((index * 3) + point_index + 1);
            let point = <Ed25519 as Ciphersuite>::generator() * scalar;
            let start = usize::try_from(point_index * 32).expect("test offset is bounded");
            result[start..start + 32].copy_from_slice(point.to_bytes().as_ref());
        }
        result
    }

    fn initialize(leaves: &[[u8; LEAF_SIZE]]) -> [u8; STATE_SIZE] {
        let mut request = vec![1, 0, 1, 0];
        request.extend_from_slice(
            &u32::try_from(leaves.len())
                .expect("test leaf count is bounded")
                .to_le_bytes(),
        );
        for leaf in leaves {
            request.extend_from_slice(leaf);
        }
        update(&request).expect("valid tree initialization")
    }

    #[test]
    fn empty_and_nonempty_roots_are_fixed_depth_and_distinct() {
        let empty = initialize(&[]);
        let empty_root = root(&empty).expect("empty root");
        assert_eq!(empty_root[2], 8);
        assert_eq!(empty_root[3], 2);
        assert_eq!(&empty_root[4..12], &0_u64.to_le_bytes());

        let one = initialize(&[leaf(0)]);
        let one_root = root(&one).expect("one-leaf root");
        assert_ne!(empty_root, one_root);
        assert_eq!(&one_root[4..12], &1_u64.to_le_bytes());
    }

    #[test]
    fn serial_and_batch_updates_have_identical_state_and_root() {
        let leaves: Vec<_> = (0..16).map(leaf).collect();
        let batch = initialize(&leaves);
        let mut serial = initialize(&[]);
        for next in leaves {
            let mut request = vec![1, 0, 0, 0];
            request.extend_from_slice(&serial);
            request.extend_from_slice(&1_u32.to_le_bytes());
            request.extend_from_slice(&next);
            serial = update(&request).expect("valid serial append");
        }
        assert_eq!(serial, batch);
        assert_eq!(root(&serial), root(&batch));
    }

    #[test]
    fn malformed_state_and_leaf_points_fail_closed() {
        let mut state = initialize(&[leaf(0)]);
        state[12] = 2;
        assert_eq!(root(&state), Err(ResultCode::InternalLocalStateFailure));

        let mut bad_leaf = leaf(1);
        bad_leaf[..32].fill(0);
        let mut request = vec![1, 0, 1, 0];
        request.extend_from_slice(&1_u32.to_le_bytes());
        request.extend_from_slice(&bad_leaf);
        assert_eq!(update(&request), Err(ResultCode::ConsensusInvalid));
    }

    #[test]
    #[ignore = "loads the full upstream proof generator set for differential assurance"]
    fn tree_generator_prefixes_equal_the_pinned_full_set() {
        assert_eq!(
            &SELENE_TREE_GENERATORS.g_bold_slice()[..6 * LAYER_ONE_LEN],
            &monero_fcmp_plus_plus::SELENE_FCMP_GENERATORS
                .generators
                .g_bold_slice()[..6 * LAYER_ONE_LEN]
        );
        assert_eq!(
            &HELIOS_TREE_GENERATORS.g_bold_slice()[..LAYER_TWO_LEN],
            &monero_fcmp_plus_plus::HELIOS_FCMP_GENERATORS
                .generators
                .g_bold_slice()[..LAYER_TWO_LEN]
        );
    }
}
