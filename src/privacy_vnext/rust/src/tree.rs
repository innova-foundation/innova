//! Canonical append frontier for the fixed eight-layer IV5 FCMP++ tree.

use ciphersuite::{
    group::{
        ff::{Field, PrimeField},
        prime::PrimeGroup,
        GroupEncoding,
    },
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

const WITNESS_HEADER_SIZE: usize = 4;
const WITNESS_TARGET_SIZE: usize = 8;
const MAX_WITNESS_TARGETS: usize = 16;
const SCALAR_SIZE: usize = 32;

/// One node hash per level, every node retained. The append frontier cannot name a
/// leaf's siblings, so witnesses rebuild whole levels from the caller's leaves.
type TreeLevels = [Vec<LevelHash>; TREE_LAYERS];

fn level_scalar_bytes(level: usize, child: LevelHash) -> Result<[u8; SCALAR_SIZE], ResultCode> {
    let mut result = [0_u8; SCALAR_SIZE];
    match (level.is_multiple_of(2), child) {
        (false, LevelHash::Selene(point)) => {
            let x = SelenePoint::to_xy(point)
                .ok_or(ResultCode::InternalLocalStateFailure)?
                .0;
            result.copy_from_slice(x.to_repr().as_ref());
        }
        (true, LevelHash::Helios(point)) => {
            let x = HeliosPoint::to_xy(point)
                .ok_or(ResultCode::InternalLocalStateFailure)?
                .0;
            result.copy_from_slice(x.to_repr().as_ref());
        }
        _ => return Err(ResultCode::InternalLocalStateFailure),
    }
    Ok(result)
}

/// Hash one internal branch from its children. Mirrors `grow_parent`: each child adds
/// only its x-coordinate at its own generator index.
fn hash_branch(level: usize, children: &[LevelHash]) -> Result<LevelHash, ResultCode> {
    if children.is_empty() || children.len() > capacity(level) {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    if level.is_multiple_of(2) {
        let mut scalars = Vec::with_capacity(children.len());
        for child in children {
            match child {
                LevelHash::Helios(point) => scalars.push(
                    HeliosPoint::to_xy(*point)
                        .ok_or(ResultCode::InternalLocalStateFailure)?
                        .0,
                ),
                LevelHash::Selene(_) => return Err(ResultCode::InternalLocalStateFailure),
            }
        }
        Ok(LevelHash::Selene(
            hash_grow::<Selene>(
                &SELENE_TREE_GENERATORS,
                *SELENE_HASH_INIT,
                0,
                SeleneScalar::ZERO,
                &scalars,
            )
            .ok_or(ResultCode::InternalLocalStateFailure)?,
        ))
    } else {
        let mut scalars = Vec::with_capacity(children.len());
        for child in children {
            match child {
                LevelHash::Selene(point) => scalars.push(
                    SelenePoint::to_xy(*point)
                        .ok_or(ResultCode::InternalLocalStateFailure)?
                        .0,
                ),
                LevelHash::Helios(_) => return Err(ResultCode::InternalLocalStateFailure),
            }
        }
        Ok(LevelHash::Helios(
            hash_grow::<Helios>(
                &HELIOS_TREE_GENERATORS,
                *HELIOS_HASH_INIT,
                0,
                HeliosScalar::ZERO,
                &scalars,
            )
            .ok_or(ResultCode::InternalLocalStateFailure)?,
        ))
    }
}

/// Rebuild every level from the full ordered leaf set, always to depth `TREE_LAYERS`
/// to match `fold_root`.
fn rebuild_levels(leaves: &[u8]) -> Result<TreeLevels, ResultCode> {
    let leaf_branch = capacity(0);
    let mut levels: TreeLevels = std::array::from_fn(|_| Vec::new());

    for chunk in leaves.chunks(LEAF_SIZE * leaf_branch) {
        let mut scalars = Vec::with_capacity(6 * leaf_branch);
        for leaf in chunk.chunks_exact(LEAF_SIZE) {
            scalars.extend_from_slice(&leaf_scalars(leaf)?);
        }
        levels[0].push(LevelHash::Selene(
            hash_grow::<Selene>(
                &SELENE_TREE_GENERATORS,
                *SELENE_HASH_INIT,
                0,
                SeleneScalar::ZERO,
                &scalars,
            )
            .ok_or(ResultCode::InternalLocalStateFailure)?,
        ));
    }
    if levels[0].is_empty() {
        return Err(ResultCode::BadLength);
    }

    for level in 1..TREE_LAYERS {
        let cap = capacity(level);
        let mut nodes = Vec::with_capacity(levels[level - 1].len().div_ceil(cap));
        for chunk in levels[level - 1].chunks(cap) {
            nodes.push(hash_branch(level, chunk)?);
        }
        levels[level] = nodes;
    }
    if levels[TREE_LAYERS - 1].len() != 1 {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    Ok(levels)
}

/// Append a branch as fixed-width scalars, zero-padded to the layer length. A real child
/// keeps its own index: the generator index is the position.
fn append_branch(
    level: usize,
    children: &[LevelHash],
    out: &mut Vec<u8>,
) -> Result<(), ResultCode> {
    let cap = capacity(level);
    if children.is_empty() || children.len() > cap {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    for child in children {
        out.extend_from_slice(&level_scalar_bytes(level, *child)?);
    }
    let padding = if level.is_multiple_of(2) {
        SeleneScalar::ZERO.to_repr().as_ref().to_vec()
    } else {
        HeliosScalar::ZERO.to_repr().as_ref().to_vec()
    };
    if padding.len() != SCALAR_SIZE {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    for _ in children.len()..cap {
        out.extend_from_slice(&padding);
    }
    Ok(())
}

/// Emit one per-input membership witness in the prover's field order; it splices into a
/// proving request verbatim after the caller's secret x and y.
fn append_witness_record(
    levels: &TreeLevels,
    leaves: &[u8],
    target: u64,
    out: &mut Vec<u8>,
) -> Result<(), ResultCode> {
    let leaf_branch = capacity(0);
    let index = usize::try_from(target).map_err(|_| ResultCode::ResourceLimit)?;
    let leaf_count = leaves.len() / LEAF_SIZE;
    if index >= leaf_count {
        return Err(ResultCode::ConsensusInvalid);
    }

    let mut node = index / leaf_branch;
    let branch_start = node * leaf_branch;
    let branch_len = leaf_branch.min(leaf_count - branch_start);

    out.extend_from_slice(&leaves[index * LEAF_SIZE..(index + 1) * LEAF_SIZE]);
    out.push(u8::try_from(branch_len).map_err(|_| ResultCode::InternalLocalStateFailure)?);
    out.extend_from_slice(&[0_u8; 3]);
    out.extend_from_slice(
        &leaves[branch_start * LEAF_SIZE..(branch_start + branch_len) * LEAF_SIZE],
    );

    // Branch at level L holds the level L-1 nodes under the path's parent. Helios levels
    // (odd) are emitted before Selene levels (even), each bottom-up, as the prover reads
    // curve_2_layers ahead of curve_1_layers.
    let mut parents = [0_usize; TREE_LAYERS];
    for (level, parent) in parents.iter_mut().enumerate().skip(1) {
        node /= capacity(level);
        *parent = node;
    }
    for level in (1..TREE_LAYERS).step_by(2) {
        let cap = capacity(level);
        let children = &levels[level - 1];
        let start = parents[level] * cap;
        let end = children.len().min(start + cap);
        if start >= end {
            return Err(ResultCode::InternalLocalStateFailure);
        }
        append_branch(level, &children[start..end], out)?;
    }
    for level in (2..TREE_LAYERS).step_by(2) {
        let cap = capacity(level);
        let children = &levels[level - 1];
        let start = parents[level] * cap;
        let end = children.len().min(start + cap);
        if start >= end {
            return Err(ResultCode::InternalLocalStateFailure);
        }
        append_branch(level, &children[start..end], out)?;
    }
    Ok(())
}

pub(crate) fn witness(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    if request.len() < WITNESS_HEADER_SIZE + STATE_SIZE + LEAF_COUNT_SIZE {
        return Err(ResultCode::BadLength);
    }
    if u16::from_le_bytes([request[0], request[1]]) != TREE_SCHEMA {
        return Err(ResultCode::UnsupportedFormat);
    }
    if request[3] != 0 {
        return Err(ResultCode::ConsensusInvalid);
    }
    let target_count = usize::from(request[2]);
    if target_count == 0 {
        return Err(ResultCode::BadLength);
    }
    if target_count > MAX_WITNESS_TARGETS {
        return Err(ResultCode::ResourceLimit);
    }

    let state_end = WITNESS_HEADER_SIZE + STATE_SIZE;
    let state = parse_state(&request[WITNESS_HEADER_SIZE..state_end])?;
    let targets_end = state_end
        .checked_add(
            target_count
                .checked_mul(WITNESS_TARGET_SIZE)
                .ok_or(ResultCode::ResourceLimit)?,
        )
        .ok_or(ResultCode::ResourceLimit)?;
    if request.len() < targets_end + LEAF_COUNT_SIZE {
        return Err(ResultCode::BadLength);
    }

    let mut targets = Vec::with_capacity(target_count);
    for index in 0..target_count {
        let offset = state_end + (index * WITNESS_TARGET_SIZE);
        let value = u64::from_le_bytes(
            request[offset..offset + WITNESS_TARGET_SIZE]
                .try_into()
                .map_err(|_| ResultCode::BadLength)?,
        );
        if value >= state.size {
            return Err(ResultCode::ConsensusInvalid);
        }
        if targets.contains(&value) {
            return Err(ResultCode::ConsensusInvalid);
        }
        targets.push(value);
    }

    let leaf_count = usize::try_from(u32::from_le_bytes(
        request[targets_end..targets_end + LEAF_COUNT_SIZE]
            .try_into()
            .map_err(|_| ResultCode::BadLength)?,
    ))
    .map_err(|_| ResultCode::ResourceLimit)?;
    if leaf_count == 0 {
        return Err(ResultCode::BadLength);
    }
    if u64::try_from(leaf_count).map_err(|_| ResultCode::ResourceLimit)? != state.size {
        return Err(ResultCode::ConsensusInvalid);
    }
    let leaves_start = targets_end + LEAF_COUNT_SIZE;
    let leaves_size = leaf_count
        .checked_mul(LEAF_SIZE)
        .ok_or(ResultCode::ResourceLimit)?;
    if request.len()
        != leaves_start
            .checked_add(leaves_size)
            .ok_or(ResultCode::ResourceLimit)?
    {
        return Err(ResultCode::BadLength);
    }
    let leaves = &request[leaves_start..];

    // The supplied leaves must be the ones that produced the supplied frontier. Replaying
    // the append path and comparing the whole serialized state checks every level hash and
    // count, not just the root.
    let mut replayed = empty_state();
    for leaf in leaves.chunks_exact(LEAF_SIZE) {
        append_leaf(&mut replayed, leaf)?;
    }
    if serialize_state(&replayed) != request[WITNESS_HEADER_SIZE..state_end] {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let levels = rebuild_levels(leaves)?;
    let root = match levels[TREE_LAYERS - 1][0] {
        LevelHash::Helios(point) => point,
        LevelHash::Selene(_) => return Err(ResultCode::InternalLocalStateFailure),
    };
    if root != fold_root(&replayed)? {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let mut result = Vec::new();
    result.extend_from_slice(&TREE_SCHEMA.to_le_bytes());
    result.push(u8::try_from(TREE_LAYERS).expect("tree layer count fits u8"));
    result.push(2);
    result.extend_from_slice(&state.size.to_le_bytes());
    result.extend_from_slice(root.to_bytes().as_ref());
    result.push(u8::try_from(target_count).expect("target count is bounded by 16"));
    result.extend_from_slice(&[0_u8; 3]);
    for target in targets {
        append_witness_record(&levels, leaves, target, &mut result)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {

    fn grow(leaves: &[[u8; LEAF_SIZE]]) -> [u8; STATE_SIZE] {
        let mut state: Option<[u8; STATE_SIZE]> = None;
        for batch in leaves.chunks(MAX_UPDATE_LEAVES) {
            let mut request = match state {
                None => vec![1, 0, 1, 0],
                Some(previous) => {
                    let mut header = vec![1, 0, 0, 0];
                    header.extend_from_slice(&previous);
                    header
                }
            };
            request.extend_from_slice(
                &u32::try_from(batch.len())
                    .expect("test leaf count is bounded")
                    .to_le_bytes(),
            );
            for leaf in batch {
                request.extend_from_slice(leaf);
            }
            state = Some(update(&request).expect("valid tree growth"));
        }
        state.unwrap_or_else(|| initialize(&[]))
    }

    fn witness_call(
        state: &[u8; STATE_SIZE],
        targets: &[u64],
        leaves: &[[u8; LEAF_SIZE]],
    ) -> Result<Vec<u8>, ResultCode> {
        let mut request = Vec::new();
        request.extend_from_slice(&TREE_SCHEMA.to_le_bytes());
        request.push(u8::try_from(targets.len()).expect("target count is bounded"));
        request.push(0);
        request.extend_from_slice(state);
        for target in targets {
            request.extend_from_slice(&target.to_le_bytes());
        }
        request.extend_from_slice(
            &u32::try_from(leaves.len())
                .expect("test leaf count is bounded")
                .to_le_bytes(),
        );
        for leaf in leaves {
            request.extend_from_slice(leaf);
        }
        witness(&request)
    }

    fn leaves(count: u64) -> Vec<[u8; LEAF_SIZE]> {
        (0..count).map(leaf).collect()
    }

    // A witness is computed from a full rebuild while the chain tracks only the frontier.
    // If the two ever disagree the witness opens a root no one else holds, so every shape
    // that changes the branch geometry is pinned here.
    #[test]
    fn rebuilt_root_matches_the_incremental_frontier() {
        for count in [1_u64, 2, 37, 38, 39, 76, 683, 684, 685] {
            let all = leaves(count);
            let state = grow(&all);
            let expected = root(&state).expect("frontier root");
            let response = witness_call(&state, &[0], &all).expect("witness must be produced");
            assert_eq!(
                &response[..ROOT_SIZE],
                &expected[..],
                "rebuild diverged from the frontier at {count} leaves"
            );
        }
    }

    // Level 2 gains a second node only at 25,993 leaves, so shallower sizes cannot
    // distinguish a rebuild that diverges from the frontier above level 1.
    #[test]
    #[ignore = "builds a 25,993-leaf tree to reach the level-2 branch boundary"]
    fn rebuilt_root_matches_the_frontier_at_the_level_two_boundary() {
        for count in [25_992_u64, 25_993] {
            let all = leaves(count);
            let state = grow(&all);
            let expected = root(&state).expect("frontier root");
            let response = witness_call(&state, &[0, count - 1], &all).expect("witness");
            assert_eq!(
                &response[..ROOT_SIZE],
                &expected[..],
                "rebuild diverged from the frontier at {count} leaves"
            );
        }
    }

    #[test]
    fn witness_covers_every_leaf_position_in_a_partial_branch() {
        let all = leaves(39);
        let state = grow(&all);
        for target in [0_u64, 1, 37, 38] {
            let response = witness_call(&state, &[target], &all).expect("witness");
            let record = &response[ROOT_SIZE + 4..];
            // The target's own leaf leads the record and must reappear inside its branch.
            let index = usize::try_from(target).expect("index is bounded");
            assert_eq!(&record[..LEAF_SIZE], &all[index][..]);
            let branch_len = usize::from(record[LEAF_SIZE]);
            assert_eq!(branch_len, if target < 38 { 38 } else { 1 });
            // Every leaf must sit at its own position: the generator index is the
            // position, so a rotated branch hashes to a different node.
            let branch = &record[LEAF_SIZE + 4..LEAF_SIZE + 4 + (branch_len * LEAF_SIZE)];
            let branch_start = (index / capacity(0)) * capacity(0);
            for (offset, candidate) in branch.chunks_exact(LEAF_SIZE).enumerate() {
                assert_eq!(candidate, &all[branch_start + offset][..]);
            }
            assert_eq!(
                &branch[(index - branch_start) * LEAF_SIZE..][..LEAF_SIZE],
                &all[index][..]
            );
        }
    }

    #[test]
    fn witness_record_is_fixed_width_per_branch() {
        let all = leaves(40);
        let state = grow(&all);
        let response = witness_call(&state, &[0, 39], &all).expect("witness");
        assert_eq!(response[ROOT_SIZE], 2);
        let branches = (4 * 18 * SCALAR_SIZE) + (3 * 38 * SCALAR_SIZE);
        let first = 100 + (38 * LEAF_SIZE) + branches;
        let second = 100 + (2 * LEAF_SIZE) + branches;
        assert_eq!(response.len(), ROOT_SIZE + 4 + first + second);
    }

    #[test]
    fn witness_rejects_malformed_requests() {
        let all = leaves(5);
        let state = grow(&all);

        assert_eq!(
            witness_call(&state, &[5], &all),
            Err(ResultCode::ConsensusInvalid)
        );
        assert_eq!(
            witness_call(&state, &[9], &all),
            Err(ResultCode::ConsensusInvalid)
        );
        assert_eq!(
            witness_call(&state, &[1, 1], &all),
            Err(ResultCode::ConsensusInvalid)
        );
        assert_eq!(witness_call(&state, &[], &all), Err(ResultCode::BadLength));
        assert_eq!(witness(&[]), Err(ResultCode::BadLength));
        assert_eq!(witness(&[1, 0, 1, 0]), Err(ResultCode::BadLength));

        // A leaf set that does not reproduce the supplied frontier must not yield a witness.
        let mut wrong = all.clone();
        wrong[4] = leaf(99);
        assert_eq!(
            witness_call(&state, &[0], &wrong),
            Err(ResultCode::InternalLocalStateFailure)
        );

        // The declared leaf count must equal the tree size the frontier claims.
        assert_eq!(
            witness_call(&state, &[0], &all[..4]),
            Err(ResultCode::ConsensusInvalid)
        );

        let mut request = Vec::new();
        request.extend_from_slice(&2_u16.to_le_bytes());
        request.push(1);
        request.push(0);
        request.extend_from_slice(&state);
        request.extend_from_slice(&0_u64.to_le_bytes());
        request.extend_from_slice(&1_u32.to_le_bytes());
        request.extend_from_slice(&all[0]);
        assert_eq!(witness(&request), Err(ResultCode::UnsupportedFormat));

        request[0] = 1;
        request[1] = 0;
        request[3] = 1;
        assert_eq!(witness(&request), Err(ResultCode::ConsensusInvalid));

        request[3] = 0;
        request[2] = 17;
        assert_eq!(witness(&request), Err(ResultCode::ResourceLimit));
    }
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
