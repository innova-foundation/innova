//! Canonical eight-layer FCMP++ proving and verification requests.

use std::collections::BTreeSet;

use blake2::{Blake2b512, Digest as _};
use ciphersuite::{
    group::{
        ff::{Field as _, PrimeField as _},
        Group as _, GroupEncoding,
    },
    Ciphersuite,
};
use dalek_ff_group::{Ed25519, EdwardsPoint};
use ec_divisors::ScalarDecomposition;
use helioselene::{Helios, Selene};
use monero_ed25519::CompressedPoint;
use monero_fcmp_plus_plus::{
    fcmps::{
        BranchBlind, Branches, CBlind, Fcmp, IBlind, IBlindBlind, Input as MembershipInput, OBlind,
        OutputBlinds, Path, TreeRoot,
    },
    sal::{OpenedInputTuple, RerandomizedOutput, SpendAuthAndLinkability},
    Curves, FcmpPlusPlus, FCMP_PARAMS, HELIOS_FCMP_GENERATORS, SELENE_FCMP_GENERATORS,
};
use monero_fcmp_plus_plus_generators::{FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V};
#[cfg(test)]
use monero_fcmp_plus_plus_generators::{HELIOS_HASH_INIT, SELENE_HASH_INIT};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroize;

use super::{disclosure, ResultCode};

const SCHEMA: u16 = 1;
const LAYERS: u8 = 8;
const ROOT_CURVE_HELIOS: u8 = 2;
const MAX_INPUTS: usize = 16;
const MAX_BYTES: usize = 256 * 1024;
const C1_LAYER_COUNT: usize = 3;
const C2_LAYER_COUNT: usize = 4;
const C1_BRANCH_LEN: usize = 38;
const C2_BRANCH_LEN: usize = 18;
const PROVE_HEADER_LEN: usize = 104;
const VERIFY_HEADER_LEN: usize = 72;
const RESPONSE_HEADER_LEN: usize = 4;
const RESPONSE_RECORD_LEN: usize = 256;
const BATCH_HEADER_LEN: usize = 8;
/// Seeds the rerandomization draw, which must not depend on the signable hash.
const RERANDOMIZE_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/RerandomizeRng/v1";
/// Seeds every proof nonce, which must depend on the signable hash they are challenged under.
const PROOF_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/ProofRng/v1";
/// Where the signable hash sits in a proving request, after the header and the root.
const SIGNABLE_HASH_OFFSET: usize = 40;
const BATCH_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/BatchWeights/v1";
/// Seeds the split membership half's branch blinds and proof nonces. Nothing it draws is
/// challenged under a message, so it must not need one.
const SPLIT_MEMBERSHIP_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/SplitMembershipRng/v1";
/// Seeds the split SAL half's nonces over its whole request, so the signable hash is in every
/// draw.
const SPLIT_SAL_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/SplitSalRng/v1";

type EdPoint = <Ed25519 as Ciphersuite>::G;
type EdScalar = <Ed25519 as Ciphersuite>::F;
type C1Scalar = <Selene as Ciphersuite>::F;
type C2Scalar = <Helios as Ciphersuite>::F;
type FcmpRoot = TreeRoot<Selene, Helios>;
type FcmpOutput = monero_fcmp_plus_plus::Output;

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], ResultCode> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ResultCode::ResourceLimit)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ResultCode::BadLength)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ResultCode> {
        self.bytes(N)?
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

    fn zeroes(&mut self, count: usize) -> Result<(), ResultCode> {
        if self.bytes(count)?.iter().any(|byte| *byte != 0) {
            return Err(ResultCode::ConsensusInvalid);
        }
        Ok(())
    }

    fn finish(self) -> Result<(), ResultCode> {
        if self.offset != self.bytes.len() {
            return Err(ResultCode::BadLength);
        }
        Ok(())
    }
}

fn check_schema_and_layers(reader: &mut Reader<'_>) -> Result<(), ResultCode> {
    if reader.u16()? != SCHEMA || reader.u8()? != LAYERS {
        return Err(ResultCode::UnsupportedFormat);
    }
    Ok(())
}

fn decode_group<C>(bytes: [u8; 32]) -> Result<C::G, ResultCode>
where
    C: Ciphersuite,
    C::G: GroupEncoding<Repr = [u8; 32]>,
{
    let mut encoded = bytes.as_slice();
    let point = C::read_G(&mut encoded).map_err(|_| ResultCode::ConsensusInvalid)?;
    if !encoded.is_empty() || bool::from(point.is_identity()) || point.to_bytes() != bytes {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(point)
}

fn decode_scalar<C: Ciphersuite>(bytes: [u8; 32]) -> Result<C::F, ResultCode> {
    let mut encoded = bytes.as_slice();
    let scalar = C::read_F(&mut encoded).map_err(|_| ResultCode::ConsensusInvalid)?;
    if !encoded.is_empty() || scalar.to_repr().as_ref() != bytes {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(scalar)
}

fn decode_output(reader: &mut Reader<'_>) -> Result<FcmpOutput, ResultCode> {
    FcmpOutput::new(
        decode_group::<Ed25519>(reader.array()?)?,
        decode_group::<Ed25519>(reader.array()?)?,
        decode_group::<Ed25519>(reader.array()?)?,
    )
    .map_err(|_| ResultCode::ConsensusInvalid)
}

fn decode_root(curve: u8, bytes: [u8; 32]) -> Result<FcmpRoot, ResultCode> {
    if curve != ROOT_CURVE_HELIOS {
        return Err(ResultCode::UnsupportedFormat);
    }
    Ok(TreeRoot::C2(decode_group::<Helios>(bytes)?))
}

fn validate_count(count: usize) -> Result<(), ResultCode> {
    if count == 0 {
        return Err(ResultCode::BadLength);
    }
    if count > MAX_INPUTS {
        return Err(ResultCode::ResourceLimit);
    }
    Ok(())
}

fn deterministic_rng(domain: &[u8], pieces: &[&[u8]]) -> ChaCha20Rng {
    let mut transcript = Blake2b512::new();
    transcript.update(domain);
    for piece in pieces {
        transcript.update(
            u32::try_from(piece.len())
                .expect("ABI piece length is bounded")
                .to_le_bytes(),
        );
        transcript.update(piece);
    }
    let digest = transcript.finalize();
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&digest[..32]);
    let rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    rng
}

fn monero_t() -> EdwardsPoint {
    EdwardsPoint(
        CompressedPoint::T
            .decompress()
            .expect("pinned Monero T generator must decompress")
            .into(),
    )
}

struct ProvingWitness {
    x: EdScalar,
    y: EdScalar,
    path: Path<Curves>,
}

impl Drop for ProvingWitness {
    fn drop(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

struct ParsedProvingRequest {
    root_bytes: [u8; 32],
    signable_hash: [u8; 32],
    entropy: [u8; 32],
    witnesses: Vec<ProvingWitness>,
}

/// One witness record: the opening, the leaf, and the branch it sits under. The record is the
/// same for every proof shape, so the membership-only request reads it with this too.
fn parse_witness(reader: &mut Reader<'_>, t: EdPoint) -> Result<ProvingWitness, ResultCode> {
    let x = decode_scalar::<Ed25519>(reader.array()?)?;
    if bool::from(x.is_zero()) {
        return Err(ResultCode::ConsensusInvalid);
    }
    let y = decode_scalar::<Ed25519>(reader.array()?)?;
    let output = decode_output(reader)?;
    if output.O() != (<Ed25519 as Ciphersuite>::generator() * x) + (t * y) {
        return Err(ResultCode::ConsensusInvalid);
    }

    let leaf_count = usize::from(reader.u8()?);
    if leaf_count == 0 || leaf_count > C1_BRANCH_LEN {
        return Err(ResultCode::ConsensusInvalid);
    }
    reader.zeroes(3)?;
    let mut leaves = Vec::with_capacity(leaf_count);
    for _ in 0..leaf_count {
        leaves.push(decode_output(reader)?);
    }
    if !leaves.iter().any(|candidate| candidate == &output) {
        return Err(ResultCode::ConsensusInvalid);
    }

    let mut curve_2_layers = Vec::with_capacity(C2_LAYER_COUNT);
    for _ in 0..C2_LAYER_COUNT {
        let mut branch = Vec::with_capacity(C2_BRANCH_LEN);
        for _ in 0..C2_BRANCH_LEN {
            branch.push(decode_scalar::<Helios>(reader.array()?)?);
        }
        curve_2_layers.push(branch);
    }
    let mut curve_1_layers = Vec::with_capacity(C1_LAYER_COUNT);
    for _ in 0..C1_LAYER_COUNT {
        let mut branch = Vec::with_capacity(C1_BRANCH_LEN);
        for _ in 0..C1_BRANCH_LEN {
            branch.push(decode_scalar::<Selene>(reader.array()?)?);
        }
        curve_1_layers.push(branch);
    }
    Ok(ProvingWitness {
        x,
        y,
        path: Path {
            output,
            leaves,
            curve_2_layers,
            curve_1_layers,
        },
    })
}

fn parse_proving_request(request: &[u8]) -> Result<ParsedProvingRequest, ResultCode> {
    if request.len() < PROVE_HEADER_LEN {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    check_schema_and_layers(&mut reader)?;
    let root_curve = reader.u8()?;
    let count = usize::from(reader.u8()?);
    validate_count(count)?;
    reader.zeroes(3)?;
    let root_bytes = reader.array()?;
    let _ = decode_root(root_curve, root_bytes)?;
    let signable_hash = reader.array()?;
    let entropy = reader.array::<32>()?;
    if entropy.iter().all(|byte| *byte == 0) {
        return Err(ResultCode::ConsensusInvalid);
    }

    let t = monero_t();
    let mut witnesses = Vec::with_capacity(count);
    for _ in 0..count {
        witnesses.push(parse_witness(&mut reader, t)?);
    }
    reader.finish()?;
    Ok(ParsedProvingRequest {
        root_bytes,
        signable_hash,
        entropy,
        witnesses,
    })
}

fn rerandomize_with_nonzero_blinds(
    rng: &mut ChaCha20Rng,
    output: &FcmpOutput,
) -> (
    RerandomizedOutput,
    ScalarDecomposition<EdScalar>,
    ScalarDecomposition<EdScalar>,
    ScalarDecomposition<EdScalar>,
    ScalarDecomposition<EdScalar>,
) {
    loop {
        let rerandomized = RerandomizedOutput::new(rng, *output);
        if let (Some(o), Some(i), Some(i_blind), Some(c)) = (
            ScalarDecomposition::new(rerandomized.o_blind()),
            ScalarDecomposition::new(rerandomized.i_blind()),
            ScalarDecomposition::new(rerandomized.i_blind_blind()),
            ScalarDecomposition::new(rerandomized.c_blind()),
        ) {
            return (rerandomized, o, i, i_blind, c);
        }
    }
}

fn random_c1_decomposition(rng: &mut ChaCha20Rng) -> ScalarDecomposition<C1Scalar> {
    loop {
        if let Some(value) = ScalarDecomposition::new(C1Scalar::random(&mut *rng)) {
            return value;
        }
    }
}

fn random_c2_decomposition(rng: &mut ChaCha20Rng) -> ScalarDecomposition<C2Scalar> {
    loop {
        if let Some(value) = ScalarDecomposition::new(C2Scalar::random(&mut *rng)) {
            return value;
        }
    }
}

fn verification_request_from_response(
    root_bytes: [u8; 32],
    signable_hash: [u8; 32],
    response: &[u8],
) -> Result<Vec<u8>, ResultCode> {
    if response.len() < RESPONSE_HEADER_LEN {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    let mut reader = Reader::new(response);
    check_schema_and_layers(&mut reader)?;
    let count = usize::from(reader.u8()?);
    validate_count(count)?;
    let mut pseudo_outs = Vec::with_capacity(count);
    let mut key_images = Vec::with_capacity(count);
    for _ in 0..count {
        pseudo_outs.push(reader.array()?);
        key_images.push(reader.array()?);
        let _mask_delta = reader.array::<32>()?;
        let _sender_authority = reader.array::<32>()?;
        let _sender_disclosure_proof = reader.bytes(128)?;
    }
    let proof_len = usize::try_from(reader.u32()?).map_err(|_| ResultCode::ResourceLimit)?;
    let proof = reader.bytes(proof_len)?;
    reader.finish()?;
    encode_verification_request(root_bytes, signable_hash, &pseudo_outs, &key_images, proof)
}

fn encode_verification_request(
    root_bytes: [u8; 32],
    signable_hash: [u8; 32],
    pseudo_outs: &[[u8; 32]],
    key_images: &[[u8; 32]],
    proof: &[u8],
) -> Result<Vec<u8>, ResultCode> {
    let count = pseudo_outs.len();
    validate_count(count)?;
    if count != key_images.len() {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    let mut request = Vec::with_capacity(
        VERIFY_HEADER_LEN
            .checked_add(count * 64)
            .and_then(|size| size.checked_add(4 + proof.len()))
            .ok_or(ResultCode::ResourceLimit)?,
    );
    request.extend_from_slice(&SCHEMA.to_le_bytes());
    request.push(LAYERS);
    request.push(ROOT_CURVE_HELIOS);
    request.push(u8::try_from(count).map_err(|_| ResultCode::ResourceLimit)?);
    request.extend_from_slice(&[0; 3]);
    request.extend_from_slice(&root_bytes);
    request.extend_from_slice(&signable_hash);
    for (pseudo_out, key_image) in pseudo_outs.iter().zip(key_images) {
        request.extend_from_slice(pseudo_out);
        request.extend_from_slice(key_image);
    }
    request.extend_from_slice(
        &u32::try_from(proof.len())
            .map_err(|_| ResultCode::ResourceLimit)?
            .to_le_bytes(),
    );
    request.extend_from_slice(proof);
    if request.len() > MAX_BYTES {
        return Err(ResultCode::ResourceLimit);
    }
    Ok(request)
}

struct ProvingResponseRecord {
    pseudo_out: [u8; 32],
    key_image: [u8; 32],
    pseudo_out_mask_delta: [u8; 32],
    sender_authority: [u8; 32],
    sender_disclosure_proof: [u8; 128],
}

impl Drop for ProvingResponseRecord {
    fn drop(&mut self) {
        self.pseudo_out_mask_delta.zeroize();
    }
}

fn encode_proving_response(
    records: &[ProvingResponseRecord],
    proof: &[u8],
) -> Result<Vec<u8>, ResultCode> {
    let count = records.len();
    validate_count(count)?;
    let mut response = Vec::with_capacity(
        RESPONSE_HEADER_LEN
            .checked_add(count * RESPONSE_RECORD_LEN)
            .and_then(|size| size.checked_add(4 + proof.len()))
            .ok_or(ResultCode::ResourceLimit)?,
    );
    response.extend_from_slice(&SCHEMA.to_le_bytes());
    response.push(LAYERS);
    response.push(u8::try_from(count).map_err(|_| ResultCode::ResourceLimit)?);
    for record in records {
        response.extend_from_slice(&record.pseudo_out);
        response.extend_from_slice(&record.key_image);
        response.extend_from_slice(&record.pseudo_out_mask_delta);
        response.extend_from_slice(&record.sender_authority);
        response.extend_from_slice(&record.sender_disclosure_proof);
    }
    response.extend_from_slice(
        &u32::try_from(proof.len())
            .map_err(|_| ResultCode::ResourceLimit)?
            .to_le_bytes(),
    );
    response.extend_from_slice(proof);
    if response.len() > MAX_BYTES {
        return Err(ResultCode::ResourceLimit);
    }
    Ok(response)
}

#[allow(clippy::too_many_lines)]
pub(super) fn prove(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    let ParsedProvingRequest {
        root_bytes,
        signable_hash,
        entropy,
        witnesses,
    } = parse_proving_request(request)?;
    let count = witnesses.len();
    // Two streams. The rerandomization must not depend on the signable hash (the hash
    // covers the pseudo-outputs it produces). Every proof nonce must depend on the hash, or
    // two proofs under different challenges would share alpha and reveal the spend key.
    let rerandomize_pieces = [
        request
            .get(..SIGNABLE_HASH_OFFSET)
            .ok_or(ResultCode::BadLength)?,
        request
            .get(SIGNABLE_HASH_OFFSET + 32..)
            .ok_or(ResultCode::BadLength)?,
    ];
    let mut rerandomize_rng = deterministic_rng(RERANDOMIZE_RNG_DOMAIN, &rerandomize_pieces);
    let mut proof_rng = deterministic_rng(PROOF_RNG_DOMAIN, &[request]);
    let t_generator = monero_t();
    let u_generator = EdwardsPoint((*FCMP_PLUS_PLUS_U).into());
    let v_generator = EdwardsPoint((*FCMP_PLUS_PLUS_V).into());

    let paths = witnesses
        .iter()
        .map(|witness| witness.path.clone())
        .collect::<Vec<_>>();
    let branches = Branches::new(paths).ok_or(ResultCode::ConsensusInvalid)?;
    let c1_blinds = branches.necessary_c1_blinds();
    let c2_blinds = branches.necessary_c2_blinds();

    let mut output_blinds = Vec::with_capacity(count);
    let mut inputs_and_authorizations = Vec::with_capacity(count);
    let mut response_records = Vec::with_capacity(count);
    let mut unique_key_images = BTreeSet::new();
    for (input_index, witness) in witnesses.iter().enumerate() {
        let (
            rerandomized,
            o_decomposition,
            i_decomposition,
            i_blind_decomposition,
            c_decomposition,
        ) = rerandomize_with_nonzero_blinds(&mut rerandomize_rng, &witness.path.output);
        let mut pseudo_out_mask_delta = -rerandomized.c_blind();
        let mut rerandomized_y = witness.y - rerandomized.o_blind();
        let opening = OpenedInputTuple::open(&rerandomized, &witness.x, &witness.y)
            .ok_or(ResultCode::ConsensusInvalid)?;
        let input = rerandomized.input();
        let (key_image, authorization) =
            SpendAuthAndLinkability::prove(&mut proof_rng, signable_hash, &opening);
        let key_image_bytes = key_image.to_bytes();
        if !unique_key_images.insert(key_image_bytes) {
            return Err(ResultCode::ConsensusInvalid);
        }
        let pseudo_out = input.C_tilde();
        let o_tilde = input.O_tilde();
        let pseudo_out_mask_delta_bytes = pseudo_out_mask_delta.to_repr();
        let sender_authority = (<Ed25519 as Ciphersuite>::generator() * witness.x).to_bytes();
        let mut rerandomized_y_bytes = rerandomized_y.to_repr();
        let input_index = u32::try_from(input_index).map_err(|_| ResultCode::ResourceLimit)?;
        let sender_disclosure_proof = disclosure::prove_sender(
            &sender_authority,
            &o_tilde,
            &witness.x.to_repr(),
            &rerandomized_y_bytes,
            &signable_hash,
            input_index,
            &entropy,
        )
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
        let sender_disclosure_valid = disclosure::verify_sender(
            &sender_authority,
            &o_tilde,
            &signable_hash,
            input_index,
            &sender_disclosure_proof,
        )
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
        if !sender_disclosure_valid {
            return Err(ResultCode::InternalLocalStateFailure);
        }
        response_records.push(ProvingResponseRecord {
            pseudo_out,
            key_image: key_image_bytes,
            pseudo_out_mask_delta: pseudo_out_mask_delta_bytes,
            sender_authority,
            sender_disclosure_proof,
        });
        pseudo_out_mask_delta.zeroize();
        rerandomized_y.zeroize();
        rerandomized_y_bytes.zeroize();
        inputs_and_authorizations.push((input, authorization));
        output_blinds.push(OutputBlinds::new(
            OBlind::new(t_generator, o_decomposition),
            IBlind::new(u_generator, v_generator, i_decomposition),
            IBlindBlind::new(t_generator, i_blind_decomposition),
            CBlind::new(<Ed25519 as Ciphersuite>::generator(), c_decomposition),
        ));
    }

    // Branch blinds and the membership proof itself hide nothing the prefix names, so they
    // belong to the hash-dependent stream with the rest of the proof randomness.
    let mut branch_1_blinds = Vec::with_capacity(c1_blinds);
    for _ in 0..c1_blinds {
        branch_1_blinds.push(BranchBlind::new(
            SELENE_FCMP_GENERATORS.generators.h(),
            random_c1_decomposition(&mut proof_rng),
        ));
    }
    let mut branch_2_blinds = Vec::with_capacity(c2_blinds);
    for _ in 0..c2_blinds {
        branch_2_blinds.push(BranchBlind::new(
            HELIOS_FCMP_GENERATORS.generators.h(),
            random_c2_decomposition(&mut proof_rng),
        ));
    }

    let blinded = branches
        .blind(output_blinds, branch_1_blinds, branch_2_blinds)
        .map_err(|_| ResultCode::ConsensusInvalid)?;
    let membership = Fcmp::prove(&mut proof_rng, &FCMP_PARAMS, blinded)
        .map_err(|_| ResultCode::ConsensusInvalid)?;
    let proof = FcmpPlusPlus::new(inputs_and_authorizations, membership);
    let expected_size = FcmpPlusPlus::proof_size(count, usize::from(LAYERS));
    let mut proof_bytes = Vec::with_capacity(expected_size);
    proof
        .write(&mut proof_bytes)
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
    if proof_bytes.len() != expected_size {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let response = encode_proving_response(&response_records, &proof_bytes)?;
    let verification = verification_request_from_response(root_bytes, signable_hash, &response)?;
    verify(&verification)?;
    Ok(response)
}

struct ParsedVerification {
    root: FcmpRoot,
    signable_hash: [u8; 32],
    key_images: Vec<EdPoint>,
    proof: FcmpPlusPlus,
    input_count: usize,
}

fn parse_verification_request(request: &[u8]) -> Result<ParsedVerification, ResultCode> {
    if request.len() < VERIFY_HEADER_LEN {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    check_schema_and_layers(&mut reader)?;
    let root_curve = reader.u8()?;
    let count = usize::from(reader.u8()?);
    validate_count(count)?;
    reader.zeroes(3)?;
    let root = decode_root(root_curve, reader.array()?)?;
    let signable_hash = reader.array()?;

    let mut pseudo_outs = Vec::with_capacity(count);
    let mut key_images = Vec::with_capacity(count);
    let mut unique_key_images = BTreeSet::new();
    for _ in 0..count {
        let pseudo_out = reader.array()?;
        let _ = decode_group::<Ed25519>(pseudo_out)?;
        pseudo_outs.push(pseudo_out);
        let key_image_bytes = reader.array()?;
        if !unique_key_images.insert(key_image_bytes) {
            return Err(ResultCode::ConsensusInvalid);
        }
        key_images.push(decode_group::<Ed25519>(key_image_bytes)?);
    }

    let proof_len = usize::try_from(reader.u32()?).map_err(|_| ResultCode::ResourceLimit)?;
    let expected = FcmpPlusPlus::proof_size(count, usize::from(LAYERS));
    if proof_len != expected {
        return Err(ResultCode::ConsensusInvalid);
    }
    let proof_bytes = reader.bytes(proof_len)?;
    reader.finish()?;
    let mut encoded = proof_bytes;
    let proof = FcmpPlusPlus::read(&pseudo_outs, usize::from(LAYERS), &mut encoded)
        .map_err(|_| ResultCode::ConsensusInvalid)?;
    if !encoded.is_empty() {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(ParsedVerification {
        root,
        signable_hash,
        key_images,
        proof,
        input_count: count,
    })
}

fn verify_requests(requests: &[&[u8]]) -> Result<(), ResultCode> {
    validate_count(requests.len())?;
    let mut parsed = Vec::with_capacity(requests.len());
    let mut total_inputs = 0_usize;
    for request in requests {
        let proof = parse_verification_request(request)?;
        total_inputs = total_inputs
            .checked_add(proof.input_count)
            .ok_or(ResultCode::ResourceLimit)?;
        if total_inputs > MAX_INPUTS {
            return Err(ResultCode::ResourceLimit);
        }
        parsed.push(proof);
    }

    let mut rng = deterministic_rng(BATCH_RNG_DOMAIN, requests);
    let mut ed_verifier = multiexp::BatchVerifier::new(total_inputs);
    let mut c1_verifier = generalized_bulletproofs::Generators::batch_verifier();
    let mut c2_verifier = generalized_bulletproofs::Generators::batch_verifier();
    for proof in &parsed {
        proof
            .proof
            .verify(
                &mut rng,
                &mut ed_verifier,
                &mut c1_verifier,
                &mut c2_verifier,
                proof.root,
                usize::from(LAYERS),
                proof.signable_hash,
                proof.key_images.clone(),
            )
            .map_err(|_| ResultCode::ConsensusInvalid)?;
    }
    let ed_valid = ed_verifier.verify_vartime();
    let c1_valid = SELENE_FCMP_GENERATORS.generators.verify(c1_verifier);
    let c2_valid = HELIOS_FCMP_GENERATORS.generators.verify(c2_verifier);
    if !(ed_valid && c1_valid && c2_valid) {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(())
}

pub(super) fn verify(request: &[u8]) -> Result<(), ResultCode> {
    verify_requests(&[request])
}

pub(crate) fn verify_components(
    root: [u8; 32],
    signable_hash: [u8; 32],
    pseudo_outs: &[[u8; 32]],
    key_images: &[[u8; 32]],
    proof: &[u8],
) -> Result<(), ResultCode> {
    let request = encode_verification_request(root, signable_hash, pseudo_outs, key_images, proof)?;
    verify(&request)
}

pub(crate) fn input_o_tilde(
    proof: &[u8],
    input_count: usize,
    input_index: usize,
) -> Result<[u8; 32], ResultCode> {
    const SERIALIZED_INPUT_AND_SAL_BYTES: usize = (3 + 12) * 32;
    if input_index >= input_count {
        return Err(ResultCode::BadLength);
    }
    let prefix_len = input_count
        .checked_mul(SERIALIZED_INPUT_AND_SAL_BYTES)
        .ok_or(ResultCode::ResourceLimit)?;
    if proof.len() < prefix_len {
        return Err(ResultCode::ConsensusInvalid);
    }
    let offset = input_index
        .checked_mul(SERIALIZED_INPUT_AND_SAL_BYTES)
        .ok_or(ResultCode::ResourceLimit)?;
    proof[offset..offset + 32]
        .try_into()
        .map_err(|_| ResultCode::InternalLocalStateFailure)
}

/// The length-framed batch envelope, which is the same whatever the framed requests prove.
fn parse_batch_frame(
    request: &[u8],
    expected_count: u32,
) -> Result<(Vec<&[u8]>, usize), ResultCode> {
    if request.len() < BATCH_HEADER_LEN {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    check_schema_and_layers(&mut reader)?;
    let count = usize::from(reader.u8()?);
    validate_count(count)?;
    if u32::try_from(count).map_err(|_| ResultCode::ResourceLimit)? != expected_count {
        return Err(ResultCode::BadLength);
    }
    let declared_inputs = usize::from(reader.u8()?);
    validate_count(declared_inputs)?;
    reader.zeroes(2)?;

    let mut requests = Vec::with_capacity(count);
    for _ in 0..count {
        let len = usize::try_from(reader.u32()?).map_err(|_| ResultCode::ResourceLimit)?;
        if len == 0 {
            return Err(ResultCode::BadLength);
        }
        if len > MAX_BYTES {
            return Err(ResultCode::ResourceLimit);
        }
        requests.push(reader.bytes(len)?);
    }
    reader.finish()?;
    Ok((requests, declared_inputs))
}

pub(super) fn verify_batch(request: &[u8], expected_count: u32) -> Result<(), ResultCode> {
    let (requests, declared_inputs) = parse_batch_frame(request, expected_count)?;

    let mut actual_inputs = 0_usize;
    for item in &requests {
        let parsed = parse_verification_request(item)?;
        actual_inputs = actual_inputs
            .checked_add(parsed.input_count)
            .ok_or(ResultCode::ResourceLimit)?;
    }
    if actual_inputs != declared_inputs {
        return Err(ResultCode::ConsensusInvalid);
    }
    verify_requests(&requests)
}

// Membership-only instance: the bare FCMP over the tree, with no spend authorization and
// no key image. It commits to no message and is replayable; binding it to a statement is
// the caller's job.

/// Header through the root: schema, layers, root curve, count, padding, root.
const MEMBERSHIP_HEADER_LEN: usize = 40;
/// The proving request adds entropy for the rerandomization draw.
const MEMBERSHIP_PROVE_HEADER_LEN: usize = MEMBERSHIP_HEADER_LEN + 32;
/// One re-randomized input tuple: O~, I~, R, C~. A key image would be a fifth point.
const MEMBERSHIP_INPUT_LEN: usize = 128;
const MEMBERSHIP_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/MembershipRng/v1";
const MEMBERSHIP_BATCH_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/MembershipBatchWeights/v1";

// `Fcmp::verify` panics, rather than erroring, when the layer count's parity disagrees with the
// tree root's curve. The layer count is a constant here, so half the pin is compile-time.
const _: () = assert!(
    LAYERS.is_multiple_of(2),
    "an even layer count is what makes a Helios root the only root Fcmp::verify accepts"
);

struct ParsedMembership {
    root: FcmpRoot,
    inputs: Vec<MembershipInput<C1Scalar>>,
    proof: Fcmp<Curves>,
    input_count: usize,
}

fn encode_membership_request(
    root_bytes: [u8; 32],
    tuples: &[[u8; MEMBERSHIP_INPUT_LEN]],
    proof: &[u8],
) -> Result<Vec<u8>, ResultCode> {
    let count = tuples.len();
    validate_count(count)?;
    let mut request = Vec::with_capacity(
        MEMBERSHIP_HEADER_LEN
            .checked_add(count * MEMBERSHIP_INPUT_LEN)
            .and_then(|size| size.checked_add(4 + proof.len()))
            .ok_or(ResultCode::ResourceLimit)?,
    );
    request.extend_from_slice(&SCHEMA.to_le_bytes());
    request.push(LAYERS);
    request.push(ROOT_CURVE_HELIOS);
    request.push(u8::try_from(count).map_err(|_| ResultCode::ResourceLimit)?);
    request.extend_from_slice(&[0; 3]);
    request.extend_from_slice(&root_bytes);
    for tuple in tuples {
        request.extend_from_slice(tuple);
    }
    request.extend_from_slice(
        &u32::try_from(proof.len())
            .map_err(|_| ResultCode::ResourceLimit)?
            .to_le_bytes(),
    );
    request.extend_from_slice(proof);
    if request.len() > MAX_BYTES {
        return Err(ResultCode::ResourceLimit);
    }
    Ok(request)
}

fn parse_membership_request(request: &[u8]) -> Result<ParsedMembership, ResultCode> {
    if request.len() < MEMBERSHIP_HEADER_LEN {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    check_schema_and_layers(&mut reader)?;
    let root_curve = reader.u8()?;
    let count = usize::from(reader.u8()?);
    validate_count(count)?;
    reader.zeroes(3)?;
    let root = decode_root(root_curve, reader.array()?)?;

    let mut inputs = Vec::with_capacity(count);
    for _ in 0..count {
        let o_tilde = decode_group::<Ed25519>(reader.array()?)?;
        let i_tilde = decode_group::<Ed25519>(reader.array()?)?;
        let r = decode_group::<Ed25519>(reader.array()?)?;
        let c_tilde = decode_group::<Ed25519>(reader.array()?)?;
        inputs.push(
            MembershipInput::new(o_tilde, i_tilde, r, c_tilde)
                .map_err(|_| ResultCode::ConsensusInvalid)?,
        );
    }

    let proof_len = usize::try_from(reader.u32()?).map_err(|_| ResultCode::ResourceLimit)?;
    // Fixing the length before the read is also what keeps `Fcmp::read`'s own size arithmetic
    // away from its underflow case.
    if proof_len != Fcmp::<Curves>::proof_size(count, usize::from(LAYERS)) {
        return Err(ResultCode::ConsensusInvalid);
    }
    let proof_bytes = reader.bytes(proof_len)?;
    reader.finish()?;
    let mut encoded = proof_bytes;
    let proof = Fcmp::<Curves>::read(&mut encoded, count, usize::from(LAYERS))
        .map_err(|_| ResultCode::ConsensusInvalid)?;
    if !encoded.is_empty() {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(ParsedMembership {
        root,
        inputs,
        proof,
        input_count: count,
    })
}

fn verify_membership_requests(requests: &[&[u8]]) -> Result<(), ResultCode> {
    validate_count(requests.len())?;
    let mut parsed = Vec::with_capacity(requests.len());
    let mut total_inputs = 0_usize;
    for request in requests {
        let proof = parse_membership_request(request)?;
        total_inputs = total_inputs
            .checked_add(proof.input_count)
            .ok_or(ResultCode::ResourceLimit)?;
        if total_inputs > MAX_INPUTS {
            return Err(ResultCode::ResourceLimit);
        }
        parsed.push(proof);
    }

    let mut rng = deterministic_rng(MEMBERSHIP_BATCH_RNG_DOMAIN, requests);
    // No ed25519 batch verifier is built at all: nothing here queues onto one, and a request
    // that names no key image has nothing to check against it.
    let mut c1_verifier = generalized_bulletproofs::Generators::batch_verifier();
    let mut c2_verifier = generalized_bulletproofs::Generators::batch_verifier();
    for proof in &parsed {
        // The decoder admits only a Helios root, and the layer count is pinned even. Restated
        // at the call site so the argument pair `Fcmp::verify` panics on cannot be assembled
        // by a later edit to either side.
        if !matches!(proof.root, TreeRoot::C2(_)) {
            return Err(ResultCode::UnsupportedFormat);
        }
        proof
            .proof
            .verify(
                &mut rng,
                &mut c1_verifier,
                &mut c2_verifier,
                &FCMP_PARAMS,
                proof.root,
                usize::from(LAYERS),
                &proof.inputs,
            )
            .map_err(|_| ResultCode::ConsensusInvalid)?;
    }
    let c1_valid = SELENE_FCMP_GENERATORS.generators.verify(c1_verifier);
    let c2_valid = HELIOS_FCMP_GENERATORS.generators.verify(c2_verifier);
    if !(c1_valid && c2_valid) {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn verify_membership(request: &[u8]) -> Result<(), ResultCode> {
    verify_membership_requests(&[request])
}

#[allow(dead_code)]
pub(crate) fn verify_membership_batch(
    request: &[u8],
    expected_count: u32,
) -> Result<(), ResultCode> {
    let (requests, declared_inputs) = parse_batch_frame(request, expected_count)?;

    let mut actual_inputs = 0_usize;
    for item in &requests {
        let parsed = parse_membership_request(item)?;
        actual_inputs = actual_inputs
            .checked_add(parsed.input_count)
            .ok_or(ResultCode::ResourceLimit)?;
    }
    if actual_inputs != declared_inputs {
        return Err(ResultCode::ConsensusInvalid);
    }
    verify_membership_requests(&requests)
}

struct ParsedMembershipProvingRequest {
    root_bytes: [u8; 32],
    witnesses: Vec<ProvingWitness>,
}

fn parse_membership_proving_request(
    request: &[u8],
) -> Result<ParsedMembershipProvingRequest, ResultCode> {
    if request.len() < MEMBERSHIP_PROVE_HEADER_LEN {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    check_schema_and_layers(&mut reader)?;
    let root_curve = reader.u8()?;
    let count = usize::from(reader.u8()?);
    validate_count(count)?;
    reader.zeroes(3)?;
    let root_bytes = reader.array()?;
    let _ = decode_root(root_curve, root_bytes)?;
    if reader.array::<32>()?.iter().all(|byte| *byte == 0) {
        return Err(ResultCode::ConsensusInvalid);
    }

    let t = monero_t();
    let mut witnesses = Vec::with_capacity(count);
    for _ in 0..count {
        witnesses.push(parse_witness(&mut reader, t)?);
    }
    reader.finish()?;
    Ok(ParsedMembershipProvingRequest {
        root_bytes,
        witnesses,
    })
}

/// Per-input material a vote needs and a bare verification request cannot carry: the sigma
/// witness for the rerandomized owner key, and the shift the amount commitment's mask took.
pub(crate) struct MembershipSecrets {
    pub o_tilde: [u8; 32],
    pub c_tilde: [u8; 32],
    pub rerandomized_y: [u8; 32],
    pub mask_delta: [u8; 32],
    /// `r_i` in the key image relation's sign (`L = x*I~ - (x*r_i)*U`). `i_blind` reports `-r_i`,
    /// so this is its negation.
    pub i_blind: [u8; 32],
    /// `r_r_i`, which `i_blind_blind` already reports unnegated. Needed to open R alongside
    /// `r_i`, since `R = r_i*V + r_r_i*T` is what pins `r_i` to the instance.
    pub i_blind_blind: [u8; 32],
}

/// Produce a membership-only instance. The result is a canonical verification request: there is
/// no wallet-only metadata to hold back, unlike the spend path's construction response.
#[allow(dead_code)]
pub(crate) fn prove_membership(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    Ok(prove_membership_with_secrets(request)?.0)
}

/// The same instance, with the per-input secrets the vote sigma is built from. One body, so a
/// vote can never be proved against a different rerandomization than the one it verifies.
pub(crate) fn prove_membership_with_secrets(
    request: &[u8],
) -> Result<(Vec<u8>, Vec<MembershipSecrets>), ResultCode> {
    let ParsedMembershipProvingRequest {
        root_bytes,
        witnesses,
    } = parse_membership_proving_request(request)?;
    let count = witnesses.len();
    // One stream: a membership proof binds no message, so freshness of O~ rests entirely
    // on the caller varying entropy.
    let mut rng = deterministic_rng(MEMBERSHIP_RNG_DOMAIN, &[request]);
    let t_generator = monero_t();
    let u_generator = EdwardsPoint((*FCMP_PLUS_PLUS_U).into());
    let v_generator = EdwardsPoint((*FCMP_PLUS_PLUS_V).into());

    let paths = witnesses
        .iter()
        .map(|witness| witness.path.clone())
        .collect::<Vec<_>>();
    let branches = Branches::new(paths).ok_or(ResultCode::ConsensusInvalid)?;
    let c1_blinds = branches.necessary_c1_blinds();
    let c2_blinds = branches.necessary_c2_blinds();

    let mut output_blinds = Vec::with_capacity(count);
    let mut tuples = Vec::with_capacity(count);
    let mut secrets = Vec::with_capacity(count);
    for witness in &witnesses {
        let (
            rerandomized,
            o_decomposition,
            i_decomposition,
            i_blind_decomposition,
            c_decomposition,
        ) = rerandomize_with_nonzero_blinds(&mut rng, &witness.path.output);
        // The rerandomization is the only part of the spend path this shares. Neither
        // `OpenedInputTuple::open` nor `SpendAuthAndLinkability::prove` runs, so no key image is
        // computed, let alone published.
        let input = rerandomized.input();
        let mut tuple = [0_u8; MEMBERSHIP_INPUT_LEN];
        tuple[..32].copy_from_slice(&input.O_tilde());
        tuple[32..64].copy_from_slice(&input.I_tilde());
        tuple[64..96].copy_from_slice(&input.R());
        tuple[96..].copy_from_slice(&input.C_tilde());
        tuples.push(tuple);
        secrets.push(MembershipSecrets {
            o_tilde: input.O_tilde(),
            c_tilde: input.C_tilde(),
            rerandomized_y: (witness.y - rerandomized.o_blind()).to_repr(),
            mask_delta: (-rerandomized.c_blind()).to_repr(),
            i_blind: (-rerandomized.i_blind()).to_repr(),
            i_blind_blind: rerandomized.i_blind_blind().to_repr(),
        });
        output_blinds.push(OutputBlinds::new(
            OBlind::new(t_generator, o_decomposition),
            IBlind::new(u_generator, v_generator, i_decomposition),
            IBlindBlind::new(t_generator, i_blind_decomposition),
            CBlind::new(<Ed25519 as Ciphersuite>::generator(), c_decomposition),
        ));
    }

    let mut branch_1_blinds = Vec::with_capacity(c1_blinds);
    for _ in 0..c1_blinds {
        branch_1_blinds.push(BranchBlind::new(
            SELENE_FCMP_GENERATORS.generators.h(),
            random_c1_decomposition(&mut rng),
        ));
    }
    let mut branch_2_blinds = Vec::with_capacity(c2_blinds);
    for _ in 0..c2_blinds {
        branch_2_blinds.push(BranchBlind::new(
            HELIOS_FCMP_GENERATORS.generators.h(),
            random_c2_decomposition(&mut rng),
        ));
    }

    let blinded = branches
        .blind(output_blinds, branch_1_blinds, branch_2_blinds)
        .map_err(|_| ResultCode::ConsensusInvalid)?;
    let membership =
        Fcmp::prove(&mut rng, &FCMP_PARAMS, blinded).map_err(|_| ResultCode::ConsensusInvalid)?;
    let expected_size = Fcmp::<Curves>::proof_size(count, usize::from(LAYERS));
    let mut proof_bytes = Vec::with_capacity(expected_size);
    membership
        .write(&mut proof_bytes)
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
    if proof_bytes.len() != expected_size {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let verification = encode_membership_request(root_bytes, &tuples, &proof_bytes)?;
    verify_membership(&verification)?;
    Ok((verification, secrets))
}

// Split proving: the rerandomization is a pure function of the membership request, which
// the SAL request carries verbatim. Each SAL nonce is seeded with the whole SAL request.

/// One split membership record: pseudo-output, key image, secret mask delta, sender authority.
const SPLIT_MEMBERSHIP_RECORD_LEN: usize = 128;
/// Schema, layers, reserved, signable hash, proving request length.
const SPLIT_SAL_HEADER_LEN: usize = 40;

type SplitRerandomization = (
    RerandomizedOutput,
    ScalarDecomposition<EdScalar>,
    ScalarDecomposition<EdScalar>,
    ScalarDecomposition<EdScalar>,
    ScalarDecomposition<EdScalar>,
);

/// Rerandomize a membership request's witnesses on the combined prover's stream, so one
/// (root, entropy, witness) set rerandomizes identically on both paths.
fn split_rerandomize(proving: &[u8], witnesses: &[ProvingWitness]) -> Vec<SplitRerandomization> {
    let mut rng = deterministic_rng(
        RERANDOMIZE_RNG_DOMAIN,
        &[
            &proving[..MEMBERSHIP_HEADER_LEN],
            &proving[MEMBERSHIP_HEADER_LEN..],
        ],
    );
    witnesses
        .iter()
        .map(|witness| rerandomize_with_nonzero_blinds(&mut rng, &witness.path.output))
        .collect()
}

fn membership_tuple(input: &monero_fcmp_plus_plus::Input) -> [u8; MEMBERSHIP_INPUT_LEN] {
    let mut tuple = [0_u8; MEMBERSHIP_INPUT_LEN];
    tuple[..32].copy_from_slice(&input.O_tilde());
    tuple[32..64].copy_from_slice(&input.I_tilde());
    tuple[64..96].copy_from_slice(&input.R());
    tuple[96..].copy_from_slice(&input.C_tilde());
    tuple
}

/// x*I from the leaf rather than from a SAL, so the membership half can publish it.
fn split_key_image(witness: &ProvingWitness) -> [u8; 32] {
    (witness.path.output.I() * witness.x).to_bytes()
}

struct SplitMembershipRecord {
    pseudo_out: [u8; 32],
    key_image: [u8; 32],
    pseudo_out_mask_delta: [u8; 32],
    sender_authority: [u8; 32],
}

impl Drop for SplitMembershipRecord {
    fn drop(&mut self) {
        self.pseudo_out_mask_delta.zeroize();
    }
}

fn encode_split_membership_response(
    records: &[SplitMembershipRecord],
    instance: &[u8],
) -> Result<Vec<u8>, ResultCode> {
    let count = records.len();
    validate_count(count)?;
    let mut response = Vec::with_capacity(
        RESPONSE_HEADER_LEN
            .checked_add(count * SPLIT_MEMBERSHIP_RECORD_LEN)
            .and_then(|size| size.checked_add(4 + instance.len()))
            .ok_or(ResultCode::ResourceLimit)?,
    );
    response.extend_from_slice(&SCHEMA.to_le_bytes());
    response.push(LAYERS);
    response.push(u8::try_from(count).map_err(|_| ResultCode::ResourceLimit)?);
    for record in records {
        response.extend_from_slice(&record.pseudo_out);
        response.extend_from_slice(&record.key_image);
        response.extend_from_slice(&record.pseudo_out_mask_delta);
        response.extend_from_slice(&record.sender_authority);
    }
    response.extend_from_slice(
        &u32::try_from(instance.len())
            .map_err(|_| ResultCode::ResourceLimit)?
            .to_le_bytes(),
    );
    response.extend_from_slice(instance);
    if response.len() > MAX_BYTES {
        return Err(ResultCode::ResourceLimit);
    }
    Ok(response)
}

/// Prove the membership half alone, before any signable hash exists.
///
/// Request: a membership proving request. Response: `schema_u16 || layers_u8 || count_u8 ||
/// count * (pseudo_out_32 || key_image_32 || mask_delta_32 || sender_authority_32) ||
/// instance_len_u32_le || instance`. Pseudo-outputs and key images match the combined
/// prover's for the same root, entropy and witnesses.
pub(crate) fn prove_membership_only(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    let ParsedMembershipProvingRequest {
        root_bytes,
        witnesses,
    } = parse_membership_proving_request(request)?;
    let count = witnesses.len();
    let rerandomizations = split_rerandomize(request, &witnesses);
    // Branch blinds and the proof itself are challenged under nothing, so their stream needs
    // no hash; it still must not be the rerandomization stream, whose draws are fixed above.
    let mut proof_rng = deterministic_rng(SPLIT_MEMBERSHIP_RNG_DOMAIN, &[request]);
    let t_generator = monero_t();
    let u_generator = EdwardsPoint((*FCMP_PLUS_PLUS_U).into());
    let v_generator = EdwardsPoint((*FCMP_PLUS_PLUS_V).into());

    let paths = witnesses
        .iter()
        .map(|witness| witness.path.clone())
        .collect::<Vec<_>>();
    let branches = Branches::new(paths).ok_or(ResultCode::ConsensusInvalid)?;
    let c1_blinds = branches.necessary_c1_blinds();
    let c2_blinds = branches.necessary_c2_blinds();

    let mut output_blinds = Vec::with_capacity(count);
    let mut tuples = Vec::with_capacity(count);
    let mut records = Vec::with_capacity(count);
    let mut unique_key_images = BTreeSet::new();
    for (witness, (rerandomized, o, i, i_blind, c)) in witnesses.iter().zip(rerandomizations) {
        let input = rerandomized.input();
        let key_image = split_key_image(witness);
        if !unique_key_images.insert(key_image) {
            return Err(ResultCode::ConsensusInvalid);
        }
        tuples.push(membership_tuple(&input));
        records.push(SplitMembershipRecord {
            pseudo_out: input.C_tilde(),
            key_image,
            pseudo_out_mask_delta: (-rerandomized.c_blind()).to_repr(),
            sender_authority: (<Ed25519 as Ciphersuite>::generator() * witness.x).to_bytes(),
        });
        output_blinds.push(OutputBlinds::new(
            OBlind::new(t_generator, o),
            IBlind::new(u_generator, v_generator, i),
            IBlindBlind::new(t_generator, i_blind),
            CBlind::new(<Ed25519 as Ciphersuite>::generator(), c),
        ));
    }

    let mut branch_1_blinds = Vec::with_capacity(c1_blinds);
    for _ in 0..c1_blinds {
        branch_1_blinds.push(BranchBlind::new(
            SELENE_FCMP_GENERATORS.generators.h(),
            random_c1_decomposition(&mut proof_rng),
        ));
    }
    let mut branch_2_blinds = Vec::with_capacity(c2_blinds);
    for _ in 0..c2_blinds {
        branch_2_blinds.push(BranchBlind::new(
            HELIOS_FCMP_GENERATORS.generators.h(),
            random_c2_decomposition(&mut proof_rng),
        ));
    }

    let blinded = branches
        .blind(output_blinds, branch_1_blinds, branch_2_blinds)
        .map_err(|_| ResultCode::ConsensusInvalid)?;
    let membership = Fcmp::prove(&mut proof_rng, &FCMP_PARAMS, blinded)
        .map_err(|_| ResultCode::ConsensusInvalid)?;
    let expected_size = Fcmp::<Curves>::proof_size(count, usize::from(LAYERS));
    let mut proof_bytes = Vec::with_capacity(expected_size);
    membership
        .write(&mut proof_bytes)
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
    if proof_bytes.len() != expected_size {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let instance = encode_membership_request(root_bytes, &tuples, &proof_bytes)?;
    verify_membership(&instance)?;
    encode_split_membership_response(&records, &instance)
}

struct ParsedSplitSal<'a> {
    signable_hash: [u8; 32],
    proving: &'a [u8],
    instance: &'a [u8],
}

fn parse_split_sal_request(request: &[u8]) -> Result<ParsedSplitSal<'_>, ResultCode> {
    if request.len() < SPLIT_SAL_HEADER_LEN {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    check_schema_and_layers(&mut reader)?;
    reader.zeroes(1)?;
    let signable_hash = reader.array()?;
    let proving_len = usize::try_from(reader.u32()?).map_err(|_| ResultCode::ResourceLimit)?;
    if proving_len < MEMBERSHIP_PROVE_HEADER_LEN {
        return Err(ResultCode::BadLength);
    }
    if proving_len > MAX_BYTES {
        return Err(ResultCode::ResourceLimit);
    }
    let proving = reader.bytes(proving_len)?;
    let instance_len = request
        .len()
        .checked_sub(SPLIT_SAL_HEADER_LEN + proving_len)
        .ok_or(ResultCode::BadLength)?;
    if instance_len < MEMBERSHIP_HEADER_LEN {
        return Err(ResultCode::BadLength);
    }
    let instance = reader.bytes(instance_len)?;
    reader.finish()?;
    Ok(ParsedSplitSal {
        signable_hash,
        proving,
        instance,
    })
}

/// An instance's root, tuples and bare proof, read at the byte level so the tuples can be held
/// against a fresh rerandomization before anything is decoded into a curve point.
#[allow(clippy::type_complexity)]
fn split_instance_parts(
    instance: &[u8],
) -> Result<([u8; 32], Vec<[u8; MEMBERSHIP_INPUT_LEN]>, &[u8]), ResultCode> {
    let mut reader = Reader::new(instance);
    check_schema_and_layers(&mut reader)?;
    let root_curve = reader.u8()?;
    let count = usize::from(reader.u8()?);
    validate_count(count)?;
    reader.zeroes(3)?;
    let root_bytes = reader.array()?;
    let _ = decode_root(root_curve, root_bytes)?;
    let mut tuples = Vec::with_capacity(count);
    for _ in 0..count {
        tuples.push(reader.array::<MEMBERSHIP_INPUT_LEN>()?);
    }
    let proof_len = usize::try_from(reader.u32()?).map_err(|_| ResultCode::ResourceLimit)?;
    if proof_len != Fcmp::<Curves>::proof_size(count, usize::from(LAYERS)) {
        return Err(ResultCode::ConsensusInvalid);
    }
    let proof = reader.bytes(proof_len)?;
    reader.finish()?;
    Ok((root_bytes, tuples, proof))
}

/// Prove the SAL half over an existing membership half, once the signable hash exists.
///
/// Request: `schema_u16 || layers_u8 || reserved_u8_zero || signable_hash_32 ||
/// proving_len_u32_le || membership proving request || instance`, the last two verbatim from
/// the membership half. Response: identical in layout to the combined prover's.
#[allow(clippy::too_many_lines)]
pub(crate) fn prove_sal_only(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    let ParsedSplitSal {
        signable_hash,
        proving,
        instance,
    } = parse_split_sal_request(request)?;
    let ParsedMembershipProvingRequest {
        root_bytes,
        witnesses,
    } = parse_membership_proving_request(proving)?;
    let entropy: [u8; 32] = proving[MEMBERSHIP_HEADER_LEN..MEMBERSHIP_PROVE_HEADER_LEN]
        .try_into()
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
    let (instance_root, instance_tuples, membership_bytes) = split_instance_parts(instance)?;
    let count = witnesses.len();
    if instance_root != root_bytes || instance_tuples.len() != count {
        return Err(ResultCode::ConsensusInvalid);
    }

    let rerandomizations = split_rerandomize(proving, &witnesses);
    // Seeded over the whole request: the hash, the witnesses and the instance. No nonce below
    // exists apart from the hash it is challenged under.
    let mut sal_rng = deterministic_rng(SPLIT_SAL_RNG_DOMAIN, &[request]);

    let mut inputs_and_authorizations = Vec::with_capacity(count);
    let mut response_records = Vec::with_capacity(count);
    let mut unique_key_images = BTreeSet::new();
    for (input_index, (witness, (rerandomized, ..))) in
        witnesses.iter().zip(rerandomizations).enumerate()
    {
        let input = rerandomized.input();
        // The tuple the instance proves is the only tuple this opening may sign for.
        if membership_tuple(&input) != instance_tuples[input_index] {
            return Err(ResultCode::ConsensusInvalid);
        }
        let mut pseudo_out_mask_delta = -rerandomized.c_blind();
        let mut rerandomized_y = witness.y - rerandomized.o_blind();
        let opening = OpenedInputTuple::open(&rerandomized, &witness.x, &witness.y)
            .ok_or(ResultCode::ConsensusInvalid)?;
        let (key_image, authorization) =
            SpendAuthAndLinkability::prove(&mut sal_rng, signable_hash, &opening);
        let key_image_bytes = key_image.to_bytes();
        // The membership half published x*I; the opening must reach the same point.
        if key_image_bytes != split_key_image(witness) {
            return Err(ResultCode::InternalLocalStateFailure);
        }
        if !unique_key_images.insert(key_image_bytes) {
            return Err(ResultCode::ConsensusInvalid);
        }
        let pseudo_out = input.C_tilde();
        let o_tilde = input.O_tilde();
        let pseudo_out_mask_delta_bytes = pseudo_out_mask_delta.to_repr();
        let sender_authority = (<Ed25519 as Ciphersuite>::generator() * witness.x).to_bytes();
        let mut rerandomized_y_bytes = rerandomized_y.to_repr();
        let input_index = u32::try_from(input_index).map_err(|_| ResultCode::ResourceLimit)?;
        let sender_disclosure_proof = disclosure::prove_sender(
            &sender_authority,
            &o_tilde,
            &witness.x.to_repr(),
            &rerandomized_y_bytes,
            &signable_hash,
            input_index,
            &entropy,
        )
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
        let sender_disclosure_valid = disclosure::verify_sender(
            &sender_authority,
            &o_tilde,
            &signable_hash,
            input_index,
            &sender_disclosure_proof,
        )
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
        if !sender_disclosure_valid {
            return Err(ResultCode::InternalLocalStateFailure);
        }
        response_records.push(ProvingResponseRecord {
            pseudo_out,
            key_image: key_image_bytes,
            pseudo_out_mask_delta: pseudo_out_mask_delta_bytes,
            sender_authority,
            sender_disclosure_proof,
        });
        pseudo_out_mask_delta.zeroize();
        rerandomized_y.zeroize();
        rerandomized_y_bytes.zeroize();
        inputs_and_authorizations.push((input, authorization));
    }

    let mut encoded = membership_bytes;
    let membership = Fcmp::<Curves>::read(&mut encoded, count, usize::from(LAYERS))
        .map_err(|_| ResultCode::ConsensusInvalid)?;
    if !encoded.is_empty() {
        return Err(ResultCode::ConsensusInvalid);
    }
    let proof = FcmpPlusPlus::new(inputs_and_authorizations, membership);
    let expected_size = FcmpPlusPlus::proof_size(count, usize::from(LAYERS));
    let mut proof_bytes = Vec::with_capacity(expected_size);
    proof
        .write(&mut proof_bytes)
        .map_err(|_| ResultCode::InternalLocalStateFailure)?;
    if proof_bytes.len() != expected_size {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let response = encode_proving_response(&response_records, &proof_bytes)?;
    let verification = verification_request_from_response(root_bytes, signable_hash, &response)?;
    verify(&verification)?;
    Ok(response)
}

#[cfg(test)]
mod tests {

    fn tree_from_leaves(leaf_bytes: &[u8]) -> Vec<u8> {
        let mut state: Option<Vec<u8>> = None;
        for batch in leaf_bytes.chunks(16 * 96) {
            let mut request = Vec::new();
            request.extend_from_slice(&1_u16.to_le_bytes());
            match &state {
                None => request.push(1),
                Some(_) => request.push(0),
            }
            request.push(0);
            if let Some(previous) = &state {
                request.extend_from_slice(previous);
            }
            let count = u32::try_from(batch.len() / 96).expect("batch is bounded");
            request.extend_from_slice(&count.to_le_bytes());
            request.extend_from_slice(batch);
            state = Some(crate::tree::update(&request).expect("tree update").to_vec());
        }
        state.expect("at least one batch")
    }

    fn witness_request(state: &[u8], targets: &[u64], leaf_bytes: &[u8]) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(&1_u16.to_le_bytes());
        request.push(u8::try_from(targets.len()).expect("target count is bounded"));
        request.push(0);
        request.extend_from_slice(state);
        for target in targets {
            request.extend_from_slice(&target.to_le_bytes());
        }
        let count = u32::try_from(leaf_bytes.len() / 96).expect("leaf count is bounded");
        request.extend_from_slice(&count.to_le_bytes());
        request.extend_from_slice(leaf_bytes);
        request
    }

    // A witness is only correct if the prover accepts it against the tree's own root and
    // the resulting proof verifies. Anything weaker passes with a witness built against a
    // root nobody else computes.
    #[test]
    fn tree_witness_yields_a_proof_that_verifies() {
        let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
        let x = EdScalar::from(7_u64);
        let y = EdScalar::from(11_u64);
        let output = FcmpOutput::new(
            (<Ed25519 as Ciphersuite>::generator() * x) + (monero_t() * y),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(13_u64),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(17_u64),
        )
        .expect("test output is nonidentity");

        // 45 leaves spans two leaf branches, so the level-1 branch has a real sibling
        // rather than only padding.
        let mut leaves = vec![output];
        while leaves.len() < 45 {
            leaves.push(random_output(&mut rng));
        }
        let mut leaf_bytes = Vec::new();
        for leaf in &leaves {
            append_output(&mut leaf_bytes, leaf);
        }

        let state = tree_from_leaves(&leaf_bytes);
        let response = crate::tree::witness(&witness_request(&state, &[0], &leaf_bytes))
            .expect("witness must be produced");

        assert_eq!(u16::from_le_bytes([response[0], response[1]]), 1);
        assert_eq!(response[2], LAYERS);
        assert_eq!(response[3], ROOT_CURVE_HELIOS);
        assert_eq!(u64::from_le_bytes(response[4..12].try_into().unwrap()), 45);
        assert_eq!(response[44], 1);
        assert_eq!(&response[45..48], &[0, 0, 0]);

        let root_bytes: [u8; 32] = response[12..44].try_into().expect("root is 32 bytes");
        let record = &response[48..];
        assert_eq!(record.len(), 100 + (96 * 38) + (2304 + 3648));

        let signable_hash = [0x51; 32];
        let mut request = Vec::new();
        request.extend_from_slice(&SCHEMA.to_le_bytes());
        request.push(LAYERS);
        request.push(ROOT_CURVE_HELIOS);
        request.push(1);
        request.extend_from_slice(&[0; 3]);
        request.extend_from_slice(&root_bytes);
        request.extend_from_slice(&signable_hash);
        request.extend_from_slice(&[0x73; 32]);
        append_scalar::<Ed25519>(&mut request, x);
        append_scalar::<Ed25519>(&mut request, y);
        request.extend_from_slice(record);

        let response = prove(&request).expect("witness must drive a real proof");
        let verification = verification_request_from_response(root_bytes, signable_hash, &response)
            .expect("verification request");
        verify(&verification).expect("a proof over a real witness must verify");
    }

    // Pseudo-outputs must not depend on the signable hash that covers them: two hashes
    // give the same pseudo-outputs and key images, each proof verifying under its own.
    #[test]
    fn pseudo_outputs_do_not_depend_on_the_signable_hash() {
        let mut rng = ChaCha20Rng::from_seed([0x63; 32]);
        let x = EdScalar::from(23_u64);
        let y = EdScalar::from(29_u64);
        let output = FcmpOutput::new(
            (<Ed25519 as Ciphersuite>::generator() * x) + (monero_t() * y),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(31_u64),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(37_u64),
        )
        .expect("test output is nonidentity");

        let mut leaves = vec![output];
        while leaves.len() < 45 {
            leaves.push(random_output(&mut rng));
        }
        let mut leaf_bytes = Vec::new();
        for leaf in &leaves {
            append_output(&mut leaf_bytes, leaf);
        }
        let state = tree_from_leaves(&leaf_bytes);
        let witness_response = crate::tree::witness(&witness_request(&state, &[0], &leaf_bytes))
            .expect("witness must be produced");
        let root_bytes: [u8; 32] = witness_response[12..44]
            .try_into()
            .expect("root is 32 bytes");
        let record = &witness_response[48..];

        let build = |signable_hash: [u8; 32]| {
            let mut request = Vec::new();
            request.extend_from_slice(&SCHEMA.to_le_bytes());
            request.push(LAYERS);
            request.push(ROOT_CURVE_HELIOS);
            request.push(1);
            request.extend_from_slice(&[0; 3]);
            request.extend_from_slice(&root_bytes);
            request.extend_from_slice(&signable_hash);
            request.extend_from_slice(&[0x4d; 32]);
            append_scalar::<Ed25519>(&mut request, x);
            append_scalar::<Ed25519>(&mut request, y);
            request.extend_from_slice(record);
            request
        };

        let first_hash = [0x01; 32];
        let second_hash = [0x02; 32];
        let first = prove(&build(first_hash)).expect("first proof");
        let second = prove(&build(second_hash)).expect("second proof");

        // The construction record leads the response: pseudo-output then key image.
        assert_eq!(&first[4..68], &second[4..68]);

        // Each proof must still be bound to the hash it was made under.
        verify(
            &verification_request_from_response(root_bytes, first_hash, &first)
                .expect("verification request"),
        )
        .expect("first proof verifies under its own hash");
        verify(
            &verification_request_from_response(root_bytes, second_hash, &second)
                .expect("verification request"),
        )
        .expect("second proof verifies under its own hash");
        assert!(verify(
            &verification_request_from_response(root_bytes, second_hash, &first)
                .expect("verification request"),
        )
        .is_err());
    }

    // Two passes under one entropy share pseudo-outputs, but a reused SAL nonce across
    // them would leak the spend key.
    #[test]
    fn sal_nonces_are_not_reused_across_signable_hashes() {
        // Per-input serialized layout: O~, I~, R, then P, A, B, R_O, R_P, R_L, then
        // s_alpha, s_beta, s_delta, s_y, s_z, s_r_p.
        const SAL_COMMITMENTS: core::ops::Range<usize> = 96..288;
        const S_BETA: usize = 320;
        const S_Z: usize = 416;

        let mut rng = ChaCha20Rng::from_seed([0x5b; 32]);
        let x = EdScalar::from(41_u64);
        let y = EdScalar::from(43_u64);
        let output = FcmpOutput::new(
            (<Ed25519 as Ciphersuite>::generator() * x) + (monero_t() * y),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(47_u64),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(53_u64),
        )
        .expect("test output is nonidentity");

        let mut leaves = vec![output];
        while leaves.len() < 45 {
            leaves.push(random_output(&mut rng));
        }
        let mut leaf_bytes = Vec::new();
        for leaf in &leaves {
            append_output(&mut leaf_bytes, leaf);
        }
        let state = tree_from_leaves(&leaf_bytes);
        let witness_response = crate::tree::witness(&witness_request(&state, &[0], &leaf_bytes))
            .expect("witness must be produced");
        let root_bytes: [u8; 32] = witness_response[12..44]
            .try_into()
            .expect("root is 32 bytes");
        let record = &witness_response[48..];

        let build = |signable_hash: [u8; 32]| {
            let mut request = Vec::new();
            request.extend_from_slice(&SCHEMA.to_le_bytes());
            request.push(LAYERS);
            request.push(ROOT_CURVE_HELIOS);
            request.push(1);
            request.extend_from_slice(&[0; 3]);
            request.extend_from_slice(&root_bytes);
            request.extend_from_slice(&signable_hash);
            // One entropy across both passes: that is what the caller does.
            request.extend_from_slice(&[0x5c; 32]);
            append_scalar::<Ed25519>(&mut request, x);
            append_scalar::<Ed25519>(&mut request, y);
            request.extend_from_slice(record);
            request
        };

        let first_hash = [0x11; 32];
        let second_hash = [0x22; 32];
        let first = prove(&build(first_hash)).expect("first proof");
        let second = prove(&build(second_hash)).expect("second proof");

        // The prefix the hash covers must still be reproducible, or the caller cannot build
        // a payload at all.
        assert_eq!(&first[4..68], &second[4..68]);

        // One input: the response is the header, one construction record, the proof length,
        // then the proof.
        let proof_at = RESPONSE_HEADER_LEN + RESPONSE_RECORD_LEN + 4;
        let first_sal = &first[proof_at..];
        let second_sal = &second[proof_at..];

        // Every SAL commitment is a function of the nonces and the opening alone, never of
        // the challenge. Two passes over one opening that share a nonce therefore publish
        // byte-identical commitments.
        assert_ne!(
            &first_sal[SAL_COMMITMENTS], &second_sal[SAL_COMMITMENTS],
            "the two passes published the same SAL commitments, so a nonce was reused"
        );

        // The recovery an auditor performed: with beta and r_z reused, the differences of
        // the published responses are (e1-e2)*r_i and (e1-e2)*x*r_i, whose quotient is the
        // spend key. It needs no secret and no transcript, only the two proofs.
        let delta = |at: usize| -> EdScalar {
            let left = decode_scalar::<Ed25519>(
                first_sal[at..at + 32]
                    .try_into()
                    .expect("SAL response is 32 bytes"),
            )
            .expect("canonical SAL response");
            let right = decode_scalar::<Ed25519>(
                second_sal[at..at + 32]
                    .try_into()
                    .expect("SAL response is 32 bytes"),
            )
            .expect("canonical SAL response");
            left - right
        };
        let delta_beta = delta(S_BETA);
        let delta_z = delta(S_Z);
        let inverse = Option::<EdScalar>::from(delta_beta.invert())
            .expect("independent responses differ, so the difference is invertible");
        let recovered = delta_z * inverse;
        let authority = decode_group::<Ed25519>(
            first[100..132]
                .try_into()
                .expect("sender authority is 32 bytes"),
        )
        .expect("the response publishes a canonical authority");
        assert_eq!(
            authority,
            <Ed25519 as Ciphersuite>::generator() * x,
            "the response must publish G*x, or this test recovers nothing"
        );
        assert_ne!(
            <Ed25519 as Ciphersuite>::generator() * recovered,
            authority,
            "the spend key was recovered from the two published proofs"
        );

        // Both proofs must still be bound to the hash each was made under.
        verify(
            &verification_request_from_response(root_bytes, first_hash, &first)
                .expect("verification request"),
        )
        .expect("first proof verifies under its own hash");
        verify(
            &verification_request_from_response(root_bytes, second_hash, &second)
                .expect("verification request"),
        )
        .expect("second proof verifies under its own hash");
    }

    // Two leaves of a deep tree, reaching nonzero branch indexes and a partial leaf branch
    // that shallower trees never exercise.
    #[test]
    fn tree_witness_proves_a_full_and_a_partial_branch_together() {
        let mut rng = ChaCha20Rng::from_seed([0x19; 32]);
        let keys = [
            (EdScalar::from(29_u64), EdScalar::from(31_u64)),
            (EdScalar::from(67_u64), EdScalar::from(71_u64)),
        ];
        let outputs: Vec<FcmpOutput> = keys
            .iter()
            .enumerate()
            .map(|(index, (x, y))| {
                FcmpOutput::new(
                    (<Ed25519 as Ciphersuite>::generator() * *x) + (monero_t() * *y),
                    <Ed25519 as Ciphersuite>::generator() * EdScalar::from(37_u64 + index as u64),
                    <Ed25519 as Ciphersuite>::generator() * EdScalar::from(41_u64 + index as u64),
                )
                .expect("test output is nonidentity")
            })
            .collect();

        // 700 leaves fill 18 level-0 branches and leave a 19th holding 16, so target 0
        // sits under a full 18-wide level-1 branch and target 699 under branch 1.
        let mut leaves = vec![outputs[0]];
        while leaves.len() < 699 {
            leaves.push(random_output(&mut rng));
        }
        leaves.push(outputs[1]);
        let mut leaf_bytes = Vec::new();
        for leaf in &leaves {
            append_output(&mut leaf_bytes, leaf);
        }

        let state = tree_from_leaves(&leaf_bytes);
        let response = crate::tree::witness(&witness_request(&state, &[0, 699], &leaf_bytes))
            .expect("witness must be produced");
        assert_eq!(response[44], 2);

        let root_bytes: [u8; 32] = response[12..44].try_into().expect("root is 32 bytes");
        let records = &response[48..];
        let branches = (4 * C2_BRANCH_LEN * 32) + (3 * C1_BRANCH_LEN * 32);
        let first_len = 100 + (C1_BRANCH_LEN * 96) + branches;
        let second_len = 100 + (16 * 96) + branches;
        assert_eq!(records.len(), first_len + second_len);
        assert_eq!(records[96], u8::try_from(C1_BRANCH_LEN).unwrap());
        assert_eq!(records[first_len + 96], 16);

        // Every Helios generator position carries a real child for the first target,
        // so a wrong generator anywhere in the branch changes the proven root.
        let level_one = &records[100 + (C1_BRANCH_LEN * 96)..][..C2_BRANCH_LEN * 32];
        for scalar in level_one.chunks_exact(32) {
            assert!(scalar.iter().any(|byte| *byte != 0));
        }

        let signable_hash = [0x62; 32];
        let mut request = Vec::new();
        request.extend_from_slice(&SCHEMA.to_le_bytes());
        request.push(LAYERS);
        request.push(ROOT_CURVE_HELIOS);
        request.push(2);
        request.extend_from_slice(&[0; 3]);
        request.extend_from_slice(&root_bytes);
        request.extend_from_slice(&signable_hash);
        request.extend_from_slice(&[0x73; 32]);
        append_scalar::<Ed25519>(&mut request, keys[0].0);
        append_scalar::<Ed25519>(&mut request, keys[0].1);
        request.extend_from_slice(&records[..first_len]);
        append_scalar::<Ed25519>(&mut request, keys[1].0);
        append_scalar::<Ed25519>(&mut request, keys[1].1);
        request.extend_from_slice(&records[first_len..]);

        let response = prove(&request).expect("deep-tree witness must drive a proof");
        let verification = verification_request_from_response(root_bytes, signable_hash, &response)
            .expect("verification request");
        verify(&verification).expect("a deep-tree proof must verify");
    }

    // The tree root is the only value binding a witness to the chain, so a witness taken
    // against a different tree must not verify against this one.
    #[test]
    fn tree_witness_is_bound_to_its_own_root() {
        let mut rng = ChaCha20Rng::from_seed([0x24; 32]);
        let x = EdScalar::from(5_u64);
        let y = EdScalar::from(9_u64);
        let output = FcmpOutput::new(
            (<Ed25519 as Ciphersuite>::generator() * x) + (monero_t() * y),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(19_u64),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(23_u64),
        )
        .expect("test output is nonidentity");
        let mut leaves = vec![output];
        while leaves.len() < 12 {
            leaves.push(random_output(&mut rng));
        }
        let mut leaf_bytes = Vec::new();
        for leaf in &leaves {
            append_output(&mut leaf_bytes, leaf);
        }

        let state = tree_from_leaves(&leaf_bytes);
        let response = crate::tree::witness(&witness_request(&state, &[0], &leaf_bytes))
            .expect("witness must be produced");
        let record = &response[48..];

        let signable_hash = [0x33; 32];
        let mut foreign_root = [0_u8; 32];
        foreign_root.copy_from_slice(
            <Helios as Ciphersuite>::G::to_bytes(
                &(*HELIOS_HASH_INIT * <Helios as Ciphersuite>::F::from(3_u64)),
            )
            .as_ref(),
        );

        let mut request = Vec::new();
        request.extend_from_slice(&SCHEMA.to_le_bytes());
        request.push(LAYERS);
        request.push(ROOT_CURVE_HELIOS);
        request.push(1);
        request.extend_from_slice(&[0; 3]);
        request.extend_from_slice(&foreign_root);
        request.extend_from_slice(&signable_hash);
        request.extend_from_slice(&[0x73; 32]);
        append_scalar::<Ed25519>(&mut request, x);
        append_scalar::<Ed25519>(&mut request, y);
        request.extend_from_slice(record);

        // The foreign root must be a decodable point, so the rejection is the membership
        // check inside the prover's self-verification and not a parse failure.
        assert!(decode_root(ROOT_CURVE_HELIOS, foreign_root).is_ok());
        assert_eq!(prove(&request), Err(ResultCode::ConsensusInvalid));
    }
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        sync::OnceLock,
    };

    use ciphersuite::group::ff::Field as _;
    use ec_divisors::DivisorCurve as _;
    use rand_core::RngCore as _;

    use super::*;

    fn hash_values<C: Ciphersuite>(
        initial: C::G,
        values: &[C::F],
        generators: &generalized_bulletproofs::Generators<C>,
    ) -> C::G {
        values
            .iter()
            .zip(generators.g_bold_slice())
            .fold(initial, |sum, (scalar, generator)| {
                sum + (*generator * *scalar)
            })
    }

    fn append_group<C>(bytes: &mut Vec<u8>, point: C::G)
    where
        C: Ciphersuite,
        C::G: GroupEncoding<Repr = [u8; 32]>,
    {
        bytes.extend_from_slice(&point.to_bytes());
    }

    fn append_scalar<C: Ciphersuite>(bytes: &mut Vec<u8>, scalar: C::F) {
        bytes.extend_from_slice(scalar.to_repr().as_ref());
    }

    fn append_output(bytes: &mut Vec<u8>, output: &FcmpOutput) {
        append_group::<Ed25519>(bytes, output.O());
        append_group::<Ed25519>(bytes, output.I());
        append_group::<Ed25519>(bytes, output.C());
    }

    fn random_output(rng: &mut ChaCha20Rng) -> FcmpOutput {
        FcmpOutput::new(
            EdPoint::random(&mut *rng),
            EdPoint::random(&mut *rng),
            EdPoint::random(&mut *rng),
        )
        .expect("random output is nonidentity")
    }

    /// A synthetic eight-layer witness: the root the leaf proves to, and the witness record the
    /// request formats share. Building the tree by hand keeps this independent of `tree`.
    fn synthetic_witness(seed: [u8; 32], x: EdScalar, y: EdScalar) -> ([u8; 32], Vec<u8>) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let output = FcmpOutput::new(
            (<Ed25519 as Ciphersuite>::generator() * x) + (monero_t() * y),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(13_u64),
            <Ed25519 as Ciphersuite>::generator() * EdScalar::from(17_u64),
        )
        .expect("test output is nonidentity");
        let mut leaves = vec![output];
        while leaves.len() < C1_BRANCH_LEN {
            leaves.push(random_output(&mut rng));
        }

        let mut leaf_values = Vec::with_capacity(C1_BRANCH_LEN * 6);
        for leaf in &leaves {
            for point in [leaf.O(), leaf.I(), leaf.C()] {
                let (x_coordinate, y_coordinate) = EdPoint::to_xy(point).expect("nonidentity");
                leaf_values.extend_from_slice(&[x_coordinate, y_coordinate]);
            }
        }
        let mut c1_hash = hash_values::<Selene>(
            *SELENE_HASH_INIT,
            &leaf_values,
            &SELENE_FCMP_GENERATORS.generators,
        );
        let mut c2_layers = Vec::with_capacity(C2_LAYER_COUNT);
        let mut c1_layers = Vec::with_capacity(C1_LAYER_COUNT);
        let mut root = None;
        for layer in 0..C2_LAYER_COUNT {
            let mut c2 = vec![
                <Selene as Ciphersuite>::G::to_xy(c1_hash)
                    .expect("C1 hash is nonidentity")
                    .0,
            ];
            while c2.len() < C2_BRANCH_LEN {
                c2.push(C2Scalar::random(&mut rng));
            }
            let c2_hash =
                hash_values::<Helios>(*HELIOS_HASH_INIT, &c2, &HELIOS_FCMP_GENERATORS.generators);
            c2_layers.push(c2);
            if layer == C2_LAYER_COUNT - 1 {
                root = Some(c2_hash);
                break;
            }
            let mut c1 = vec![
                <Helios as Ciphersuite>::G::to_xy(c2_hash)
                    .expect("C2 hash is nonidentity")
                    .0,
            ];
            while c1.len() < C1_BRANCH_LEN {
                c1.push(C1Scalar::random(&mut rng));
            }
            c1_hash =
                hash_values::<Selene>(*SELENE_HASH_INIT, &c1, &SELENE_FCMP_GENERATORS.generators);
            c1_layers.push(c1);
        }
        let root = root.expect("eight layers end on Helios");

        let mut record = Vec::new();
        append_scalar::<Ed25519>(&mut record, x);
        append_scalar::<Ed25519>(&mut record, y);
        append_output(&mut record, &output);
        record.push(u8::try_from(leaves.len()).expect("leaf count is bounded"));
        record.extend_from_slice(&[0; 3]);
        for leaf in leaves {
            append_output(&mut record, &leaf);
        }
        for branch in c2_layers {
            for scalar in branch {
                append_scalar::<Helios>(&mut record, scalar);
            }
        }
        for branch in c1_layers {
            for scalar in branch {
                append_scalar::<Selene>(&mut record, scalar);
            }
        }
        (root.to_bytes(), record)
    }

    fn real_proving_request() -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let (root_bytes, record) =
            synthetic_witness([0x42; 32], EdScalar::from(7_u64), EdScalar::from(11_u64));
        let signable_hash = [0x51; 32];
        let mut request = Vec::new();
        request.extend_from_slice(&SCHEMA.to_le_bytes());
        request.push(LAYERS);
        request.push(ROOT_CURVE_HELIOS);
        request.push(1);
        request.extend_from_slice(&[0; 3]);
        request.extend_from_slice(&root_bytes);
        request.extend_from_slice(&signable_hash);
        request.extend_from_slice(&[0x73; 32]);
        request.extend_from_slice(&record);
        (request, root_bytes, signable_hash)
    }

    /// A membership-only proving request over one synthetic witness. Same header as the spend
    /// request through the root, then entropy, then the witness records. No signable hash,
    /// because nothing here is challenged under one.
    fn membership_proving_request(root_bytes: [u8; 32], records: &[&[u8]]) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(&SCHEMA.to_le_bytes());
        request.push(LAYERS);
        request.push(ROOT_CURVE_HELIOS);
        request.push(u8::try_from(records.len()).expect("test count is bounded"));
        request.extend_from_slice(&[0; 3]);
        request.extend_from_slice(&root_bytes);
        request.extend_from_slice(&[0x9e; 32]);
        for record in records {
            request.extend_from_slice(record);
        }
        request
    }

    fn batch_request(requests: &[&[u8]], total_inputs: u8) -> Vec<u8> {
        let mut batch = Vec::new();
        batch.extend_from_slice(&SCHEMA.to_le_bytes());
        batch.push(LAYERS);
        batch.push(u8::try_from(requests.len()).expect("test batch is bounded"));
        batch.push(total_inputs);
        batch.extend_from_slice(&[0; 2]);
        for request in requests {
            batch.extend_from_slice(
                &u32::try_from(request.len())
                    .expect("test request is bounded")
                    .to_le_bytes(),
            );
            batch.extend_from_slice(request);
        }
        batch
    }

    #[test]
    fn malformed_proof_frames_fail_before_verification() {
        assert_eq!(verify(&[1]), Err(ResultCode::BadLength));
        assert_eq!(verify_batch(&[1], 1), Err(ResultCode::BadLength));
        assert_eq!(
            parse_proving_request(&[1]).err(),
            Some(ResultCode::BadLength)
        );
    }

    #[test]
    fn proving_response_keeps_wallet_metadata_out_of_verification() {
        let record = ProvingResponseRecord {
            pseudo_out: [0x11; 32],
            key_image: [0x22; 32],
            pseudo_out_mask_delta: [0x33; 32],
            sender_authority: [0x44; 32],
            sender_disclosure_proof: [0x55; 128],
        };
        let proof = [0x66; 3];
        let response =
            encode_proving_response(&[record], &proof).expect("construction response must encode");
        assert_eq!(
            response.len(),
            RESPONSE_HEADER_LEN + RESPONSE_RECORD_LEN + 4 + 3
        );
        assert_eq!(&response[68..100], &[0x33; 32]);
        assert_eq!(&response[100..132], &[0x44; 32]);
        assert_eq!(&response[132..260], &[0x55; 128]);

        let request = verification_request_from_response([0x77; 32], [0x88; 32], &response)
            .expect("construction response must project to verifier request");
        assert_eq!(request.len(), VERIFY_HEADER_LEN + 64 + 4 + 3);
        assert_eq!(
            &request[VERIFY_HEADER_LEN..VERIFY_HEADER_LEN + 32],
            &[0x11; 32]
        );
        assert_eq!(
            &request[VERIFY_HEADER_LEN + 32..VERIFY_HEADER_LEN + 64],
            &[0x22; 32]
        );
        assert_eq!(
            &request[VERIFY_HEADER_LEN + 64..VERIFY_HEADER_LEN + 68],
            &3_u32.to_le_bytes()
        );
        assert_eq!(&request[VERIFY_HEADER_LEN + 68..], &proof);
    }

    fn random_tuple(rng: &mut ChaCha20Rng) -> [u8; MEMBERSHIP_INPUT_LEN] {
        let mut tuple = [0_u8; MEMBERSHIP_INPUT_LEN];
        for slot in 0..4 {
            tuple[slot * 32..(slot + 1) * 32]
                .copy_from_slice(&EdPoint::random(&mut *rng).to_bytes());
        }
        tuple
    }

    fn random_membership_proof(rng: &mut ChaCha20Rng, count: usize) -> Vec<u8> {
        let mut proof = vec![0_u8; Fcmp::<Curves>::proof_size(count, usize::from(LAYERS))];
        rng.fill_bytes(&mut proof);
        proof
    }

    fn membership_request_bytes(
        layers: u8,
        root_curve: u8,
        count: u8,
        root: [u8; 32],
        tuples: &[[u8; MEMBERSHIP_INPUT_LEN]],
        proof: &[u8],
    ) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(&SCHEMA.to_le_bytes());
        request.push(layers);
        request.push(root_curve);
        request.push(count);
        request.extend_from_slice(&[0; 3]);
        request.extend_from_slice(&root);
        for tuple in tuples {
            request.extend_from_slice(tuple);
        }
        request.extend_from_slice(
            &u32::try_from(proof.len())
                .expect("test proof is bounded")
                .to_le_bytes(),
        );
        request.extend_from_slice(proof);
        request
    }

    fn rejects_without_unwinding<T>(
        label: &str,
        entry_point: &str,
        call: impl FnOnce() -> Result<T, ResultCode>,
    ) {
        let Ok(result) = catch_unwind(AssertUnwindSafe(call)) else {
            panic!("{label} unwound out of the membership {entry_point}");
        };
        assert!(result.is_err(), "{label} was accepted by the {entry_point}");
    }

    /// One 32-byte slot of the first input tuple in an encoded membership request.
    fn tuple_at(request: &[u8], slot: usize) -> [u8; 32] {
        request[MEMBERSHIP_HEADER_LEN + (slot * 32)..][..32]
            .try_into()
            .expect("a tuple slot is 32 bytes")
    }

    fn helios_root(scale: u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(
            <Helios as Ciphersuite>::G::to_bytes(
                &(*HELIOS_HASH_INIT * <Helios as Ciphersuite>::F::from(scale)),
            )
            .as_ref(),
        );
        bytes
    }

    fn selene_root(scale: u64) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(
            <Selene as Ciphersuite>::G::to_bytes(
                &(*SELENE_HASH_INIT * <Selene as Ciphersuite>::F::from(scale)),
            )
            .as_ref(),
        );
        bytes
    }

    const MEMBERSHIP_X: u64 = 19;
    const MEMBERSHIP_Y: u64 = 23;

    /// One real eight-layer membership instance, shared because proving one is the dominant
    /// cost in this module: the instance, the root it proves to, and the witness record.
    fn shared_membership_instance() -> &'static (Vec<u8>, [u8; 32], Vec<u8>) {
        static INSTANCE: OnceLock<(Vec<u8>, [u8; 32], Vec<u8>)> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            let (root_bytes, record) = synthetic_witness(
                [0x24; 32],
                EdScalar::from(MEMBERSHIP_X),
                EdScalar::from(MEMBERSHIP_Y),
            );
            let request = membership_proving_request(root_bytes, &[&record]);
            let instance =
                prove_membership(&request).expect("membership instance must be produced");
            (instance, root_bytes, record)
        })
    }

    fn instance_tuple(instance: &[u8]) -> [u8; MEMBERSHIP_INPUT_LEN] {
        instance[MEMBERSHIP_HEADER_LEN..][..MEMBERSHIP_INPUT_LEN]
            .try_into()
            .expect("an input tuple is a fixed width")
    }

    // `i_blind` reports -r_i; the exported r_i must have the sign used in
    // L = x*I~ - (x*r_i)*U. Checked against a key image computed independently.
    #[test]
    fn exported_i_blind_reconstructs_the_true_key_image() {
        let (root_bytes, record) = synthetic_witness(
            [0x24; 32],
            EdScalar::from(MEMBERSHIP_X),
            EdScalar::from(MEMBERSHIP_Y),
        );
        let request = membership_proving_request(root_bytes, &[&record]);
        let (instance, secrets) =
            prove_membership_with_secrets(&request).expect("membership instance is produced");
        assert_eq!(secrets.len(), 1);

        let tuple = instance_tuple(&instance);
        let i_tilde = decode_group::<Ed25519>(tuple[32..64].try_into().expect("I~ is 32 bytes"))
            .expect("I~ is canonical");
        let r_i = decode_scalar::<Ed25519>(secrets[0].i_blind).expect("r_i is canonical");
        let x = EdScalar::from(MEMBERSHIP_X);
        let u = EdwardsPoint((*FCMP_PLUS_PLUS_U).into());

        // synthetic_witness builds the leaf with I = G*13.
        let key_image = <Ed25519 as Ciphersuite>::generator() * (x * EdScalar::from(13_u64));
        assert_eq!((i_tilde * x) - (u * (x * r_i)), key_image);
        // The opposite sign does not, which is what makes the export load-bearing.
        assert_ne!((i_tilde * x) + (u * (x * r_i)), key_image);
    }

    fn instance_proof(instance: &[u8]) -> &[u8] {
        &instance[MEMBERSHIP_HEADER_LEN + MEMBERSHIP_INPUT_LEN + 4..]
    }

    // The whole point of the membership shape is that the spend authorization never runs, so
    // the instance must prove and verify with no SAL, no signable hash, and no key image
    // anywhere in its bytes.
    #[test]
    fn membership_instance_proves_and_verifies_without_sal() {
        let x = EdScalar::from(MEMBERSHIP_X);
        let y = EdScalar::from(MEMBERSHIP_Y);
        let (instance, root_bytes, record) = shared_membership_instance();
        let instance = instance.clone();
        let root_bytes = *root_bytes;
        let request = membership_proving_request(root_bytes, &[record]);

        // Exact size: header, one input tuple, the length, and a bare FCMP. There is no room
        // for a key image or a SAL, and the gap to the fused proof is exactly those fifteen
        // points.
        let membership_proof_len = Fcmp::<Curves>::proof_size(1, usize::from(LAYERS));
        assert_eq!(
            instance.len(),
            MEMBERSHIP_HEADER_LEN + MEMBERSHIP_INPUT_LEN + 4 + membership_proof_len
        );
        assert_eq!(
            FcmpPlusPlus::proof_size(1, usize::from(LAYERS)) - membership_proof_len,
            15 * 32
        );

        verify_membership(&instance).expect("the instance must verify");
        verify_membership_batch(&batch_request(&[&instance], 1), 1)
            .expect("a one-item batch equals a single verification");
        verify_membership_batch(&batch_request(&[&instance, &instance], 2), 2)
            .expect("a shared batch must verify");

        // The prover holds everything a key image needs and still publishes none. Recomputing
        // it from the same rerandomization is the direct check that it is absent.
        let mut rng = deterministic_rng(MEMBERSHIP_RNG_DOMAIN, &[request.as_slice()]);
        let output = decode_output(&mut Reader::new(&record[64..])).expect("witness names a leaf");
        let (rerandomized, ..) = rerandomize_with_nonzero_blinds(&mut rng, &output);
        assert_eq!(
            &instance[MEMBERSHIP_HEADER_LEN..][..32],
            &rerandomized.input().O_tilde()
        );
        let opening =
            OpenedInputTuple::open(&rerandomized, &x, &y).expect("the witness opens its own tuple");
        let (key_image, _authorization) = SpendAuthAndLinkability::prove(
            &mut ChaCha20Rng::from_seed([0x31; 32]),
            [0x00; 32],
            &opening,
        );
        let key_image_bytes = key_image.to_bytes();
        assert!(
            !instance
                .windows(32)
                .any(|window| window == key_image_bytes.as_slice()),
            "the instance published the spend key image"
        );

        // The two request shapes must stay distinct in both directions, or a vote and a spend
        // could be fed to each other's verifier.
        assert!(parse_verification_request(&instance).is_err());
        let spend = encode_verification_request(
            root_bytes,
            [0x51; 32],
            &[tuple_at(&instance, 3)],
            &[tuple_at(&instance, 0)],
            &vec![0_u8; FcmpPlusPlus::proof_size(1, usize::from(LAYERS))],
        )
        .expect("a spend-shaped request encodes");
        assert!(parse_membership_request(&spend).is_err());

        let mut malleated = instance;
        *malleated.last_mut().expect("the instance is nonempty") ^= 1;
        assert_eq!(
            verify_membership(&malleated),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    // `Fcmp::verify` panics rather than errors when the tree root's curve disagrees with the
    // layer count's parity. The panic sits past the commitment reads, so only a structurally
    // valid proof reaches it: a garbage proof errors out first and would prove nothing here.
    #[test]
    fn membership_verification_pins_the_layer_count_and_root_curve() {
        let (instance, _root_bytes, _record) = shared_membership_instance();
        let tuple = instance_tuple(instance);
        let proof = instance_proof(instance);

        // The pinned pair verifies, so the rejections below are the pin itself and not a shared
        // parse failure that would pass whatever the pin did.
        verify_membership(instance).expect("the pinned pair must verify");

        let wrong_curve = membership_request_bytes(LAYERS, 1, 1, selene_root(5), &[tuple], proof);
        assert_eq!(
            catch_unwind(AssertUnwindSafe(|| verify_membership(&wrong_curve))).ok(),
            Some(Err(ResultCode::UnsupportedFormat)),
            "a Selene root reached Fcmp::verify at an even layer count"
        );

        for layers in [0_u8, 1, 7, 9, 16, 255] {
            let wrong_layers = membership_request_bytes(
                layers,
                ROOT_CURVE_HELIOS,
                1,
                helios_root(5),
                &[tuple],
                proof,
            );
            assert_eq!(
                catch_unwind(AssertUnwindSafe(|| verify_membership(&wrong_layers))).ok(),
                Some(Err(ResultCode::UnsupportedFormat)),
                "layer count {layers} reached the verifier"
            );
        }

        // The same root byte on the proving side, where the prover's own self-verification is
        // what would reach the panic.
        let (root_bytes, record) = synthetic_witness(
            [0x24; 32],
            EdScalar::from(MEMBERSHIP_X),
            EdScalar::from(MEMBERSHIP_Y),
        );
        let mut wrong_curve_proving = membership_proving_request(root_bytes, &[&record]);
        wrong_curve_proving[3] = 1;
        assert_eq!(
            catch_unwind(AssertUnwindSafe(|| prove_membership(&wrong_curve_proving))).ok(),
            Some(Err(ResultCode::UnsupportedFormat)),
            "a Selene root reached the prover's self-verification"
        );
    }

    // The vote path is P2P-reachable, so an unwind out of the verifier is a denial of service
    // and not merely a wrong answer. Every malformed shape must come back as an error.
    #[test]
    fn malformed_membership_requests_error_instead_of_unwinding() {
        let mut rng = ChaCha20Rng::from_seed([0xc3; 32]);
        let tuple = random_tuple(&mut rng);
        let proof = random_membership_proof(&mut rng, 1);
        let root = helios_root(5);
        let well_formed =
            membership_request_bytes(LAYERS, ROOT_CURVE_HELIOS, 1, root, &[tuple], &proof);

        let mut identity_tuple = tuple;
        identity_tuple[..32].copy_from_slice(&EdPoint::identity().to_bytes());
        let mut nonzero_padding = well_formed.clone();
        nonzero_padding[5] = 1;
        let mut truncated_proof = well_formed.clone();
        truncated_proof.truncate(truncated_proof.len() - 1);
        let mut trailing = well_formed.clone();
        trailing.push(0);
        let mut oversized_length = well_formed.clone();
        oversized_length[MEMBERSHIP_HEADER_LEN + MEMBERSHIP_INPUT_LEN..][..4]
            .copy_from_slice(&u32::MAX.to_le_bytes());

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("one byte", vec![1]),
            ("header only", well_formed[..MEMBERSHIP_HEADER_LEN].to_vec()),
            (
                "zero inputs",
                membership_request_bytes(LAYERS, ROOT_CURVE_HELIOS, 0, root, &[], &proof),
            ),
            (
                "more inputs than the bound",
                membership_request_bytes(LAYERS, ROOT_CURVE_HELIOS, 17, root, &[tuple], &proof),
            ),
            (
                "count disagrees with the tuples present",
                membership_request_bytes(LAYERS, ROOT_CURVE_HELIOS, 2, root, &[tuple], &proof),
            ),
            (
                "identity in the input tuple",
                membership_request_bytes(
                    LAYERS,
                    ROOT_CURVE_HELIOS,
                    1,
                    root,
                    &[identity_tuple],
                    &proof,
                ),
            ),
            (
                "identity root",
                membership_request_bytes(LAYERS, ROOT_CURVE_HELIOS, 1, [0; 32], &[tuple], &proof),
            ),
            (
                "proof shorter than the layer count requires",
                membership_request_bytes(
                    LAYERS,
                    ROOT_CURVE_HELIOS,
                    1,
                    root,
                    &[tuple],
                    &proof[..proof.len() - 32],
                ),
            ),
            ("nonzero padding", nonzero_padding),
            ("truncated proof", truncated_proof),
            ("trailing bytes", trailing),
            ("proof length beyond the buffer", oversized_length),
            ("a spend request fed to the membership decoder", {
                let (spend, _, _) = real_proving_request();
                spend
            }),
            // The one case that runs the whole circuit rather than failing at the decoder: a
            // real proof against a root it was not built for.
            ("a real proof under a foreign root", {
                let (instance, _, _) = shared_membership_instance();
                membership_request_bytes(
                    LAYERS,
                    ROOT_CURVE_HELIOS,
                    1,
                    helios_root(9),
                    &[instance_tuple(instance)],
                    instance_proof(instance),
                )
            }),
        ];

        for (label, request) in cases {
            rejects_without_unwinding(label, "verifier", || verify_membership(&request));
            rejects_without_unwinding(label, "batch verifier", || {
                verify_membership_batch(&request, 1)
            });
            rejects_without_unwinding(label, "prover", || prove_membership(&request));
        }
    }

    const SPLIT_X: u64 = 61;
    const SPLIT_Y: u64 = 67;

    fn split_sal_request(signable_hash: [u8; 32], proving: &[u8], instance: &[u8]) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(&SCHEMA.to_le_bytes());
        request.push(LAYERS);
        request.push(0);
        request.extend_from_slice(&signable_hash);
        request.extend_from_slice(
            &u32::try_from(proving.len())
                .expect("test request is bounded")
                .to_le_bytes(),
        );
        request.extend_from_slice(proving);
        request.extend_from_slice(instance);
        request
    }

    fn split_instance(response: &[u8]) -> &[u8] {
        let count = usize::from(response[3]);
        let at = RESPONSE_HEADER_LEN + count * SPLIT_MEMBERSHIP_RECORD_LEN;
        let len = usize::try_from(u32::from_le_bytes(
            response[at..at + 4].try_into().expect("length is 4 bytes"),
        ))
        .expect("test instance is bounded");
        &response[at + 4..at + 4 + len]
    }

    /// One membership half over one synthetic witness, proved once.
    struct SplitMembership {
        root_bytes: [u8; 32],
        record: Vec<u8>,
        proving: Vec<u8>,
        response: Vec<u8>,
    }

    fn shared_split_membership() -> &'static SplitMembership {
        static INSTANCE: OnceLock<SplitMembership> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            let (root_bytes, record) =
                synthetic_witness([0x24; 32], EdScalar::from(SPLIT_X), EdScalar::from(SPLIT_Y));
            let proving = membership_proving_request(root_bytes, &[&record]);
            let response =
                prove_membership_only(&proving).expect("membership half must be produced");
            SplitMembership {
                root_bytes,
                record,
                proving,
                response,
            }
        })
    }

    // Split and combined paths name the same pseudo-output, key image, mask delta and
    // authority, and produce same-length proofs verifying under the same statement.
    #[test]
    fn split_halves_verify_like_the_combined_prover() {
        let shared = shared_split_membership();
        let root_bytes = shared.root_bytes;
        let proving = &shared.proving;
        let membership = &shared.response;
        let signable_hash = [0x5d; 32];

        let mut combined_request = Vec::new();
        combined_request.extend_from_slice(&proving[..MEMBERSHIP_HEADER_LEN]);
        combined_request.extend_from_slice(&signable_hash);
        combined_request.extend_from_slice(&proving[MEMBERSHIP_HEADER_LEN..]);
        let combined = prove(&combined_request).expect("combined proof");

        let split = prove_sal_only(&split_sal_request(
            signable_hash,
            proving,
            split_instance(membership),
        ))
        .expect("SAL half over the membership half");

        assert_eq!(&membership[4..132], &combined[4..132]);
        assert_eq!(&split[4..132], &combined[4..132]);
        assert_eq!(split.len(), combined.len());

        let combined_verification =
            verification_request_from_response(root_bytes, signable_hash, &combined)
                .expect("verification request");
        let split_verification =
            verification_request_from_response(root_bytes, signable_hash, &split)
                .expect("verification request");
        let statement = VERIFY_HEADER_LEN + 64 + 4;
        assert_eq!(
            &combined_verification[..statement],
            &split_verification[..statement]
        );
        assert_ne!(combined_verification, split_verification);
        verify(&combined_verification).expect("the combined proof verifies");
        verify(&split_verification).expect("the split proof verifies");
        assert!(verify(
            &verification_request_from_response(root_bytes, [0x5e; 32], &split)
                .expect("verification request"),
        )
        .is_err());
    }

    // The membership half is challenged under nothing: its request has no hash slot, its
    // instance verifies alone and in a batch, and the key image the response reports is
    // nowhere in what the verifier is handed.
    #[test]
    fn split_membership_half_verifies_before_any_hash_exists() {
        let shared = shared_split_membership();
        let proving = &shared.proving;
        let membership = &shared.response;
        assert_eq!(
            proving.len(),
            MEMBERSHIP_PROVE_HEADER_LEN + shared.record.len()
        );
        let instance = split_instance(membership);
        assert_eq!(
            instance.len(),
            MEMBERSHIP_HEADER_LEN
                + MEMBERSHIP_INPUT_LEN
                + 4
                + Fcmp::<Curves>::proof_size(1, usize::from(LAYERS))
        );
        verify_membership(instance).expect("the membership half verifies on its own");
        verify_membership_batch(&batch_request(&[instance], 1), 1)
            .expect("a one-item batch equals a single verification");

        let key_image = &membership[36..68];
        assert!(
            !instance.windows(32).any(|window| window == key_image),
            "the instance published the key image"
        );

        let mut malleated = instance.to_vec();
        *malleated.last_mut().expect("the instance is nonempty") ^= 1;
        assert_eq!(
            verify_membership(&malleated),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    // SAL retry under a new hash shares no commitment with the first proof; under one hash
    // it is byte-identical; foreign membership bytes are refused.
    #[test]
    fn split_sal_retry_under_a_new_hash_shares_no_nonce() {
        const SAL_COMMITMENTS: core::ops::Range<usize> = 96..288;
        const S_BETA: usize = 320;
        const S_Z: usize = 416;

        let shared = shared_split_membership();
        let root_bytes = shared.root_bytes;
        let proving = &shared.proving;
        let membership = &shared.response;
        let instance = split_instance(membership);
        let x = EdScalar::from(SPLIT_X);

        let first_hash = [0x11; 32];
        let second_hash = [0x22; 32];
        let first = prove_sal_only(&split_sal_request(first_hash, proving, instance))
            .expect("first SAL half");
        let second = prove_sal_only(&split_sal_request(second_hash, proving, instance))
            .expect("retried SAL half");
        assert_eq!(&first[4..132], &second[4..132]);

        let proof_at = RESPONSE_HEADER_LEN + RESPONSE_RECORD_LEN + 4;
        let first_sal = &first[proof_at..];
        let second_sal = &second[proof_at..];
        assert_ne!(
            &first_sal[SAL_COMMITMENTS], &second_sal[SAL_COMMITMENTS],
            "the retry published the same SAL commitments, so a nonce was reused"
        );
        let delta = |at: usize| -> EdScalar {
            let left = decode_scalar::<Ed25519>(
                first_sal[at..at + 32]
                    .try_into()
                    .expect("SAL response is 32 bytes"),
            )
            .expect("canonical SAL response");
            let right = decode_scalar::<Ed25519>(
                second_sal[at..at + 32]
                    .try_into()
                    .expect("SAL response is 32 bytes"),
            )
            .expect("canonical SAL response");
            left - right
        };
        let inverse = Option::<EdScalar>::from(delta(S_BETA).invert())
            .expect("independent responses differ, so the difference is invertible");
        let recovered = delta(S_Z) * inverse;
        assert_ne!(
            <Ed25519 as Ciphersuite>::generator() * recovered,
            <Ed25519 as Ciphersuite>::generator() * x,
            "the spend key was recovered from the two published proofs"
        );

        let again = prove_sal_only(&split_sal_request(first_hash, proving, instance))
            .expect("the same hash proves again");
        assert_eq!(again, first);

        verify(
            &verification_request_from_response(root_bytes, first_hash, &first)
                .expect("verification request"),
        )
        .expect("first proof verifies under its own hash");
        verify(
            &verification_request_from_response(root_bytes, second_hash, &second)
                .expect("verification request"),
        )
        .expect("retried proof verifies under its own hash");
        assert!(verify(
            &verification_request_from_response(root_bytes, second_hash, &first)
                .expect("verification request"),
        )
        .is_err());

        let mut other_entropy = proving.clone();
        other_entropy[MEMBERSHIP_HEADER_LEN] ^= 1;
        assert_eq!(
            prove_sal_only(&split_sal_request(first_hash, &other_entropy, instance)),
            Err(ResultCode::ConsensusInvalid)
        );
        let mut other_root = instance.to_vec();
        other_root[MEMBERSHIP_HEADER_LEN - 1] ^= 1;
        assert_eq!(
            prove_sal_only(&split_sal_request(first_hash, proving, &other_root)),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    #[test]
    fn malformed_split_requests_error_instead_of_unwinding() {
        assert_eq!(prove_membership_only(&[1]), Err(ResultCode::BadLength));
        assert_eq!(prove_sal_only(&[1]), Err(ResultCode::BadLength));
        // A proving length that leaves no room for an instance.
        let request = split_sal_request([0x11; 32], &[0; MEMBERSHIP_PROVE_HEADER_LEN], &[]);
        assert_eq!(prove_sal_only(&request), Err(ResultCode::BadLength));
        // A proving length past the end of the request.
        let mut overrun = split_sal_request([0x11; 32], &[0; MEMBERSHIP_PROVE_HEADER_LEN], &[]);
        overrun[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(prove_sal_only(&overrun), Err(ResultCode::ResourceLimit));
    }

    #[test]
    #[ignore = "full eight-layer FCMP++ proving vector is intentionally expensive"]
    fn real_eight_layer_prove_single_batch_and_malleation() {
        let (proving_request, root, signable_hash) = real_proving_request();
        let response = prove(&proving_request).expect("real proof must be constructed");
        let verification = verification_request_from_response(root, signable_hash, &response)
            .expect("response converts to canonical verification request");
        verify(&verification).expect("single proof must verify");

        let one = batch_request(&[&verification], 1);
        verify_batch(&one, 1).expect("one-item batch equals single verification");
        let two = batch_request(&[&verification, &verification], 2);
        verify_batch(&two, 2).expect("shared two-proof batch must verify");

        let mut malleated = verification;
        let last = malleated.last_mut().expect("proof request is nonempty");
        *last ^= 1;
        assert_eq!(verify(&malleated), Err(ResultCode::ConsensusInvalid));
    }
}
