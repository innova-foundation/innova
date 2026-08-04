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
        BranchBlind, Branches, CBlind, Fcmp, IBlind, IBlindBlind, OBlind, OutputBlinds, Path,
        TreeRoot,
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
const PROVER_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/ProverRng/v1";
const BATCH_RNG_DOMAIN: &[u8] = b"Innova/IV5/FCMP++/BatchWeights/v1";

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
        let x = decode_scalar::<Ed25519>(reader.array()?)?;
        if bool::from(x.is_zero()) {
            return Err(ResultCode::ConsensusInvalid);
        }
        let y = decode_scalar::<Ed25519>(reader.array()?)?;
        let output = decode_output(&mut reader)?;
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
            leaves.push(decode_output(&mut reader)?);
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
        witnesses.push(ProvingWitness {
            x,
            y,
            path: Path {
                output,
                leaves,
                curve_2_layers,
                curve_1_layers,
            },
        });
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
    let mut rng = deterministic_rng(PROVER_RNG_DOMAIN, &[request]);
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
        ) = rerandomize_with_nonzero_blinds(&mut rng, &witness.path.output);
        let mut pseudo_out_mask_delta = -rerandomized.c_blind();
        let mut rerandomized_y = witness.y - rerandomized.o_blind();
        let opening = OpenedInputTuple::open(&rerandomized, &witness.x, &witness.y)
            .ok_or(ResultCode::ConsensusInvalid)?;
        let input = rerandomized.input();
        let (key_image, authorization) =
            SpendAuthAndLinkability::prove(&mut rng, signable_hash, &opening);
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

pub(super) fn verify_batch(request: &[u8], expected_count: u32) -> Result<(), ResultCode> {
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
    use super::*;
    use ec_divisors::DivisorCurve as _;

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

    fn real_proving_request() -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
        let x = EdScalar::from(7_u64);
        let y = EdScalar::from(11_u64);
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
        let root_bytes = root.to_bytes();
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
        append_output(&mut request, &output);
        request.push(u8::try_from(leaves.len()).expect("leaf count is bounded"));
        request.extend_from_slice(&[0; 3]);
        for leaf in leaves {
            append_output(&mut request, &leaf);
        }
        for branch in c2_layers {
            for scalar in branch {
                append_scalar::<Helios>(&mut request, scalar);
            }
        }
        for branch in c1_layers {
            for scalar in branch {
                append_scalar::<Selene>(&mut request, scalar);
            }
        }
        (request, root_bytes, signable_hash)
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
