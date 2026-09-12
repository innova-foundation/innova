use std::{
    collections::BTreeMap,
    sync::{Mutex, PoisonError},
};

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use monero_bulletproofs::Bulletproof;
use monero_ed25519::{Commitment, CompressedPoint, Scalar as MoneroScalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroize;

use crate::{ResultCode, MAX_NULLSEND_INPUTS, PAYLOAD_SCHEMA_U16};

pub(crate) const MAX_VALUE_COMMITMENTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValueError {
    BadLength,
    InvalidEncoding,
    InvalidProof,
    ResourceLimit,
    /// A mix nonce this process already signed with, offered a different aggregate.
    NonceReuse,
}

fn hash_to_scalar(domain: &[u8], fields: &[&[u8]]) -> Scalar {
    let mut hash = Blake2b512::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}

fn deterministic_rng(domain: &[u8], fields: &[&[u8]]) -> ChaCha20Rng {
    let mut hash = Blake2b512::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    let digest = hash.finalize();
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&digest[..32]);
    ChaCha20Rng::from_seed(seed)
}

fn canonical_scalar(bytes: &[u8; 32]) -> Result<Scalar, ValueError> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).ok_or(ValueError::InvalidEncoding)
}

fn canonical_point(bytes: &[u8; 32], allow_identity: bool) -> Result<EdwardsPoint, ValueError> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .filter(|point| point.compress().to_bytes() == *bytes)
        .filter(EdwardsPoint::is_torsion_free)
        .ok_or(ValueError::InvalidEncoding)?;
    if !allow_identity && point.is_identity() {
        return Err(ValueError::InvalidEncoding);
    }
    Ok(point)
}

fn monero_h() -> EdwardsPoint {
    CompressedEdwardsY(CompressedPoint::H.to_bytes())
        .decompress()
        .expect("the pinned Monero H encoding must decompress")
}

pub(crate) fn commitment(amount: u64, mask_bytes: &[u8; 32]) -> Result<[u8; 32], ValueError> {
    let mask = canonical_scalar(mask_bytes)?;
    let commitment = Commitment::new(MoneroScalar::from(mask), amount).commit();
    Ok(commitment.compress().to_bytes())
}

/// `C - shift * H`: the point a floor statement is proved over. Only moves the point; the
/// shift itself is the caller's fact. Both inputs are torsion-free, so the result is too.
pub(crate) fn shift_commitment(encoded: &[u8; 32], shift: u64) -> Result<[u8; 32], ValueError> {
    let point = canonical_point(encoded, false)?;
    Ok((point - monero_h() * Scalar::from(shift)).compress().to_bytes())
}

pub(crate) fn validate_disclosed_commitment(
    encoded: &[u8; 32],
    amount: u64,
    mask: &[u8; 32],
) -> Result<bool, ValueError> {
    canonical_point(encoded, false)?;
    Ok(commitment(amount, mask)? == *encoded)
}

pub(crate) fn prove_range(
    amounts: &[u64],
    masks: &[[u8; 32]],
    entropy: &[u8; 32],
) -> Result<(Vec<[u8; 32]>, Vec<u8>), ValueError> {
    if amounts.is_empty() || amounts.len() != masks.len() {
        return Err(ValueError::BadLength);
    }
    if amounts.len() > MAX_VALUE_COMMITMENTS {
        return Err(ValueError::ResourceLimit);
    }

    let mut openings = Vec::with_capacity(amounts.len());
    let mut encoded = Vec::with_capacity(amounts.len());
    for (&amount, mask_bytes) in amounts.iter().zip(masks) {
        let mask = canonical_scalar(mask_bytes)?;
        let opening = Commitment::new(MoneroScalar::from(mask), amount);
        let point = opening.commit().compress().to_bytes();
        canonical_point(&point, false)?;
        encoded.push(point);
        openings.push(opening);
    }

    let encoded_flat = encoded.iter().flatten().copied().collect::<Vec<_>>();
    let mut rng = deterministic_rng(b"Innova/IV5/RangeProof/Prove/v1", &[entropy, &encoded_flat]);
    let proof = Bulletproof::prove_plus(&mut rng, openings)
        .map_err(|_| ValueError::InvalidProof)?
        .serialize();
    Ok((encoded, proof))
}

pub(crate) fn verify_range(
    commitments: &[[u8; 32]],
    proof_bytes: &[u8],
    signable_hash: &[u8; 32],
) -> Result<bool, ValueError> {
    if commitments.is_empty() || proof_bytes.is_empty() {
        return Err(ValueError::BadLength);
    }
    if commitments.len() > MAX_VALUE_COMMITMENTS {
        return Err(ValueError::ResourceLimit);
    }

    let mut compressed = Vec::with_capacity(commitments.len());
    for encoded in commitments {
        canonical_point(encoded, false)?;
        compressed.push(CompressedPoint::from(*encoded));
    }

    let mut reader = proof_bytes;
    let proof = Bulletproof::read_plus(&mut reader).map_err(|_| ValueError::InvalidEncoding)?;
    if !reader.is_empty() || proof.serialize() != proof_bytes {
        return Err(ValueError::InvalidEncoding);
    }

    let commitments_flat = commitments.iter().flatten().copied().collect::<Vec<_>>();
    let mut rng = deterministic_rng(
        b"Innova/IV5/RangeProof/Verify/v1",
        &[signable_hash, &commitments_flat, proof_bytes],
    );
    Ok(proof.verify(&mut rng, &compressed))
}

fn excess_point(
    pseudo_outs: &[[u8; 32]],
    outputs: &[[u8; 32]],
    transparent_value_balance: i64,
    fee: u64,
) -> Result<EdwardsPoint, ValueError> {
    if pseudo_outs.len() > MAX_VALUE_COMMITMENTS || outputs.len() > MAX_VALUE_COMMITMENTS {
        return Err(ValueError::ResourceLimit);
    }
    if fee > i64::MAX as u64 {
        return Err(ValueError::ResourceLimit);
    }

    let mut excess = EdwardsPoint::identity();
    for encoded in pseudo_outs {
        excess += canonical_point(encoded, false)?;
    }
    for encoded in outputs {
        excess -= canonical_point(encoded, false)?;
    }

    // Positive balance enters the private pool; negative balance exits it.
    let public_delta = i128::from(transparent_value_balance) - i128::from(fee);
    let magnitude =
        u64::try_from(public_delta.unsigned_abs()).map_err(|_| ValueError::ResourceLimit)?;
    let public_term = monero_h() * Scalar::from(magnitude);
    if public_delta >= 0 {
        excess += public_term;
    } else {
        excess -= public_term;
    }
    Ok(excess)
}

/// Schnorr proof of knowledge of the value-excess mask: inputs, outputs, balance and fee
/// sum to zero. Sign only once per key; two challenge domains would reveal the mask.
pub(crate) fn prove_balance(
    pseudo_outs: &[[u8; 32]],
    outputs: &[[u8; 32]],
    transparent_value_balance: i64,
    fee: u64,
    excess_mask_bytes: &[u8; 32],
    signable_hash: &[u8; 32],
    entropy: &[u8; 32],
) -> Result<[u8; 64], ValueError> {
    let excess_mask = canonical_scalar(excess_mask_bytes)?;
    let excess = excess_point(pseudo_outs, outputs, transparent_value_balance, fee)?;
    if excess != ED25519_BASEPOINT_POINT * excess_mask {
        return Err(ValueError::InvalidProof);
    }

    let excess_encoded = excess.compress().to_bytes();
    let mut nonce = hash_to_scalar(
        b"Innova/IV5/BalanceProof/Nonce/v1",
        &[entropy, excess_mask_bytes, signable_hash, &excess_encoded],
    );
    if nonce == Scalar::ZERO {
        nonce = Scalar::ONE;
    }
    let nonce_point = ED25519_BASEPOINT_POINT * nonce;
    let nonce_encoded = nonce_point.compress().to_bytes();
    let challenge = hash_to_scalar(
        b"Innova/IV5/BalanceProof/Challenge/v1",
        &[signable_hash, &excess_encoded, &nonce_encoded],
    );
    let response = nonce + (challenge * excess_mask);

    let mut proof = [0_u8; 64];
    proof[..32].copy_from_slice(&nonce_encoded);
    proof[32..].copy_from_slice(&response.to_bytes());
    Ok(proof)
}

pub(crate) fn verify_balance(
    pseudo_outs: &[[u8; 32]],
    outputs: &[[u8; 32]],
    transparent_value_balance: i64,
    fee: u64,
    signable_hash: &[u8; 32],
    proof: &[u8],
) -> Result<bool, ValueError> {
    if proof.len() != 64 {
        return Err(ValueError::BadLength);
    }
    let mut nonce_bytes = [0_u8; 32];
    nonce_bytes.copy_from_slice(&proof[..32]);
    let nonce = canonical_point(&nonce_bytes, false)?;
    let mut response_bytes = [0_u8; 32];
    response_bytes.copy_from_slice(&proof[32..]);
    let response = canonical_scalar(&response_bytes)?;

    let excess = excess_point(pseudo_outs, outputs, transparent_value_balance, fee)?;
    let excess_encoded = excess.compress().to_bytes();
    let challenge = hash_to_scalar(
        b"Innova/IV5/BalanceProof/Challenge/v1",
        &[signable_hash, &excess_encoded, &nonce_bytes],
    );
    Ok((ED25519_BASEPOINT_POINT * response) == (nonce + (excess * challenge)))
}

pub(crate) const AMOUNT_EQUALITY_PROOF_BYTES: usize = 64;

/// The amount-equality statement `commitment - amount*H`, which is `mask*G` exactly when
/// the commitment holds `amount`. The identity is refused: a zero mask accepts anything.
fn amount_equality_statement(
    commitment: &[u8; 32],
    amount: u64,
) -> Result<EdwardsPoint, ValueError> {
    let statement = canonical_point(commitment, false)? - (monero_h() * Scalar::from(amount));
    if statement.is_identity() {
        return Err(ValueError::InvalidProof);
    }
    Ok(statement)
}

/// Schnorr knowledge of the mask behind `commitment - amount*H`: the commitment holds
/// `amount`. Run on a re-randomized commitment; the challenge binds commitment and amount.
pub(crate) fn prove_amount_equality(
    commitment: &[u8; 32],
    amount: u64,
    mask_bytes: &[u8; 32],
    signable_hash: &[u8; 32],
    entropy: &[u8; 32],
) -> Result<[u8; AMOUNT_EQUALITY_PROOF_BYTES], ValueError> {
    let mask = canonical_scalar(mask_bytes)?;
    let statement = amount_equality_statement(commitment, amount)?;
    if statement != ED25519_BASEPOINT_POINT * mask {
        return Err(ValueError::InvalidProof);
    }

    let statement_encoded = statement.compress().to_bytes();
    let mut nonce = hash_to_scalar(
        b"Innova/IV5/AmountEquality/Nonce/v1",
        &[entropy, mask_bytes, signable_hash, &statement_encoded],
    );
    if nonce == Scalar::ZERO {
        nonce = Scalar::ONE;
    }
    let nonce_encoded = (ED25519_BASEPOINT_POINT * nonce).compress().to_bytes();
    let challenge = hash_to_scalar(
        b"Innova/IV5/AmountEquality/Challenge/v1",
        &[
            signable_hash,
            commitment,
            &amount.to_le_bytes(),
            &statement_encoded,
            &nonce_encoded,
        ],
    );
    let response = nonce + (challenge * mask);

    let mut proof = [0_u8; AMOUNT_EQUALITY_PROOF_BYTES];
    proof[..32].copy_from_slice(&nonce_encoded);
    proof[32..].copy_from_slice(&response.to_bytes());
    Ok(proof)
}

pub(crate) fn verify_amount_equality(
    commitment: &[u8; 32],
    amount: u64,
    signable_hash: &[u8; 32],
    proof: &[u8],
) -> Result<bool, ValueError> {
    if proof.len() != AMOUNT_EQUALITY_PROOF_BYTES {
        return Err(ValueError::BadLength);
    }
    let mut nonce_bytes = [0_u8; 32];
    nonce_bytes.copy_from_slice(&proof[..32]);
    let nonce = canonical_point(&nonce_bytes, false)?;
    let mut response_bytes = [0_u8; 32];
    response_bytes.copy_from_slice(&proof[32..]);
    let response = canonical_scalar(&response_bytes)?;

    let statement = amount_equality_statement(commitment, amount)?;
    let statement_encoded = statement.compress().to_bytes();
    let challenge = hash_to_scalar(
        b"Innova/IV5/AmountEquality/Challenge/v1",
        &[
            signable_hash,
            commitment,
            &amount.to_le_bytes(),
            &statement_encoded,
            &nonce_bytes,
        ],
    );
    Ok((ED25519_BASEPOINT_POINT * response) == (nonce + (statement * challenge)))
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ResultCode> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ResultCode::ResourceLimit)?;
        if end > self.bytes.len() {
            return Err(ResultCode::BadLength);
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

    fn u64(&mut self) -> Result<u64, ResultCode> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, ResultCode> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), ResultCode> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ResultCode::BadLength)
        }
    }
}

pub(crate) fn result_code(error: ValueError) -> ResultCode {
    match error {
        ValueError::BadLength => ResultCode::BadLength,
        ValueError::ResourceLimit => ResultCode::ResourceLimit,
        ValueError::InvalidEncoding | ValueError::InvalidProof => ResultCode::ConsensusInvalid,
        ValueError::NonceReuse => ResultCode::InternalLocalStateFailure,
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn prove_request(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    const HEADER_BYTES: usize = 116;
    if request.len() < HEADER_BYTES {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    if reader.u16()? != PAYLOAD_SCHEMA_U16 {
        return Err(ResultCode::UnsupportedFormat);
    }
    let output_count = usize::from(reader.u8()?);
    let input_count = usize::from(reader.u8()?);
    if output_count > MAX_VALUE_COMMITMENTS || input_count > MAX_VALUE_COMMITMENTS {
        return Err(ResultCode::ResourceLimit);
    }
    let transparent_value_balance = reader.i64()?;
    let fee = reader.u64()?;
    let signable_hash = reader.array()?;
    let entropy = reader.array()?;
    let excess_mask = reader.array()?;
    if signable_hash.iter().all(|byte| *byte == 0) || entropy.iter().all(|byte| *byte == 0) {
        return Err(ResultCode::ConsensusInvalid);
    }
    let mut pseudo_outs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let pseudo_out = reader.array()?;
        canonical_point(&pseudo_out, false).map_err(result_code)?;
        pseudo_outs.push(pseudo_out);
    }
    let mut amounts = Vec::with_capacity(output_count);
    let mut masks = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        amounts.push(reader.u64()?);
        let mask = reader.array()?;
        canonical_scalar(&mask).map_err(result_code)?;
        masks.push(mask);
    }
    reader.finish()?;

    let (output_commitments, range_proof) = if output_count == 0 {
        (Vec::new(), Vec::new())
    } else {
        prove_range(&amounts, &masks, &entropy).map_err(result_code)?
    };
    let balance_proof = prove_balance(
        &pseudo_outs,
        &output_commitments,
        transparent_value_balance,
        fee,
        &excess_mask,
        &signable_hash,
        &entropy,
    )
    .map_err(result_code)?;

    if (output_count != 0
        && !verify_range(&output_commitments, &range_proof, &signable_hash).map_err(result_code)?)
        || !verify_balance(
            &pseudo_outs,
            &output_commitments,
            transparent_value_balance,
            fee,
            &signable_hash,
            &balance_proof,
        )
        .map_err(result_code)?
    {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let mut response = Vec::new();
    response.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
    response.push(u8::try_from(output_count).map_err(|_| ResultCode::ResourceLimit)?);
    response.push(u8::try_from(input_count).map_err(|_| ResultCode::ResourceLimit)?);
    for commitment in output_commitments {
        response.extend_from_slice(&commitment);
    }
    response.extend_from_slice(
        &u32::try_from(range_proof.len())
            .map_err(|_| ResultCode::ResourceLimit)?
            .to_le_bytes(),
    );
    response.extend_from_slice(&range_proof);
    response.extend_from_slice(&balance_proof);
    Ok(response)
}

// Multi-party mix balance proof: s_i = k_i + c*x_i, proof (sum R_i, sum s_i). Reusing k_i
// under two aggregates reveals the mask, so `mix_share_sign` pins each nonce to one
// aggregate (process state only: request entropy must be fresh per signing).

const MIX_NONCE_DOMAIN: &[u8] = b"Innova/IV5/MixBalance/Nonce/v1";
/// The domain `prove_balance` and `verify_balance` use; the joint proof must land on it.
const BALANCE_CHALLENGE_DOMAIN: &[u8] = b"Innova/IV5/BalanceProof/Challenge/v1";

/// The facts a balance proof is over, as the payload states them.
#[derive(Clone, Copy)]
pub(crate) struct BalanceInstance<'a> {
    pub(crate) pseudo_outs: &'a [[u8; 32]],
    pub(crate) outputs: &'a [[u8; 32]],
    pub(crate) transparent_value_balance: i64,
    pub(crate) fee: u64,
    pub(crate) signable_hash: &'a [u8; 32],
}

impl BalanceInstance<'_> {
    fn excess_encoded(&self) -> Result<[u8; 32], ValueError> {
        Ok(excess_point(
            self.pseudo_outs,
            self.outputs,
            self.transparent_value_balance,
            self.fee,
        )?
        .compress()
        .to_bytes())
    }

    /// `pseudo_out - output - fee_share*H`: `x*G` exactly when the input funds the output
    /// with `fee_share` left over.
    fn share_statement(
        &self,
        input_index: usize,
        output_index: usize,
        fee_share: u64,
    ) -> Result<EdwardsPoint, ValueError> {
        let pseudo_out = self
            .pseudo_outs
            .get(input_index)
            .ok_or(ValueError::BadLength)?;
        let output = self
            .outputs
            .get(output_index)
            .ok_or(ValueError::BadLength)?;
        Ok(canonical_point(pseudo_out, false)?
            - canonical_point(output, false)?
            - monero_h() * Scalar::from(fee_share))
    }

    /// Sum of the nonce points, one per input in input order, in the encoding the challenge
    /// and the proof carry. An identity sum is refused: `verify_balance` refuses it.
    fn aggregate_nonce(&self, nonces: &[[u8; 32]]) -> Result<[u8; 32], ValueError> {
        if nonces.len() != self.pseudo_outs.len() {
            return Err(ValueError::BadLength);
        }
        if nonces.len() > MAX_NULLSEND_INPUTS {
            return Err(ValueError::ResourceLimit);
        }
        if nonces.len() < 2 {
            return Err(ValueError::InvalidProof);
        }
        let mut total = EdwardsPoint::identity();
        for nonce in nonces {
            total += canonical_point(nonce, false)?;
        }
        if total.is_identity() {
            return Err(ValueError::InvalidProof);
        }
        Ok(total.compress().to_bytes())
    }

    fn challenge(&self, excess_encoded: &[u8; 32], aggregate: &[u8; 32]) -> Scalar {
        hash_to_scalar(
            BALANCE_CHALLENGE_DOMAIN,
            &[self.signable_hash, excess_encoded, aggregate],
        )
    }
}

/// One participant's side of a mix.
#[derive(Clone, Copy)]
pub(crate) struct MixShare<'a> {
    pub(crate) input_index: usize,
    pub(crate) output_index: usize,
    /// Input amount less output amount: this participant's part of the fee.
    pub(crate) fee_share: u64,
    /// Pseudo-output mask less output mask: this participant's part of the excess mask.
    pub(crate) mask: &'a [u8; 32],
    pub(crate) entropy: &'a [u8; 32],
}

impl MixShare<'_> {
    /// The mask and the nonce, once the mask is known to open the share's pair.
    fn secrets(
        &self,
        instance: &BalanceInstance<'_>,
        excess_encoded: &[u8; 32],
    ) -> Result<(Scalar, Scalar), ValueError> {
        let mask = canonical_scalar(self.mask)?;
        let statement =
            instance.share_statement(self.input_index, self.output_index, self.fee_share)?;
        if statement != ED25519_BASEPOINT_POINT * mask {
            return Err(ValueError::InvalidProof);
        }
        let mut nonce = hash_to_scalar(
            MIX_NONCE_DOMAIN,
            &[
                self.entropy,
                self.mask,
                instance.signable_hash,
                excess_encoded,
            ],
        );
        if nonce == Scalar::ZERO {
            nonce = Scalar::ONE;
        }
        Ok((mask, nonce))
    }
}

/// Nonce points this process has signed with, each with the aggregate it signed under.
static SIGNED_MIX_NONCES: Mutex<BTreeMap<[u8; 32], [u8; 32]>> = Mutex::new(BTreeMap::new());
/// Past this the process refuses new mix signings rather than forget one: a forgotten
/// record is the second signature the record exists to refuse.
const MAX_SIGNED_MIX_NONCES: usize = 1 << 16;

fn record_signing(own: &[u8; 32], aggregate: &[u8; 32]) -> Result<(), ValueError> {
    // A poisoned lock is a panic between lock and unlock. The map is only read or given
    // one entry under it, so its contents are whole either way.
    let mut signed = SIGNED_MIX_NONCES
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match signed.get(own) {
        Some(previous) if previous == aggregate => Ok(()),
        Some(_) => Err(ValueError::NonceReuse),
        None if signed.len() >= MAX_SIGNED_MIX_NONCES => Err(ValueError::ResourceLimit),
        None => {
            signed.insert(*own, *aggregate);
            Ok(())
        }
    }
}

/// Round one: the participant's nonce point, a pure function of the share.
pub(crate) fn mix_share_nonce(
    instance: &BalanceInstance<'_>,
    share: &MixShare<'_>,
) -> Result<[u8; 32], ValueError> {
    let excess_encoded = instance.excess_encoded()?;
    let (_, nonce) = share.secrets(instance, &excess_encoded)?;
    Ok((ED25519_BASEPOINT_POINT * nonce).compress().to_bytes())
}

/// Round two: the participant's response under every nonce point, its own listed at its
/// input index. One nonce signs under one aggregate for the life of the process.
pub(crate) fn mix_share_sign(
    instance: &BalanceInstance<'_>,
    share: &MixShare<'_>,
    nonces: &[[u8; 32]],
) -> Result<[u8; 32], ValueError> {
    let excess_encoded = instance.excess_encoded()?;
    let (mask, nonce) = share.secrets(instance, &excess_encoded)?;
    let own = (ED25519_BASEPOINT_POINT * nonce).compress().to_bytes();
    if nonces.get(share.input_index) != Some(&own) {
        return Err(ValueError::InvalidProof);
    }
    let aggregate = instance.aggregate_nonce(nonces)?;
    let challenge = instance.challenge(&excess_encoded, &aggregate);
    record_signing(&own, &aggregate)?;
    Ok((nonce + challenge * mask).to_bytes())
}

/// Whether one response is right for the pair and fee share its participant claims.
/// Amounts in a mix are disclosed, so whoever knows the pairing can name a bad share
/// rather than a bad proof. Not carried by the FFI; the tests use it to show that.
#[cfg(test)]
fn mix_share_verify(
    instance: &BalanceInstance<'_>,
    input_index: usize,
    output_index: usize,
    fee_share: u64,
    nonces: &[[u8; 32]],
    response: &[u8; 32],
) -> Result<bool, ValueError> {
    let statement = instance.share_statement(input_index, output_index, fee_share)?;
    let own = canonical_point(nonces.get(input_index).ok_or(ValueError::BadLength)?, false)?;
    let aggregate = instance.aggregate_nonce(nonces)?;
    let challenge = instance.challenge(&instance.excess_encoded()?, &aggregate);
    let response = canonical_scalar(response)?;
    Ok(ED25519_BASEPOINT_POINT * response == own + statement * challenge)
}

/// The joint proof in the layout `verify_balance` reads, verified before it is returned so
/// a wrong share yields no proof rather than a bad one.
pub(crate) fn mix_balance_combine(
    instance: &BalanceInstance<'_>,
    nonces: &[[u8; 32]],
    responses: &[[u8; 32]],
) -> Result<[u8; 64], ValueError> {
    if responses.len() != nonces.len() {
        return Err(ValueError::BadLength);
    }
    let aggregate = instance.aggregate_nonce(nonces)?;
    let mut total = Scalar::ZERO;
    for response in responses {
        total += canonical_scalar(response)?;
    }
    let mut proof = [0_u8; 64];
    proof[..32].copy_from_slice(&aggregate);
    proof[32..].copy_from_slice(&total.to_bytes());
    if !verify_balance(
        instance.pseudo_outs,
        instance.outputs,
        instance.transparent_value_balance,
        instance.fee,
        instance.signable_hash,
        &proof,
    )? {
        return Err(ValueError::InvalidProof);
    }
    Ok(proof)
}

/// Bytes of a mix instance before its pseudo-outputs.
const MIX_INSTANCE_HEADER_BYTES: usize = 52;
/// Bytes of one participant's share block.
const MIX_SHARE_BYTES: usize = 76;

/// `schema_u16 || output_count_u8 || input_count_u8 || transparent_value_balance_i64_le ||
/// fee_u64_le || signable_hash_32`, then the pseudo-outputs and the outputs.
struct MixInstanceBytes {
    pseudo_outs: Vec<[u8; 32]>,
    outputs: Vec<[u8; 32]>,
    transparent_value_balance: i64,
    fee: u64,
    signable_hash: [u8; 32],
}

impl MixInstanceBytes {
    fn read(reader: &mut Reader<'_>) -> Result<Self, ResultCode> {
        if reader.u16()? != PAYLOAD_SCHEMA_U16 {
            return Err(ResultCode::UnsupportedFormat);
        }
        let output_count = usize::from(reader.u8()?);
        let input_count = usize::from(reader.u8()?);
        if output_count > MAX_VALUE_COMMITMENTS || input_count > MAX_NULLSEND_INPUTS {
            return Err(ResultCode::ResourceLimit);
        }
        if input_count < 2 || output_count == 0 {
            return Err(ResultCode::ConsensusInvalid);
        }
        let transparent_value_balance = reader.i64()?;
        let fee = reader.u64()?;
        let signable_hash: [u8; 32] = reader.array()?;
        if signable_hash.iter().all(|byte| *byte == 0) {
            return Err(ResultCode::ConsensusInvalid);
        }
        let mut pseudo_outs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let pseudo_out = reader.array()?;
            canonical_point(&pseudo_out, false).map_err(result_code)?;
            pseudo_outs.push(pseudo_out);
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let output = reader.array()?;
            canonical_point(&output, false).map_err(result_code)?;
            outputs.push(output);
        }
        Ok(Self {
            pseudo_outs,
            outputs,
            transparent_value_balance,
            fee,
            signable_hash,
        })
    }

    fn view(&self) -> BalanceInstance<'_> {
        BalanceInstance {
            pseudo_outs: &self.pseudo_outs,
            outputs: &self.outputs,
            transparent_value_balance: self.transparent_value_balance,
            fee: self.fee,
            signable_hash: &self.signable_hash,
        }
    }

    /// One 32-byte field per input, in input order.
    fn per_input(&self, reader: &mut Reader<'_>) -> Result<Vec<[u8; 32]>, ResultCode> {
        let mut fields = Vec::with_capacity(self.pseudo_outs.len());
        for _ in 0..self.pseudo_outs.len() {
            fields.push(reader.array()?);
        }
        Ok(fields)
    }
}

/// `input_index_u8 || output_index_u8 || reserved_u16_zero || fee_share_u64_le || mask_32 ||
/// entropy_32`.
struct MixShareBytes {
    input_index: usize,
    output_index: usize,
    fee_share: u64,
    mask: [u8; 32],
    entropy: [u8; 32],
}

impl Drop for MixShareBytes {
    fn drop(&mut self) {
        self.mask.zeroize();
        self.entropy.zeroize();
    }
}

impl MixShareBytes {
    fn read(reader: &mut Reader<'_>, instance: &MixInstanceBytes) -> Result<Self, ResultCode> {
        let input_index = usize::from(reader.u8()?);
        let output_index = usize::from(reader.u8()?);
        if reader.u16()? != 0 {
            return Err(ResultCode::ConsensusInvalid);
        }
        if input_index >= instance.pseudo_outs.len() || output_index >= instance.outputs.len() {
            return Err(ResultCode::ConsensusInvalid);
        }
        let fee_share = reader.u64()?;
        let mask: [u8; 32] = reader.array()?;
        canonical_scalar(&mask).map_err(result_code)?;
        let entropy: [u8; 32] = reader.array()?;
        if entropy.iter().all(|byte| *byte == 0) {
            return Err(ResultCode::ConsensusInvalid);
        }
        Ok(Self {
            input_index,
            output_index,
            fee_share,
            mask,
            entropy,
        })
    }

    fn view(&self) -> MixShare<'_> {
        MixShare {
            input_index: self.input_index,
            output_index: self.output_index,
            fee_share: self.fee_share,
            mask: &self.mask,
            entropy: &self.entropy,
        }
    }
}

pub(crate) fn mix_nonce_request(request: &[u8]) -> Result<[u8; 32], ResultCode> {
    if request.len() < MIX_INSTANCE_HEADER_BYTES + MIX_SHARE_BYTES {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    let instance = MixInstanceBytes::read(&mut reader)?;
    let share = MixShareBytes::read(&mut reader, &instance)?;
    reader.finish()?;
    mix_share_nonce(&instance.view(), &share.view()).map_err(result_code)
}

pub(crate) fn mix_sign_request(request: &[u8]) -> Result<[u8; 32], ResultCode> {
    if request.len() < MIX_INSTANCE_HEADER_BYTES + MIX_SHARE_BYTES {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    let instance = MixInstanceBytes::read(&mut reader)?;
    let share = MixShareBytes::read(&mut reader, &instance)?;
    let nonces = instance.per_input(&mut reader)?;
    reader.finish()?;
    mix_share_sign(&instance.view(), &share.view(), &nonces).map_err(result_code)
}

pub(crate) fn mix_combine_request(request: &[u8]) -> Result<[u8; 64], ResultCode> {
    if request.len() < MIX_INSTANCE_HEADER_BYTES {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    let instance = MixInstanceBytes::read(&mut reader)?;
    let nonces = instance.per_input(&mut reader)?;
    let responses = instance.per_input(&mut reader)?;
    reader.finish()?;
    mix_balance_combine(&instance.view(), &nonces, &responses).map_err(result_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u64) -> [u8; 32] {
        Scalar::from(value).to_bytes()
    }

    #[test]
    fn aggregate_range_proof_roundtrip_and_malleation() {
        let amounts = [0, 42, u64::MAX];
        let masks = [scalar(3), scalar(5), scalar(7)];
        let entropy = [9_u8; 32];
        let signable_hash = [11_u8; 32];
        let (commitments, proof) = prove_range(&amounts, &masks, &entropy).unwrap();
        assert!(verify_range(&commitments, &proof, &signable_hash).unwrap());

        let mut malformed = proof.clone();
        let last = malformed.len() - 1;
        malformed[last] ^= 1;
        assert!(!verify_range(&commitments, &malformed, &signable_hash).unwrap_or(false));

        let mut wrong_commitments = commitments.clone();
        wrong_commitments[0] = commitment(1, &masks[0]).unwrap();
        assert!(!verify_range(&wrong_commitments, &proof, &signable_hash).unwrap());
    }

    #[test]
    fn disclosed_amount_is_bound_to_commitment() {
        let mask = scalar(19);
        let encoded = commitment(123, &mask).unwrap();
        assert!(validate_disclosed_commitment(&encoded, 123, &mask).unwrap());
        assert!(!validate_disclosed_commitment(&encoded, 124, &mask).unwrap());
    }

    #[test]
    fn balance_proof_covers_private_and_public_sides() {
        let input = commitment(100, &scalar(5)).unwrap();
        let output = commitment(90, &scalar(2)).unwrap();
        let signable_hash = [21_u8; 32];
        let proof = prove_balance(
            &[input],
            &[output],
            0,
            10,
            &scalar(3),
            &signable_hash,
            &[22_u8; 32],
        )
        .unwrap();
        assert!(verify_balance(&[input], &[output], 0, 10, &signable_hash, &proof).unwrap());
        assert!(!verify_balance(&[input], &[output], 0, 11, &signable_hash, &proof).unwrap());

        let mut malformed = proof;
        malformed[63] ^= 1;
        assert!(
            !verify_balance(&[input], &[output], 0, 10, &signable_hash, &malformed)
                .unwrap_or(false)
        );

        let shielded = commitment(50, &scalar(7)).unwrap();
        let shield_proof = prove_balance(
            &[],
            &[shielded],
            51,
            1,
            &(-Scalar::from(7_u64)).to_bytes(),
            &signable_hash,
            &[23_u8; 32],
        )
        .unwrap();
        assert!(verify_balance(&[], &[shielded], 51, 1, &signable_hash, &shield_proof).unwrap());
    }

    // The collateral tier is proved, never published; this proof alone separates
    // 25,000 from 24,999.
    #[test]
    fn an_amount_proof_holds_for_one_amount_only() {
        const TIER: u64 = 25_000 * 100_000_000;
        let mask = scalar(7);
        let commitment = commitment(TIER, &mask).unwrap();
        let signable_hash = [0x61_u8; 32];
        let proof =
            prove_amount_equality(&commitment, TIER, &mask, &signable_hash, &[0x62; 32]).unwrap();
        assert!(verify_amount_equality(&commitment, TIER, &signable_hash, &proof).unwrap());

        for wrong in [TIER - 1, TIER + 1, 0] {
            assert!(
                !verify_amount_equality(&commitment, wrong, &signable_hash, &proof)
                    .unwrap_or(false),
                "a proof for the tier must not verify at {wrong}"
            );
            let off_tier = super::commitment(wrong, &mask).unwrap();
            assert!(
                !verify_amount_equality(&off_tier, TIER, &signable_hash, &proof).unwrap_or(false),
                "a note holding {wrong} must not pass the tier check"
            );
            assert_eq!(
                prove_amount_equality(&off_tier, TIER, &mask, &signable_hash, &[0x62; 32]),
                Err(ValueError::InvalidProof),
                "a prover must not be able to claim the tier for {wrong}"
            );
        }

        // The proof travels with a payload, so it must not survive being moved to another.
        assert!(
            !verify_amount_equality(&commitment, TIER, &[0x63; 32], &proof).unwrap_or(false),
            "a proof must not verify under another payload's signing hash"
        );

        // Mix and match: a second note of the same tier has a different commitment, and its
        // proof must not stand in for this one's.
        let foreign = super::commitment(TIER, &scalar(11)).unwrap();
        let foreign_proof =
            prove_amount_equality(&foreign, TIER, &scalar(11), &signable_hash, &[0x64; 32])
                .unwrap();
        assert!(verify_amount_equality(&foreign, TIER, &signable_hash, &foreign_proof).unwrap());
        assert!(
            !verify_amount_equality(&commitment, TIER, &signable_hash, &foreign_proof)
                .unwrap_or(false),
            "a proof made against a foreign commitment must not verify against this one"
        );
    }

    // A zero mask puts `C - amount*H` at the identity, where any nonce verifies; the
    // registering wallet can grind for it, so it must be refused.
    #[test]
    fn an_amount_proof_refuses_an_identity_statement() {
        const TIER: u64 = 25_000 * 100_000_000;
        let zero_mask = Scalar::ZERO.to_bytes();
        let commitment = commitment(TIER, &zero_mask).unwrap();
        assert_eq!(
            prove_amount_equality(&commitment, TIER, &zero_mask, &[0x71; 32], &[0x72; 32]),
            Err(ValueError::InvalidProof)
        );

        // The forgery the check exists to stop: a transcript built with no secret at all.
        let nonce = Scalar::from(9_u64);
        let mut forged = [0_u8; AMOUNT_EQUALITY_PROOF_BYTES];
        forged[..32].copy_from_slice(&(ED25519_BASEPOINT_POINT * nonce).compress().to_bytes());
        forged[32..].copy_from_slice(&nonce.to_bytes());
        assert_eq!(
            verify_amount_equality(&commitment, TIER, &[0x71; 32], &forged),
            Err(ValueError::InvalidProof)
        );
    }

    #[test]
    fn malformed_value_material_is_rejected() {
        let noncanonical = [0xff_u8; 32];
        assert_eq!(
            commitment(1, &noncanonical),
            Err(ValueError::InvalidEncoding)
        );
        assert_eq!(
            prove_range(&[], &[], &[0_u8; 32]),
            Err(ValueError::BadLength)
        );
        assert_eq!(
            verify_balance(&[], &[], 0, 0, &[0_u8; 32], &[0_u8; 63]),
            Err(ValueError::BadLength)
        );
    }

    #[test]
    fn canonical_value_proving_request_self_verifies() {
        let pseudo_out = commitment(100, &scalar(5)).unwrap();
        let mut request = Vec::new();
        request.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.extend_from_slice(&[1, 1]);
        request.extend_from_slice(&0_i64.to_le_bytes());
        request.extend_from_slice(&10_u64.to_le_bytes());
        request.extend_from_slice(&[0x81; 32]);
        request.extend_from_slice(&[0x82; 32]);
        request.extend_from_slice(&scalar(3));
        request.extend_from_slice(&pseudo_out);
        request.extend_from_slice(&90_u64.to_le_bytes());
        request.extend_from_slice(&scalar(2));
        let response = prove_request(&request).unwrap();
        assert_eq!(&response[..4], &[1, 0, 1, 1]);
        assert_eq!(&response[4..36], &commitment(90, &scalar(2)).unwrap());
        // One signature under the value-excess key, and the response ends there: a second
        // one over the same message would be recoverable material, not extra assurance.
        let range_length = u32::from_le_bytes(response[36..40].try_into().unwrap()) as usize;
        assert_eq!(response.len(), 40 + range_length + 64);
        request.push(0);
        assert_eq!(prove_request(&request), Err(ResultCode::BadLength));
    }

    /// Nonce reuse across two challenge domains reveals the excess mask; the format
    /// therefore carries one value signature.
    #[test]
    fn one_nonce_under_two_challenges_recovers_the_excess_mask() {
        let input = commitment(100, &scalar(5)).unwrap();
        let output = commitment(90, &scalar(2)).unwrap();
        let excess_mask_bytes = scalar(3);
        let excess_mask = canonical_scalar(&excess_mask_bytes).unwrap();
        let signable_hash = [31_u8; 32];
        let entropy = [32_u8; 32];

        let excess = excess_point(&[input], &[output], 0, 10).unwrap();
        assert_eq!(excess, ED25519_BASEPOINT_POINT * excess_mask);
        let excess_encoded = excess.compress().to_bytes();

        let nonce = hash_to_scalar(
            b"Innova/IV5/BalanceProof/Nonce/v1",
            &[
                &entropy,
                &excess_mask_bytes,
                &signable_hash,
                &excess_encoded,
            ],
        );
        let nonce_encoded = (ED25519_BASEPOINT_POINT * nonce).compress().to_bytes();
        let sign_with = |domain: &[u8]| {
            let challenge =
                hash_to_scalar(domain, &[&signable_hash, &excess_encoded, &nonce_encoded]);
            (challenge, nonce + (challenge * excess_mask))
        };
        let (challenge_one, response_one) = sign_with(b"Innova/IV5/BalanceProof/Challenge/v1");
        let (challenge_two, response_two) = sign_with(b"Innova/IV5/BindingSignature/Challenge/v1");
        assert_ne!(challenge_one, challenge_two);

        let recovered = (response_one - response_two) * (challenge_one - challenge_two).invert();
        assert_eq!(recovered, excess_mask);
    }

    /// A mix: equal outputs of one denomination, input `i` paying `fee_shares[i]` over it
    /// and funding output `permutation[i]`. `tag` separates tests, since the signing
    /// record is process-wide.
    struct Mix {
        pseudo_outs: Vec<[u8; 32]>,
        outputs: Vec<[u8; 32]>,
        fee: u64,
        signable_hash: [u8; 32],
        fee_shares: Vec<u64>,
        permutation: Vec<usize>,
        masks: Vec<[u8; 32]>,
        entropy: Vec<[u8; 32]>,
    }

    impl Mix {
        const DENOMINATION: u64 = 10_000_000_000;

        fn new(tag: u8, fee_shares: &[u64], permutation: &[usize]) -> Self {
            let count = fee_shares.len();
            let base = 1000 * u64::from(tag);
            let pseudo_masks: Vec<[u8; 32]> = (0..count)
                .map(|index| scalar(base + 1 + u64::try_from(index).unwrap()))
                .collect();
            let output_masks: Vec<[u8; 32]> = (0..count)
                .map(|index| scalar(base + 100 + u64::try_from(index).unwrap()))
                .collect();
            let pseudo_outs = fee_shares
                .iter()
                .zip(&pseudo_masks)
                .map(|(fee_share, mask)| commitment(Self::DENOMINATION + fee_share, mask).unwrap())
                .collect();
            let outputs = output_masks
                .iter()
                .map(|mask| commitment(Self::DENOMINATION, mask).unwrap())
                .collect();
            let masks = permutation
                .iter()
                .zip(&pseudo_masks)
                .map(|(&output_index, pseudo_mask)| {
                    (canonical_scalar(pseudo_mask).unwrap()
                        - canonical_scalar(&output_masks[output_index]).unwrap())
                    .to_bytes()
                })
                .collect();
            let entropy = (0..count)
                .map(|index| {
                    let mut bytes = [tag; 32];
                    bytes[0] = u8::try_from(index).unwrap();
                    bytes
                })
                .collect();
            Self {
                pseudo_outs,
                outputs,
                fee: fee_shares.iter().sum(),
                signable_hash: [tag; 32],
                fee_shares: fee_shares.to_vec(),
                permutation: permutation.to_vec(),
                masks,
                entropy,
            }
        }

        fn instance(&self) -> BalanceInstance<'_> {
            BalanceInstance {
                pseudo_outs: &self.pseudo_outs,
                outputs: &self.outputs,
                transparent_value_balance: 0,
                fee: self.fee,
                signable_hash: &self.signable_hash,
            }
        }

        fn share(&self, index: usize) -> MixShare<'_> {
            MixShare {
                input_index: index,
                output_index: self.permutation[index],
                fee_share: self.fee_shares[index],
                mask: &self.masks[index],
                entropy: &self.entropy[index],
            }
        }

        fn verify(&self, proof: &[u8]) -> bool {
            verify_balance(
                &self.pseudo_outs,
                &self.outputs,
                0,
                self.fee,
                &self.signable_hash,
                proof,
            )
            .unwrap()
        }

        fn round(&self) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
            let instance = self.instance();
            let nonces: Vec<[u8; 32]> = (0..self.pseudo_outs.len())
                .map(|index| mix_share_nonce(&instance, &self.share(index)).unwrap())
                .collect();
            let responses = (0..self.pseudo_outs.len())
                .map(|index| mix_share_sign(&instance, &self.share(index), &nonces).unwrap())
                .collect();
            (nonces, responses)
        }

        fn instance_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&PAYLOAD_SCHEMA_U16.to_le_bytes());
            bytes.push(u8::try_from(self.outputs.len()).unwrap());
            bytes.push(u8::try_from(self.pseudo_outs.len()).unwrap());
            bytes.extend_from_slice(&0_i64.to_le_bytes());
            bytes.extend_from_slice(&self.fee.to_le_bytes());
            bytes.extend_from_slice(&self.signable_hash);
            for point in self.pseudo_outs.iter().chain(&self.outputs) {
                bytes.extend_from_slice(point);
            }
            bytes
        }

        fn share_bytes(&self, index: usize) -> Vec<u8> {
            let mut bytes = vec![
                u8::try_from(index).unwrap(),
                u8::try_from(self.permutation[index]).unwrap(),
                0,
                0,
            ];
            bytes.extend_from_slice(&self.fee_shares[index].to_le_bytes());
            bytes.extend_from_slice(&self.masks[index]);
            bytes.extend_from_slice(&self.entropy[index]);
            bytes
        }
    }

    #[test]
    fn a_three_party_mix_signs_one_balance_proof() {
        let mix = Mix::new(0x41, &[1, 1, 0], &[2, 0, 1]);
        let instance = mix.instance();
        let (nonces, responses) = mix.round();
        let proof = mix_balance_combine(&instance, &nonces, &responses).unwrap();
        assert!(mix.verify(&proof), "the joint proof must verify unchanged");
        assert!(
            !verify_balance(
                &mix.pseudo_outs,
                &mix.outputs,
                0,
                mix.fee,
                &[0x40; 32],
                &proof
            )
            .unwrap(),
            "a joint proof must not verify under another payload's hash"
        );
        assert!(
            !verify_balance(
                &mix.pseudo_outs,
                &mix.outputs,
                0,
                mix.fee + 1,
                &mix.signable_hash,
                &proof
            )
            .unwrap(),
            "a joint proof must not verify with another fee"
        );
        for index in 0..3 {
            assert!(mix_share_verify(
                &instance,
                index,
                mix.permutation[index],
                mix.fee_shares[index],
                &nonces,
                &responses[index],
            )
            .unwrap());
        }

        // Same round, same bytes: a retransmit learns nothing and answers nothing new.
        assert_eq!(
            mix_share_nonce(&instance, &mix.share(0)).unwrap(),
            nonces[0]
        );
        assert_eq!(
            mix_share_sign(&instance, &mix.share(0), &nonces).unwrap(),
            responses[0]
        );
        // The mix bounds: a joint proof over one participant is not a mix.
        assert_eq!(
            instance.aggregate_nonce(&nonces[..1]),
            Err(ValueError::BadLength)
        );
    }

    #[test]
    fn a_tampered_share_yields_no_proof_and_is_attributable() {
        let mix = Mix::new(0x42, &[2, 0, 1], &[1, 2, 0]);
        let instance = mix.instance();
        let (nonces, responses) = mix.round();

        let mut tampered = responses.clone();
        tampered[1] = (canonical_scalar(&tampered[1]).unwrap() + Scalar::ONE).to_bytes();
        assert_eq!(
            mix_balance_combine(&instance, &nonces, &tampered),
            Err(ValueError::InvalidProof),
            "a bad share must yield no proof, not a proof that fails on the network"
        );
        let verdicts: Vec<bool> = (0..3)
            .map(|index| {
                mix_share_verify(
                    &instance,
                    index,
                    mix.permutation[index],
                    mix.fee_shares[index],
                    &nonces,
                    &tampered[index],
                )
                .unwrap()
            })
            .collect();
        assert_eq!(verdicts, [true, false, true]);

        // A participant cannot sign for a pair its mask does not open, nor claim a fee
        // share it did not leave: both are refused before a nonce exists.
        let one = scalar(1);
        let wrong_mask = MixShare {
            mask: &one,
            ..mix.share(0)
        };
        assert_eq!(
            mix_share_nonce(&instance, &wrong_mask),
            Err(ValueError::InvalidProof)
        );
        let wrong_fee = MixShare {
            fee_share: mix.fee_shares[0] + 1,
            ..mix.share(0)
        };
        assert_eq!(
            mix_share_nonce(&instance, &wrong_fee),
            Err(ValueError::InvalidProof)
        );
        // Nor sign under a list that does not carry its own point at its input index.
        let mut swapped = nonces.clone();
        swapped.swap(0, 1);
        assert_eq!(
            mix_share_sign(&instance, &mix.share(0), &swapped),
            Err(ValueError::InvalidProof)
        );
        // Shares that each open but do not cover the fee produce no proof either.
        let short = Mix {
            fee: mix.fee + 1,
            ..Mix::new(0x42, &[2, 0, 1], &[1, 2, 0])
        };
        let (short_nonces, short_responses) = short.round();
        assert_eq!(
            mix_balance_combine(&short.instance(), &short_nonces, &short_responses),
            Err(ValueError::InvalidProof)
        );
    }

    /// Two-aggregate nonce reuse recovers the mask; the signing record refuses it.
    #[test]
    fn an_adaptive_coordinator_is_refused_a_second_signature() {
        let mix = Mix::new(0x43, &[1, 1, 1], &[0, 1, 2]);
        let instance = mix.instance();
        let victim = mix.share(0);
        let victim_nonce = mix_share_nonce(&instance, &victim).unwrap();
        // The coordinator holds inputs 1 and 2 and publishes whatever points it likes.
        let sybil = |round: u64, index: u64| {
            (ED25519_BASEPOINT_POINT * Scalar::from(round * 1000 + index))
                .compress()
                .to_bytes()
        };
        let first = [victim_nonce, sybil(1, 1), sybil(1, 2)];
        let second = [victim_nonce, sybil(2, 1), sybil(2, 2)];
        let response = mix_share_sign(&instance, &victim, &first).unwrap();

        // What the second response would give away, from the derivation directly.
        let excess_encoded = instance.excess_encoded().unwrap();
        let (mask, nonce) = victim.secrets(&instance, &excess_encoded).unwrap();
        let first_challenge =
            instance.challenge(&excess_encoded, &instance.aggregate_nonce(&first).unwrap());
        let second_challenge =
            instance.challenge(&excess_encoded, &instance.aggregate_nonce(&second).unwrap());
        assert_ne!(first_challenge, second_challenge);
        let would_be = nonce + second_challenge * mask;
        let recovered = (canonical_scalar(&response).unwrap() - would_be)
            * (first_challenge - second_challenge).invert();
        assert_eq!(
            recovered, mask,
            "one nonce under two challenges is the mask"
        );

        assert_eq!(
            mix_share_sign(&instance, &victim, &second),
            Err(ValueError::NonceReuse),
            "the second round must be refused, not answered"
        );
        assert_eq!(
            mix_share_sign(&instance, &victim, &first),
            Ok(response),
            "the refusal must not lock the honest round out"
        );
        // A permutation of the same points is the same aggregate and the same challenge.
        let permuted = [victim_nonce, sybil(1, 2), sybil(1, 1)];
        assert_eq!(mix_share_sign(&instance, &victim, &permuted), Ok(response));

        // Fresh entropy is a fresh nonce: it may sign under a new aggregate, and solving
        // the two responses as if they shared a nonce yields nothing.
        let fresh_entropy = [0x44; 32];
        let fresh = MixShare {
            entropy: &fresh_entropy,
            ..victim
        };
        let fresh_nonce = mix_share_nonce(&instance, &fresh).unwrap();
        assert_ne!(fresh_nonce, victim_nonce);
        let third = [fresh_nonce, sybil(2, 1), sybil(2, 2)];
        let fresh_response = mix_share_sign(&instance, &fresh, &third).unwrap();
        let third_challenge =
            instance.challenge(&excess_encoded, &instance.aggregate_nonce(&third).unwrap());
        let naive = (canonical_scalar(&response).unwrap()
            - canonical_scalar(&fresh_response).unwrap())
            * (first_challenge - third_challenge).invert();
        assert_ne!(naive, mask);
    }

    /// The single-party prover is pinned to its known bytes.
    #[test]
    fn the_single_party_balance_proof_is_byte_identical() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        let input = commitment(100, &scalar(5)).unwrap();
        let output = commitment(90, &scalar(2)).unwrap();
        let transfer = prove_balance(
            &[input],
            &[output],
            0,
            10,
            &scalar(3),
            &[21_u8; 32],
            &[22_u8; 32],
        )
        .unwrap();
        assert_eq!(
            hex(&transfer),
            "8dc26217fcdb6989397c6628ad3598682e69b4bdefba6f5cfb11c93dfc62438a\
             bce053c167e02e4ccbf895d558253998cc0c11ce79e00d063f33a72dfaf7d40a"
        );
        let shielded = commitment(50, &scalar(7)).unwrap();
        let shield = prove_balance(
            &[],
            &[shielded],
            51,
            1,
            &(-Scalar::from(7_u64)).to_bytes(),
            &[21_u8; 32],
            &[23_u8; 32],
        )
        .unwrap();
        assert_eq!(
            hex(&shield),
            "8bed74f9d23b0d130e351dbd9a7a0cd8af49473968e4e9fd9ee0aac17b5703f0\
             57714e81f18fe0ab43e0bc4b23734faccdd234b3a8a174f760d6876c7f7aa501"
        );
    }

    #[test]
    fn mix_requests_follow_their_layouts() {
        let mix = Mix::new(0x45, &[1, 0], &[1, 0]);
        let instance = mix.instance();
        let facts = mix.instance_bytes();
        assert_eq!(facts.len(), MIX_INSTANCE_HEADER_BYTES + 4 * 32);
        assert_eq!(mix.share_bytes(0).len(), MIX_SHARE_BYTES);

        let nonce_request = |index: usize| [facts.clone(), mix.share_bytes(index)].concat();
        let nonces = [
            mix_nonce_request(&nonce_request(0)).unwrap(),
            mix_nonce_request(&nonce_request(1)).unwrap(),
        ];
        assert_eq!(
            nonces[0],
            mix_share_nonce(&instance, &mix.share(0)).unwrap()
        );
        let sign_request =
            |index: usize| [nonce_request(index), nonces[0].to_vec(), nonces[1].to_vec()].concat();
        let responses = [
            mix_sign_request(&sign_request(0)).unwrap(),
            mix_sign_request(&sign_request(1)).unwrap(),
        ];
        assert_eq!(
            responses[1],
            mix_share_sign(&instance, &mix.share(1), &nonces).unwrap()
        );
        let combine_request = [facts.clone(), nonces.concat(), responses.concat()].concat();
        let proof = mix_combine_request(&combine_request).unwrap();
        assert!(mix.verify(&proof));

        // Every layout is exact.
        let exact = |parse: &dyn Fn(&[u8]) -> Option<ResultCode>, request: &[u8]| {
            let mut longer = request.to_vec();
            longer.push(0);
            assert_eq!(parse(&longer), Some(ResultCode::BadLength));
            assert_eq!(
                parse(&request[..request.len() - 1]),
                Some(ResultCode::BadLength)
            );
        };
        exact(&|bytes| mix_nonce_request(bytes).err(), &nonce_request(0));
        exact(&|bytes| mix_sign_request(bytes).err(), &sign_request(0));
        exact(&|bytes| mix_combine_request(bytes).err(), &combine_request);
        let mut wrong_schema = nonce_request(0);
        wrong_schema[0] = 2;
        assert_eq!(
            mix_nonce_request(&wrong_schema),
            Err(ResultCode::UnsupportedFormat)
        );
        let mut reserved = nonce_request(0);
        reserved[facts.len() + 2] = 1;
        assert_eq!(
            mix_nonce_request(&reserved),
            Err(ResultCode::ConsensusInvalid)
        );
        let mut zero_entropy = nonce_request(0);
        zero_entropy[facts.len() + 44..].fill(0);
        assert_eq!(
            mix_nonce_request(&zero_entropy),
            Err(ResultCode::ConsensusInvalid)
        );
        let mut out_of_range = nonce_request(0);
        out_of_range[facts.len()] = 2;
        assert_eq!(
            mix_nonce_request(&out_of_range),
            Err(ResultCode::ConsensusInvalid)
        );
        let mut tampered = combine_request;
        tampered[facts.len() + 64] ^= 1;
        assert_eq!(
            mix_combine_request(&tampered),
            Err(ResultCode::ConsensusInvalid)
        );

        // The participant bounds are read before any point is.
        let mut alone = facts.clone();
        alone[3] = 1;
        assert_eq!(mix_nonce_request(&alone), Err(ResultCode::ConsensusInvalid));
        let mut crowd = facts;
        crowd[3] = u8::try_from(MAX_NULLSEND_INPUTS + 1).unwrap();
        assert_eq!(mix_nonce_request(&crowd), Err(ResultCode::ResourceLimit));
    }
}
