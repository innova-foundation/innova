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

use crate::{ResultCode, PAYLOAD_SCHEMA_U16};

pub(crate) const MAX_VALUE_COMMITMENTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValueError {
    BadLength,
    InvalidEncoding,
    InvalidProof,
    ResourceLimit,
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

fn result_code(error: ValueError) -> ResultCode {
    match error {
        ValueError::BadLength => ResultCode::BadLength,
        ValueError::ResourceLimit => ResultCode::ResourceLimit,
        ValueError::InvalidEncoding | ValueError::InvalidProof => ResultCode::ConsensusInvalid,
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
                !verify_amount_equality(&commitment, wrong, &signable_hash, &proof).unwrap_or(false),
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
            prove_amount_equality(&foreign, TIER, &scalar(11), &signable_hash, &[0x64; 32]).unwrap();
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
}
