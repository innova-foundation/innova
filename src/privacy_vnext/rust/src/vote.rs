//! Note-vote primitives: the authorization sigma, ed25519 point arithmetic for the
//! tally's statements, and a single-commitment range proof. A membership proof binds
//! no message, so every field a note vote binds travels in the sigma's challenge.

use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use monero_ed25519::CompressedPoint;

use crate::{fcmp, hash_to_point::vote_tag_base, value, ResultCode};

pub(crate) const SIGMA_PROVE_REQUEST_BYTES: usize = 204;
pub(crate) const SIGMA_PROOF_BYTES: usize = 128;
pub(crate) const SIGMA_PROVE_RESPONSE_BYTES: usize = 32 + SIGMA_PROOF_BYTES;
pub(crate) const SIGMA_VERIFY_REQUEST_BYTES: usize = 140 + SIGMA_PROOF_BYTES;
pub(crate) const MAX_COMBINE_TERMS: usize = 1024;
pub(crate) const RANGE_PROVE_REQUEST_BYTES: usize = 76;

const SIGMA_NONCE_DOMAIN: &[u8] = b"Innova/IV5/Vote/SigmaNonce/v1";
const SIGMA_CHALLENGE_DOMAIN: &[u8] = b"Innova/IV5/Vote/SigmaChallenge/v1";

const TERM_SOURCE_SUPPLIED: u8 = 0;
const TERM_SOURCE_MONERO_H: u8 = 1;
const TERM_SOURCE_ED25519_G: u8 = 2;

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ResultCode> {
        if self.bytes.len() < count {
            return Err(ResultCode::BadLength);
        }
        let (head, tail) = self.bytes.split_at(count);
        self.bytes = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ResultCode> {
        let mut out = [0_u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ResultCode> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ResultCode> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ResultCode> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn zeroes(&mut self, count: usize) -> Result<(), ResultCode> {
        if self.take(count)?.iter().any(|byte| *byte != 0) {
            return Err(ResultCode::ConsensusInvalid);
        }
        Ok(())
    }

    fn rest(self) -> &'a [u8] {
        self.bytes
    }

    fn finish(self) -> Result<(), ResultCode> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(ResultCode::BadLength)
        }
    }
}

fn header(reader: &mut Reader<'_>) -> Result<(), ResultCode> {
    if reader.u16()? != crate::PAYLOAD_SCHEMA_U16 {
        return Err(ResultCode::UnsupportedFormat);
    }
    reader.zeroes(2)
}

fn monero_h() -> EdwardsPoint {
    CompressedEdwardsY(CompressedPoint::H.to_bytes())
        .decompress()
        .expect("the pinned Monero H encoding must decompress")
}

fn monero_t() -> EdwardsPoint {
    CompressedEdwardsY(CompressedPoint::T.to_bytes())
        .decompress()
        .expect("the pinned Monero T encoding must decompress")
}

fn canonical_scalar(bytes: &[u8; 32]) -> Result<Scalar, ResultCode> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).ok_or(ResultCode::ConsensusInvalid)
}

fn canonical_point(bytes: &[u8; 32], allow_identity: bool) -> Result<EdwardsPoint, ResultCode> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .filter(|point| point.compress().to_bytes() == *bytes)
        .filter(EdwardsPoint::is_torsion_free)
        .ok_or(ResultCode::ConsensusInvalid)?;
    if !allow_identity && point.is_identity() {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(point)
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

struct SigmaStatement {
    epoch: u64,
    o_tilde: EdwardsPoint,
    o_tilde_bytes: [u8; 32],
    c_tilde_bytes: [u8; 32],
    binding: [u8; 32],
    tag_base: EdwardsPoint,
    tag_base_bytes: [u8; 32],
}

impl SigmaStatement {
    fn read(reader: &mut Reader<'_>) -> Result<Self, ResultCode> {
        let epoch = reader.u64()?;
        let o_tilde_bytes = reader.array()?;
        let c_tilde_bytes = reader.array()?;
        let binding = reader.array()?;
        let o_tilde = canonical_point(&o_tilde_bytes, false)?;
        // C~ never enters an equation here; it is transcripted so a sigma cannot be moved
        // onto a different membership instance's amount commitment.
        canonical_point(&c_tilde_bytes, false)?;
        let tag_base = vote_tag_base(epoch);
        let tag_base_bytes = tag_base.compress().to_bytes();
        Ok(SigmaStatement {
            epoch,
            o_tilde,
            o_tilde_bytes,
            c_tilde_bytes,
            binding,
            tag_base,
            tag_base_bytes,
        })
    }

    fn challenge(&self, tag_bytes: &[u8; 32], r1: &[u8; 32], r2: &[u8; 32]) -> Scalar {
        hash_to_scalar(
            SIGMA_CHALLENGE_DOMAIN,
            &[
                &self.epoch.to_le_bytes(),
                &self.tag_base_bytes,
                &self.o_tilde_bytes,
                &self.c_tilde_bytes,
                tag_bytes,
                &self.binding,
                r1,
                r2,
            ],
        )
    }
}

/// Prove membership and report the per-input sigma witnesses alongside the canonical
/// verification request. The witnesses depend on blinds the prover draws internally, so a
/// caller cannot reconstruct them from the request it sent.
pub(crate) fn membership_prove(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    let (verification, secrets) = fcmp::prove_membership_with_secrets(request)?;
    let count = u8::try_from(secrets.len()).map_err(|_| ResultCode::ResourceLimit)?;
    let mut response = Vec::with_capacity(8 + secrets.len() * 128 + verification.len());
    response.extend_from_slice(&crate::PAYLOAD_SCHEMA_U16.to_le_bytes());
    response.push(count);
    response.push(0);
    for secret in &secrets {
        response.extend_from_slice(&secret.o_tilde);
        response.extend_from_slice(&secret.c_tilde);
        response.extend_from_slice(&secret.rerandomized_y);
        response.extend_from_slice(&secret.mask_delta);
    }
    response.extend_from_slice(
        &u32::try_from(verification.len())
            .map_err(|_| ResultCode::ResourceLimit)?
            .to_le_bytes(),
    );
    response.extend_from_slice(&verification);
    Ok(response)
}

/// Prove `O~ = xG + yT` and `T_e = x*U_e` under one challenge.
pub(crate) fn sigma_prove(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    if request.len() != SIGMA_PROVE_REQUEST_BYTES {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    header(&mut reader)?;
    let statement = SigmaStatement::read(&mut reader)?;
    let x = canonical_scalar(&reader.array()?)?;
    let y_tilde = canonical_scalar(&reader.array()?)?;
    let entropy: [u8; 32] = reader.array()?;
    reader.finish()?;
    if entropy.iter().all(|byte| *byte == 0) || x == Scalar::ZERO {
        return Err(ResultCode::ConsensusInvalid);
    }

    let t = monero_t();
    if statement.o_tilde != (ED25519_BASEPOINT_POINT * x) + (t * y_tilde) {
        return Err(ResultCode::ConsensusInvalid);
    }
    let tag = statement.tag_base * x;
    if tag.is_identity() {
        return Err(ResultCode::ConsensusInvalid);
    }
    let tag_bytes = tag.compress().to_bytes();

    // Hedged: the nonce depends on the witness and the full statement as well as the caller's
    // entropy, so a repeated or degenerate draw does not leak x.
    let nonce_x = hash_to_scalar(
        SIGMA_NONCE_DOMAIN,
        &[
            &entropy,
            &x.to_bytes(),
            &y_tilde.to_bytes(),
            &statement.epoch.to_le_bytes(),
            &statement.o_tilde_bytes,
            &statement.c_tilde_bytes,
            &statement.binding,
            b"x",
        ],
    );
    let nonce_y = hash_to_scalar(
        SIGMA_NONCE_DOMAIN,
        &[
            &entropy,
            &x.to_bytes(),
            &y_tilde.to_bytes(),
            &statement.epoch.to_le_bytes(),
            &statement.o_tilde_bytes,
            &statement.c_tilde_bytes,
            &statement.binding,
            b"y",
        ],
    );
    if nonce_x == Scalar::ZERO {
        return Err(ResultCode::InternalLocalStateFailure);
    }

    let r1 = ((ED25519_BASEPOINT_POINT * nonce_x) + (t * nonce_y))
        .compress()
        .to_bytes();
    let r2 = (statement.tag_base * nonce_x).compress().to_bytes();
    let challenge = statement.challenge(&tag_bytes, &r1, &r2);
    let s_x = nonce_x + (challenge * x);
    let s_y = nonce_y + (challenge * y_tilde);

    let mut response = Vec::with_capacity(SIGMA_PROVE_RESPONSE_BYTES);
    response.extend_from_slice(&tag_bytes);
    response.extend_from_slice(&r1);
    response.extend_from_slice(&r2);
    response.extend_from_slice(&s_x.to_bytes());
    response.extend_from_slice(&s_y.to_bytes());

    // A proof that does not verify under the exported verifier must never leave the prover.
    let mut check = Vec::with_capacity(SIGMA_VERIFY_REQUEST_BYTES);
    check.extend_from_slice(&crate::PAYLOAD_SCHEMA_U16.to_le_bytes());
    check.extend_from_slice(&[0; 2]);
    check.extend_from_slice(&statement.epoch.to_le_bytes());
    check.extend_from_slice(&statement.o_tilde_bytes);
    check.extend_from_slice(&statement.c_tilde_bytes);
    check.extend_from_slice(&statement.binding);
    check.extend_from_slice(&response);
    sigma_verify(&check)?;
    Ok(response)
}

pub(crate) fn sigma_verify(request: &[u8]) -> Result<(), ResultCode> {
    if request.len() != SIGMA_VERIFY_REQUEST_BYTES {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    header(&mut reader)?;
    let statement = SigmaStatement::read(&mut reader)?;
    let tag_bytes: [u8; 32] = reader.array()?;
    let r1: [u8; 32] = reader.array()?;
    let r2: [u8; 32] = reader.array()?;
    let s_x = canonical_scalar(&reader.array()?)?;
    let s_y = canonical_scalar(&reader.array()?)?;
    reader.finish()?;

    let tag = canonical_point(&tag_bytes, false)?;
    let nonce_1 = canonical_point(&r1, false)?;
    let nonce_2 = canonical_point(&r2, false)?;
    let challenge = statement.challenge(&tag_bytes, &r1, &r2);

    let t = monero_t();
    let left_1 = (ED25519_BASEPOINT_POINT * s_x) + (t * s_y);
    let left_2 = statement.tag_base * s_x;
    if left_1 != nonce_1 + (statement.o_tilde * challenge) || left_2 != nonce_2 + (tag * challenge)
    {
        return Err(ResultCode::ConsensusInvalid);
    }
    Ok(())
}

/// Sum `scalar * point` over caller-named terms, where a point is either supplied or one of
/// the two pinned generators. The identity is a legal result: a certificate whose winner
/// drew no note vote derives exactly that.
pub(crate) fn combine(request: &[u8]) -> Result<[u8; 32], ResultCode> {
    let mut reader = Reader::new(request);
    header(&mut reader)?;
    let count = usize::from(reader.u16()?);
    reader.zeroes(2)?;
    if count > MAX_COMBINE_TERMS {
        return Err(ResultCode::ResourceLimit);
    }

    let mut total = EdwardsPoint::identity();
    for _ in 0..count {
        let source = reader.u8()?;
        reader.zeroes(3)?;
        let scalar = canonical_scalar(&reader.array()?)?;
        let point_bytes: [u8; 32] = reader.array()?;
        let point = match source {
            TERM_SOURCE_SUPPLIED => canonical_point(&point_bytes, true)?,
            TERM_SOURCE_MONERO_H | TERM_SOURCE_ED25519_G => {
                if point_bytes.iter().any(|byte| *byte != 0) {
                    return Err(ResultCode::ConsensusInvalid);
                }
                if source == TERM_SOURCE_MONERO_H {
                    monero_h()
                } else {
                    ED25519_BASEPOINT_POINT
                }
            }
            _ => return Err(ResultCode::UnsupportedFormat),
        };
        total += point * scalar;
    }
    reader.finish()?;
    Ok(total.compress().to_bytes())
}

/// Range-prove one opening. The response carries the commitment the proof is over so a caller
/// can check it equals the point it derived independently.
pub(crate) fn range_prove(request: &[u8]) -> Result<Vec<u8>, ResultCode> {
    if request.len() != RANGE_PROVE_REQUEST_BYTES {
        return Err(ResultCode::BadLength);
    }
    let mut reader = Reader::new(request);
    header(&mut reader)?;
    let amount = reader.u64()?;
    let mask: [u8; 32] = reader.array()?;
    let entropy: [u8; 32] = reader.array()?;
    reader.finish()?;
    if entropy.iter().all(|byte| *byte == 0) {
        return Err(ResultCode::ConsensusInvalid);
    }

    let (commitments, proof) =
        value::prove_range(&[amount], &[mask], &entropy).map_err(value::result_code)?;
    if commitments.len() != 1 {
        return Err(ResultCode::InternalLocalStateFailure);
    }
    let mut response = Vec::with_capacity(36 + proof.len());
    response.extend_from_slice(&commitments[0]);
    response.extend_from_slice(
        &u32::try_from(proof.len())
            .map_err(|_| ResultCode::ResourceLimit)?
            .to_le_bytes(),
    );
    response.extend_from_slice(&proof);
    Ok(response)
}

pub(crate) fn range_verify(request: &[u8]) -> Result<(), ResultCode> {
    let mut reader = Reader::new(request);
    header(&mut reader)?;
    let commitment: [u8; 32] = reader.array()?;
    let signable: [u8; 32] = reader.array()?;
    let proof = reader.rest();
    if proof.is_empty() {
        return Err(ResultCode::BadLength);
    }
    // The identity opens to zero under any mask, so it carries no in-range claim at all.
    canonical_point(&commitment, false)?;
    match value::verify_range(&[commitment], proof, &signable) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ResultCode::ConsensusInvalid),
        Err(error) => Err(value::result_code(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sigma_prove_request(
        epoch: u64,
        o_tilde: &[u8; 32],
        c_tilde: &[u8; 32],
        binding: &[u8; 32],
        x: &Scalar,
        y: &Scalar,
        entropy: &[u8; 32],
    ) -> Vec<u8> {
        let mut request = Vec::with_capacity(SIGMA_PROVE_REQUEST_BYTES);
        request.extend_from_slice(&crate::PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.extend_from_slice(&[0; 2]);
        request.extend_from_slice(&epoch.to_le_bytes());
        request.extend_from_slice(o_tilde);
        request.extend_from_slice(c_tilde);
        request.extend_from_slice(binding);
        request.extend_from_slice(&x.to_bytes());
        request.extend_from_slice(&y.to_bytes());
        request.extend_from_slice(entropy);
        request
    }

    fn sigma_verify_request(
        epoch: u64,
        o_tilde: &[u8; 32],
        c_tilde: &[u8; 32],
        binding: &[u8; 32],
        response: &[u8],
    ) -> Vec<u8> {
        let mut request = Vec::with_capacity(SIGMA_VERIFY_REQUEST_BYTES);
        request.extend_from_slice(&crate::PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.extend_from_slice(&[0; 2]);
        request.extend_from_slice(&epoch.to_le_bytes());
        request.extend_from_slice(o_tilde);
        request.extend_from_slice(c_tilde);
        request.extend_from_slice(binding);
        request.extend_from_slice(response);
        request
    }

    fn instance(seed: u8) -> (Scalar, Scalar, [u8; 32], [u8; 32]) {
        let x = Scalar::from(1_000_003_u64 + u64::from(seed));
        let y = Scalar::from(7_777_777_u64 + u64::from(seed));
        let o_tilde = ((ED25519_BASEPOINT_POINT * x) + (monero_t() * y))
            .compress()
            .to_bytes();
        let c_tilde = (monero_h() * Scalar::from(4_200_u64 + u64::from(seed))
            + ED25519_BASEPOINT_POINT * Scalar::from(99_u64 + u64::from(seed)))
        .compress()
        .to_bytes();
        (x, y, o_tilde, c_tilde)
    }

    #[test]
    fn sigma_round_trips_and_publishes_a_tag_only_the_witness_reaches() {
        let (x, y, o_tilde, c_tilde) = instance(1);
        let binding = [9_u8; 32];
        let response = sigma_prove(&sigma_prove_request(
            42, &o_tilde, &c_tilde, &binding, &x, &y, &[3; 32],
        ))
        .expect("the sigma must prove");
        assert_eq!(response.len(), SIGMA_PROVE_RESPONSE_BYTES);
        assert_eq!(
            &response[..32],
            &(vote_tag_base(42) * x).compress().to_bytes()
        );
        sigma_verify(&sigma_verify_request(
            42, &o_tilde, &c_tilde, &binding, &response,
        ))
        .expect("the sigma must verify");
    }

    // Every field the challenge covers is a field a whole valid vote could otherwise be
    // replayed under, so each one must break verification on its own.
    #[test]
    fn every_bound_field_rejects_a_substitution() {
        let (x, y, o_tilde, c_tilde) = instance(2);
        let binding = [1_u8; 32];
        let response = sigma_prove(&sigma_prove_request(
            7, &o_tilde, &c_tilde, &binding, &x, &y, &[5; 32],
        ))
        .expect("the sigma must prove");

        let (_, _, other_o, other_c) = instance(3);
        let mut other_binding = binding;
        other_binding[0] ^= 1;
        for (label, request) in [
            (
                "epoch",
                sigma_verify_request(8, &o_tilde, &c_tilde, &binding, &response),
            ),
            (
                "o_tilde",
                sigma_verify_request(7, &other_o, &c_tilde, &binding, &response),
            ),
            (
                "c_tilde",
                sigma_verify_request(7, &o_tilde, &other_c, &binding, &response),
            ),
            (
                "binding",
                sigma_verify_request(7, &o_tilde, &c_tilde, &other_binding, &response),
            ),
        ] {
            assert_eq!(
                sigma_verify(&request),
                Err(ResultCode::ConsensusInvalid),
                "substituting {label} must break the sigma"
            );
        }

        let mut tag_swapped = response.clone();
        tag_swapped[..32]
            .copy_from_slice(&(vote_tag_base(7) * (x + Scalar::ONE)).compress().to_bytes());
        assert_eq!(
            sigma_verify(&sigma_verify_request(
                7,
                &o_tilde,
                &c_tilde,
                &binding,
                &tag_swapped
            )),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    // The tag is the whole dedup mechanism: one note reaches one tag per epoch and a
    // different epoch must reach a different one.
    #[test]
    fn the_tag_is_note_stable_within_an_epoch_and_rotates_across_them() {
        let (x, y, o_tilde, c_tilde) = instance(4);
        let first = sigma_prove(&sigma_prove_request(
            11,
            &o_tilde,
            &c_tilde,
            &[0xaa; 32],
            &x,
            &y,
            &[1; 32],
        ))
        .expect("prove");
        let second = sigma_prove(&sigma_prove_request(
            11,
            &o_tilde,
            &c_tilde,
            &[0xbb; 32],
            &x,
            &y,
            &[2; 32],
        ))
        .expect("prove");
        let next_epoch = sigma_prove(&sigma_prove_request(
            12,
            &o_tilde,
            &c_tilde,
            &[0xaa; 32],
            &x,
            &y,
            &[1; 32],
        ))
        .expect("prove");
        assert_eq!(first[..32], second[..32]);
        assert_ne!(first[..32], next_epoch[..32]);
    }

    #[test]
    fn a_witness_that_does_not_open_the_statement_is_refused() {
        let (x, y, o_tilde, c_tilde) = instance(5);
        assert_eq!(
            sigma_prove(&sigma_prove_request(
                1,
                &o_tilde,
                &c_tilde,
                &[0; 32],
                &(x + Scalar::ONE),
                &y,
                &[1; 32]
            )),
            Err(ResultCode::ConsensusInvalid)
        );
        assert_eq!(
            sigma_prove(&sigma_prove_request(
                1, &o_tilde, &c_tilde, &[0; 32], &x, &y, &[0; 32]
            )),
            Err(ResultCode::ConsensusInvalid)
        );
    }

    fn combine_request(terms: &[(u8, Scalar, [u8; 32])]) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(&crate::PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.extend_from_slice(&[0; 2]);
        request.extend_from_slice(&u16::try_from(terms.len()).expect("bounded").to_le_bytes());
        request.extend_from_slice(&[0; 2]);
        for (source, scalar, point) in terms {
            request.push(*source);
            request.extend_from_slice(&[0; 3]);
            request.extend_from_slice(&scalar.to_bytes());
            request.extend_from_slice(point);
        }
        request
    }

    #[test]
    fn combination_sums_supplied_points_and_pinned_generators() {
        let (_, _, o_tilde, c_tilde) = instance(6);
        let two = Scalar::from(2_u64);
        let three = Scalar::from(3_u64);
        let combined = combine(&combine_request(&[
            (TERM_SOURCE_SUPPLIED, two, o_tilde),
            (TERM_SOURCE_SUPPLIED, three, c_tilde),
            (TERM_SOURCE_MONERO_H, Scalar::from(5_u64), [0; 32]),
            (TERM_SOURCE_ED25519_G, Scalar::from(7_u64), [0; 32]),
        ]))
        .expect("combine");
        let expected = (canonical_point(&o_tilde, false).unwrap() * two)
            + (canonical_point(&c_tilde, false).unwrap() * three)
            + (monero_h() * Scalar::from(5_u64))
            + (ED25519_BASEPOINT_POINT * Scalar::from(7_u64));
        assert_eq!(combined, expected.compress().to_bytes());

        // An empty term list is the identity, which is what an epoch with no note vote for
        // the winner derives.
        assert_eq!(
            combine(&combine_request(&[])).expect("combine"),
            EdwardsPoint::identity().compress().to_bytes()
        );
    }

    #[test]
    fn a_generator_term_may_not_smuggle_a_point() {
        let (_, _, o_tilde, _) = instance(7);
        assert_eq!(
            combine(&combine_request(&[(
                TERM_SOURCE_MONERO_H,
                Scalar::ONE,
                o_tilde
            )])),
            Err(ResultCode::ConsensusInvalid)
        );
        assert_eq!(
            combine(&combine_request(&[(9, Scalar::ONE, [0; 32])])),
            Err(ResultCode::UnsupportedFormat)
        );
    }

    fn range_prove_request(amount: u64, mask: &[u8; 32], entropy: &[u8; 32]) -> Vec<u8> {
        let mut request = Vec::with_capacity(RANGE_PROVE_REQUEST_BYTES);
        request.extend_from_slice(&crate::PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.extend_from_slice(&[0; 2]);
        request.extend_from_slice(&amount.to_le_bytes());
        request.extend_from_slice(mask);
        request.extend_from_slice(entropy);
        request
    }

    fn range_verify_request(commitment: &[u8; 32], signable: &[u8; 32], proof: &[u8]) -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(&crate::PAYLOAD_SCHEMA_U16.to_le_bytes());
        request.extend_from_slice(&[0; 2]);
        request.extend_from_slice(commitment);
        request.extend_from_slice(signable);
        request.extend_from_slice(proof);
        request
    }

    #[test]
    fn a_range_proof_verifies_only_against_the_point_it_was_made_over() {
        let mask = Scalar::from(1_234_567_u64).to_bytes();
        let response =
            range_prove(&range_prove_request(9_000_000, &mask, &[4; 32])).expect("range prove");
        let mut commitment = [0_u8; 32];
        commitment.copy_from_slice(&response[..32]);
        let proof_len = u32::from_le_bytes(response[32..36].try_into().unwrap()) as usize;
        let proof = &response[36..36 + proof_len];

        // The response commitment must be exactly the derived point a validator rebuilds.
        let derived = (monero_h() * Scalar::from(9_000_000_u64))
            + (ED25519_BASEPOINT_POINT * canonical_scalar(&mask).unwrap());
        assert_eq!(commitment, derived.compress().to_bytes());

        range_verify(&range_verify_request(&commitment, &[0; 32], proof)).expect("verify");

        let (_, _, other, _) = instance(8);
        assert!(range_verify(&range_verify_request(&other, &[0; 32], proof)).is_err());
        assert_eq!(
            range_verify(&range_verify_request(
                &EdwardsPoint::identity().compress().to_bytes(),
                &[0; 32],
                proof
            )),
            Err(ResultCode::ConsensusInvalid)
        );
    }
}
