use blake2::{Blake2b512, Digest};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use monero_ed25519::CompressedPoint;

pub(crate) const SENDER_PROOF_BYTES: usize = 128;
pub(crate) const RECEIVER_PROOF_BYTES: usize = 160;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DisclosureError {
    BadLength,
    InvalidEncoding,
    InvalidProof,
}

fn canonical_scalar(bytes: &[u8; 32]) -> Result<Scalar, DisclosureError> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or(DisclosureError::InvalidEncoding)
}

fn canonical_point(bytes: &[u8; 32]) -> Result<EdwardsPoint, DisclosureError> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .filter(|point| point.compress().to_bytes() == *bytes)
        .filter(EdwardsPoint::is_torsion_free)
        .ok_or(DisclosureError::InvalidEncoding)?;
    if point.is_identity() {
        return Err(DisclosureError::InvalidEncoding);
    }
    Ok(point)
}

fn monero_t() -> EdwardsPoint {
    CompressedEdwardsY(CompressedPoint::T.to_bytes())
        .decompress()
        .expect("the pinned Monero T encoding must decompress")
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

#[allow(clippy::too_many_arguments)]
fn schnorr_prove(
    nonce_domain: &[u8],
    challenge_domain: &[u8],
    generator: EdwardsPoint,
    public: EdwardsPoint,
    witness: Scalar,
    signable_hash: &[u8; 32],
    index: u32,
    context: &[u8],
    entropy: &[u8; 32],
) -> Result<[u8; 64], DisclosureError> {
    if public != generator * witness || entropy.iter().all(|byte| *byte == 0) {
        return Err(DisclosureError::InvalidProof);
    }
    let public_bytes = public.compress().to_bytes();
    let index_bytes = index.to_le_bytes();
    let mut nonce = hash_to_scalar(
        nonce_domain,
        &[
            entropy,
            &witness.to_bytes(),
            signable_hash,
            &index_bytes,
            context,
            &public_bytes,
        ],
    );
    if nonce == Scalar::ZERO {
        nonce = Scalar::ONE;
    }
    let nonce_bytes = (generator * nonce).compress().to_bytes();
    let challenge = hash_to_scalar(
        challenge_domain,
        &[
            signable_hash,
            &index_bytes,
            context,
            &public_bytes,
            &nonce_bytes,
        ],
    );
    let response = nonce + (challenge * witness);
    let mut proof = [0_u8; 64];
    proof[..32].copy_from_slice(&nonce_bytes);
    proof[32..].copy_from_slice(&response.to_bytes());
    Ok(proof)
}

fn schnorr_verify(
    challenge_domain: &[u8],
    generator: EdwardsPoint,
    public: EdwardsPoint,
    signable_hash: &[u8; 32],
    index: u32,
    context: &[u8],
    proof: &[u8],
) -> Result<bool, DisclosureError> {
    if proof.len() != 64 {
        return Err(DisclosureError::BadLength);
    }
    let mut nonce_bytes = [0_u8; 32];
    nonce_bytes.copy_from_slice(&proof[..32]);
    let nonce = canonical_point(&nonce_bytes)?;
    let mut response_bytes = [0_u8; 32];
    response_bytes.copy_from_slice(&proof[32..]);
    let response = canonical_scalar(&response_bytes)?;
    let public_bytes = public.compress().to_bytes();
    let index_bytes = index.to_le_bytes();
    let challenge = hash_to_scalar(
        challenge_domain,
        &[
            signable_hash,
            &index_bytes,
            context,
            &public_bytes,
            &nonce_bytes,
        ],
    );
    Ok((generator * response) == (nonce + (public * challenge)))
}

#[allow(dead_code)]
pub(crate) fn prove_sender(
    authority_bytes: &[u8; 32],
    o_tilde_bytes: &[u8; 32],
    authority_secret_bytes: &[u8; 32],
    rerandomized_y_bytes: &[u8; 32],
    signable_hash: &[u8; 32],
    input_index: u32,
    entropy: &[u8; 32],
) -> Result<[u8; SENDER_PROOF_BYTES], DisclosureError> {
    let authority = canonical_point(authority_bytes)?;
    let o_tilde = canonical_point(o_tilde_bytes)?;
    let authority_secret = canonical_scalar(authority_secret_bytes)?;
    let rerandomized_y = canonical_scalar(rerandomized_y_bytes)?;
    let t_component = o_tilde - authority;
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(authority_bytes);
    context.extend_from_slice(o_tilde_bytes);
    let authority_proof = schnorr_prove(
        b"Innova/IV5/Disclosure/Sender/AuthorityNonce/v1",
        b"Innova/IV5/Disclosure/Sender/AuthorityChallenge/v1",
        ED25519_BASEPOINT_POINT,
        authority,
        authority_secret,
        signable_hash,
        input_index,
        &context,
        entropy,
    )?;
    let rerandomization_proof = schnorr_prove(
        b"Innova/IV5/Disclosure/Sender/RerandomizationNonce/v1",
        b"Innova/IV5/Disclosure/Sender/RerandomizationChallenge/v1",
        monero_t(),
        t_component,
        rerandomized_y,
        signable_hash,
        input_index,
        &context,
        entropy,
    )?;
    let mut proof = [0_u8; SENDER_PROOF_BYTES];
    proof[..64].copy_from_slice(&authority_proof);
    proof[64..].copy_from_slice(&rerandomization_proof);
    Ok(proof)
}

pub(crate) fn verify_sender(
    authority_bytes: &[u8; 32],
    o_tilde_bytes: &[u8; 32],
    signable_hash: &[u8; 32],
    input_index: u32,
    proof: &[u8],
) -> Result<bool, DisclosureError> {
    if proof.len() != SENDER_PROOF_BYTES {
        return Err(DisclosureError::BadLength);
    }
    let authority = canonical_point(authority_bytes)?;
    let o_tilde = canonical_point(o_tilde_bytes)?;
    let t_component = o_tilde - authority;
    if t_component.is_identity() || !t_component.is_torsion_free() {
        return Err(DisclosureError::InvalidEncoding);
    }
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(authority_bytes);
    context.extend_from_slice(o_tilde_bytes);
    Ok(schnorr_verify(
        b"Innova/IV5/Disclosure/Sender/AuthorityChallenge/v1",
        ED25519_BASEPOINT_POINT,
        authority,
        signable_hash,
        input_index,
        &context,
        &proof[..64],
    )? && schnorr_verify(
        b"Innova/IV5/Disclosure/Sender/RerandomizationChallenge/v1",
        monero_t(),
        t_component,
        signable_hash,
        input_index,
        &context,
        &proof[64..],
    )?)
}

pub(crate) fn receiver_tweak(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    spend: &[u8; 32],
    view: &[u8; 32],
    output_index: u32,
) -> Scalar {
    hash_to_scalar(
        b"Innova/IV5/ReceiverTweak/v1",
        &[shared, ephemeral, spend, view, &output_index.to_le_bytes()],
    )
}

#[allow(dead_code, clippy::similar_names, clippy::too_many_arguments)]
pub(crate) fn prove_receiver(
    spend_bytes: &[u8; 32],
    view_bytes: &[u8; 32],
    output_o_bytes: &[u8; 32],
    ephemeral_bytes: &[u8; 32],
    ephemeral_secret_bytes: &[u8; 32],
    output_y_bytes: &[u8; 32],
    signable_hash: &[u8; 32],
    output_index: u32,
    entropy: &[u8; 32],
) -> Result<[u8; RECEIVER_PROOF_BYTES], DisclosureError> {
    let spend = canonical_point(spend_bytes)?;
    let view = canonical_point(view_bytes)?;
    let output_o = canonical_point(output_o_bytes)?;
    let ephemeral = canonical_point(ephemeral_bytes)?;
    let ephemeral_secret = canonical_scalar(ephemeral_secret_bytes)?;
    let output_y = canonical_scalar(output_y_bytes)?;
    if ephemeral != ED25519_BASEPOINT_POINT * ephemeral_secret {
        return Err(DisclosureError::InvalidProof);
    }
    let shared = view * ephemeral_secret;
    let shared_bytes = shared.compress().to_bytes();
    let tweak = receiver_tweak(
        &shared_bytes,
        ephemeral_bytes,
        spend_bytes,
        view_bytes,
        output_index,
    );
    let t_component = output_o - spend - (ED25519_BASEPOINT_POINT * tweak);
    if t_component != monero_t() * output_y {
        return Err(DisclosureError::InvalidProof);
    }

    let index_bytes = output_index.to_le_bytes();
    let mut dleq_nonce = hash_to_scalar(
        b"Innova/IV5/Disclosure/Receiver/DleqNonce/v1",
        &[
            entropy,
            ephemeral_secret_bytes,
            signable_hash,
            &index_bytes,
            spend_bytes,
            view_bytes,
            output_o_bytes,
            ephemeral_bytes,
            &shared_bytes,
        ],
    );
    if dleq_nonce == Scalar::ZERO {
        dleq_nonce = Scalar::ONE;
    }
    let a_g = ED25519_BASEPOINT_POINT * dleq_nonce;
    let a_v = view * dleq_nonce;
    let challenge = hash_to_scalar(
        b"Innova/IV5/Disclosure/Receiver/DleqChallenge/v1",
        &[
            signable_hash,
            &index_bytes,
            spend_bytes,
            view_bytes,
            output_o_bytes,
            ephemeral_bytes,
            &shared_bytes,
            &a_g.compress().to_bytes(),
            &a_v.compress().to_bytes(),
        ],
    );
    let response = dleq_nonce + (challenge * ephemeral_secret);
    let mut context = Vec::with_capacity(160);
    context.extend_from_slice(spend_bytes);
    context.extend_from_slice(view_bytes);
    context.extend_from_slice(output_o_bytes);
    context.extend_from_slice(ephemeral_bytes);
    context.extend_from_slice(&shared_bytes);
    let output_proof = schnorr_prove(
        b"Innova/IV5/Disclosure/Receiver/OutputNonce/v1",
        b"Innova/IV5/Disclosure/Receiver/OutputChallenge/v1",
        monero_t(),
        t_component,
        output_y,
        signable_hash,
        output_index,
        &context,
        entropy,
    )?;

    let mut proof = [0_u8; RECEIVER_PROOF_BYTES];
    proof[..32].copy_from_slice(&shared_bytes);
    proof[32..64].copy_from_slice(&challenge.to_bytes());
    proof[64..96].copy_from_slice(&response.to_bytes());
    proof[96..].copy_from_slice(&output_proof);
    Ok(proof)
}

pub(crate) fn verify_receiver(
    spend_bytes: &[u8; 32],
    view_bytes: &[u8; 32],
    output_o_bytes: &[u8; 32],
    ephemeral_bytes: &[u8; 32],
    signable_hash: &[u8; 32],
    output_index: u32,
    proof: &[u8],
) -> Result<bool, DisclosureError> {
    if proof.len() != RECEIVER_PROOF_BYTES {
        return Err(DisclosureError::BadLength);
    }
    let spend = canonical_point(spend_bytes)?;
    let view = canonical_point(view_bytes)?;
    let output_o = canonical_point(output_o_bytes)?;
    let ephemeral = canonical_point(ephemeral_bytes)?;
    let mut shared_bytes = [0_u8; 32];
    shared_bytes.copy_from_slice(&proof[..32]);
    let shared = canonical_point(&shared_bytes)?;
    let mut challenge_bytes = [0_u8; 32];
    challenge_bytes.copy_from_slice(&proof[32..64]);
    let challenge = canonical_scalar(&challenge_bytes)?;
    let mut response_bytes = [0_u8; 32];
    response_bytes.copy_from_slice(&proof[64..96]);
    let response = canonical_scalar(&response_bytes)?;

    let a_g = (ED25519_BASEPOINT_POINT * response) - (ephemeral * challenge);
    let a_v = (view * response) - (shared * challenge);
    let index_bytes = output_index.to_le_bytes();
    let expected_challenge = hash_to_scalar(
        b"Innova/IV5/Disclosure/Receiver/DleqChallenge/v1",
        &[
            signable_hash,
            &index_bytes,
            spend_bytes,
            view_bytes,
            output_o_bytes,
            ephemeral_bytes,
            &shared_bytes,
            &a_g.compress().to_bytes(),
            &a_v.compress().to_bytes(),
        ],
    );
    if expected_challenge != challenge {
        return Ok(false);
    }

    let tweak = receiver_tweak(
        &shared_bytes,
        ephemeral_bytes,
        spend_bytes,
        view_bytes,
        output_index,
    );
    let t_component = output_o - spend - (ED25519_BASEPOINT_POINT * tweak);
    if t_component.is_identity() || !t_component.is_torsion_free() {
        return Err(DisclosureError::InvalidEncoding);
    }
    let mut context = Vec::with_capacity(160);
    context.extend_from_slice(spend_bytes);
    context.extend_from_slice(view_bytes);
    context.extend_from_slice(output_o_bytes);
    context.extend_from_slice(ephemeral_bytes);
    context.extend_from_slice(&shared_bytes);
    schnorr_verify(
        b"Innova/IV5/Disclosure/Receiver/OutputChallenge/v1",
        monero_t(),
        t_component,
        signable_hash,
        output_index,
        &context,
        &proof[96..],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_disclosure_is_bound_to_fcmp_input() {
        let x = Scalar::from(3_u64);
        let q = Scalar::from(5_u64);
        let authority = (ED25519_BASEPOINT_POINT * x).compress().to_bytes();
        let o_tilde = ((ED25519_BASEPOINT_POINT * x) + (monero_t() * q))
            .compress()
            .to_bytes();
        let hash = [0x51_u8; 32];
        let proof = prove_sender(
            &authority,
            &o_tilde,
            &x.to_bytes(),
            &q.to_bytes(),
            &hash,
            2,
            &[0x52; 32],
        )
        .unwrap();
        assert!(verify_sender(&authority, &o_tilde, &hash, 2, &proof).unwrap());
        assert!(!verify_sender(&authority, &o_tilde, &hash, 3, &proof).unwrap());
    }

    #[test]
    fn receiver_disclosure_proves_address_and_ephemeral_link() {
        let spend_secret = Scalar::from(7_u64);
        let view_secret = Scalar::from(11_u64);
        let ephemeral_secret = Scalar::from(13_u64);
        let output_y = Scalar::from(17_u64);
        let spend = (ED25519_BASEPOINT_POINT * spend_secret)
            .compress()
            .to_bytes();
        let view = (ED25519_BASEPOINT_POINT * view_secret)
            .compress()
            .to_bytes();
        let ephemeral = (ED25519_BASEPOINT_POINT * ephemeral_secret)
            .compress()
            .to_bytes();
        let shared = (ED25519_BASEPOINT_POINT * (view_secret * ephemeral_secret))
            .compress()
            .to_bytes();
        let tweak = receiver_tweak(&shared, &ephemeral, &spend, &view, 1);
        let output_o = ((ED25519_BASEPOINT_POINT * (spend_secret + tweak))
            + (monero_t() * output_y))
            .compress()
            .to_bytes();
        let hash = [0x61_u8; 32];
        let proof = prove_receiver(
            &spend,
            &view,
            &output_o,
            &ephemeral,
            &ephemeral_secret.to_bytes(),
            &output_y.to_bytes(),
            &hash,
            1,
            &[0x62; 32],
        )
        .unwrap();
        assert!(verify_receiver(&spend, &view, &output_o, &ephemeral, &hash, 1, &proof,).unwrap());
        assert!(!verify_receiver(&spend, &view, &output_o, &ephemeral, &hash, 0, &proof,).unwrap());
    }
}
