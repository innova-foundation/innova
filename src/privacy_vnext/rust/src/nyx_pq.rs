//! Nyx messenger primitives: ML-KEM-768, ML-DSA-65, X25519, ChaCha20-Poly1305, HKDF-SHA256.
//! Every function returns 0 on success and a nonzero code otherwise. Not a consensus input.

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    slice,
};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit as AeadKeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::Hkdf;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65,
    Signature, VerifyingKey, B32,
};
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey, EncapsulationKey, ExpandedDecapsulationKey,
    KeyExport, MlKem768,
};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

pub const NYX_MLKEM768_SEED: usize = 64;
pub const NYX_MLKEM768_EK: usize = 1184;
pub const NYX_MLKEM768_DK: usize = 2400;
pub const NYX_MLKEM768_CT: usize = 1088;
pub const NYX_MLKEM768_SS: usize = 32;
pub const NYX_MLDSA65_SEED: usize = 32;
pub const NYX_MLDSA65_PK: usize = 1952;
pub const NYX_MLDSA65_SK: usize = 4032;
pub const NYX_MLDSA65_SIG: usize = 3309;
pub const NYX_X25519: usize = 32;
pub const NYX_AEAD_KEY: usize = 32;
pub const NYX_AEAD_NONCE: usize = 12;
pub const NYX_AEAD_TAG: usize = 16;
pub const NYX_HKDF_MAX: usize = 255 * 32;

const _: () = assert!(size_of::<EncodedVerifyingKey<MlDsa65>>() == NYX_MLDSA65_PK);
const _: () = assert!(size_of::<EncodedSignature<MlDsa65>>() == NYX_MLDSA65_SIG);
const _: () = assert!(size_of::<ExpandedSigningKeyBytes<MlDsa65>>() == NYX_MLDSA65_SK);
const _: () = assert!(size_of::<ml_kem::Key<EncapsulationKey<MlKem768>>>() == NYX_MLKEM768_EK);
const _: () = assert!(size_of::<ExpandedDecapsulationKey<MlKem768>>() == NYX_MLKEM768_DK);
const _: () = assert!(size_of::<Ciphertext<MlKem768>>() == NYX_MLKEM768_CT);
const _: () = assert!(size_of::<ml_kem::Seed>() == NYX_MLKEM768_SEED);
const _: () = assert!(size_of::<B32>() == NYX_MLDSA65_SEED);

const ERR_ARG: i32 = 1;
const ERR_CRYPTO: i32 = 2;
const ERR_PANIC: i32 = 3;

type Res = Result<(), i32>;

fn boundary(f: impl FnOnce() -> Res) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(code)) => code,
        Err(_) => ERR_PANIC,
    }
}

/// # Safety
/// `p` is null only when `n` is 0; otherwise it points to `n` readable bytes.
unsafe fn input<'a>(p: *const u8, n: usize) -> Result<&'a [u8], i32> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(ERR_ARG);
    }
    // SAFETY: non-null and the caller guarantees `n` readable bytes.
    Ok(unsafe { slice::from_raw_parts(p, n) })
}

/// # Safety
/// `p` points to `n` writable bytes when non-null.
unsafe fn output<'a>(p: *mut u8, n: usize) -> Result<&'a mut [u8], i32> {
    if p.is_null() {
        return Err(ERR_ARG);
    }
    // SAFETY: non-null and the caller guarantees `n` writable bytes.
    Ok(unsafe { slice::from_raw_parts_mut(p, n) })
}

fn os_random(out: &mut [u8]) -> Res {
    OsRng.try_fill_bytes(out).map_err(|_| ERR_CRYPTO)
}

fn b32(p: &[u8]) -> Result<B32, i32> {
    B32::try_from(p).map_err(|_| ERR_ARG)
}

// FIPS 204 pure-mode prefix for an empty context: domain 0, context length 0.
const PURE_EMPTY_CTX: [u8; 2] = [0, 0];

fn dsa_sign(sk: &ExpandedSigningKey<MlDsa65>, mp: &[&[u8]], rnd: &B32, out: &mut [u8]) {
    let sig = sk.sign_internal(mp, rnd);
    out.copy_from_slice(&sig.encode());
}

fn dsa_verify_internal(pk: &[u8], mp: &[&[u8]], sig: &[u8]) -> Res {
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk).map_err(|_| ERR_ARG)?;
    let vk = VerifyingKey::<MlDsa65>::decode(&enc);
    let enc_sig = EncodedSignature::<MlDsa65>::try_from(sig).map_err(|_| ERR_ARG)?;
    let sig = Signature::<MlDsa65>::decode(&enc_sig).ok_or(ERR_CRYPTO)?;
    let joined: Vec<u8> = mp.concat();
    if vk.verify_internal(&joined, &sig) {
        Ok(())
    } else {
        Err(ERR_CRYPTO)
    }
}

/// Fill `out` from the OS random source.
/// # Safety
/// `out` must point to `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nyx_random(out: *mut u8, len: usize) -> i32 {
    boundary(|| os_random(unsafe { output(out, len) }?))
}

/// Report the compiled sizes, in the order of `nyx_pq.h`, for a runtime cross-check.
/// # Safety
/// `out` must point to `n` writable `u32`s.
#[no_mangle]
pub unsafe extern "C" fn nyx_pq_sizes(out: *mut u32, n: usize) -> i32 {
    boundary(|| {
        let sizes = [
            NYX_MLKEM768_SEED,
            NYX_MLKEM768_EK,
            NYX_MLKEM768_DK,
            NYX_MLKEM768_CT,
            NYX_MLKEM768_SS,
            NYX_MLDSA65_SEED,
            NYX_MLDSA65_PK,
            NYX_MLDSA65_SK,
            NYX_MLDSA65_SIG,
            NYX_X25519,
            NYX_AEAD_KEY,
            NYX_AEAD_NONCE,
            NYX_AEAD_TAG,
        ];
        if out.is_null() || n != sizes.len() {
            return Err(ERR_ARG);
        }
        // SAFETY: non-null and the caller guarantees `n` writable u32s.
        let dst = unsafe { slice::from_raw_parts_mut(out, n) };
        for (d, s) in dst.iter_mut().zip(sizes) {
            *d = u32::try_from(s).map_err(|_| ERR_ARG)?;
        }
        Ok(())
    })
}

/// Random ML-KEM-768 key: `seed64 = d || z` and the encapsulation key.
/// # Safety
/// Outputs must point to 64 and 1184 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nyx_mlkem768_keygen(out_seed: *mut u8, out_ek: *mut u8) -> i32 {
    boundary(|| {
        {
            let seed = unsafe { output(out_seed, NYX_MLKEM768_SEED) }?;
            os_random(seed)?;
        }
        // SAFETY: forwarded caller contract; no Rust reference to the seed is live.
        let rc = unsafe { nyx_mlkem768_ek_from_seed(out_seed, out_ek) };
        if rc == 0 {
            Ok(())
        } else {
            unsafe { output(out_seed, NYX_MLKEM768_SEED) }?.zeroize();
            Err(rc)
        }
    })
}

/// FIPS 203 `KeyGen_internal(d, z)` encapsulation key from `seed64 = d || z`.
/// # Safety
/// `seed` must point to 64 readable bytes and `out_ek` to 1184 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nyx_mlkem768_ek_from_seed(seed: *const u8, out_ek: *mut u8) -> i32 {
    boundary(|| {
        let s = unsafe { input(seed, NYX_MLKEM768_SEED) }?;
        let out = unsafe { output(out_ek, NYX_MLKEM768_EK) }?;
        let mut sd = ml_kem::Seed::try_from(s).map_err(|_| ERR_ARG)?;
        let dk = DecapsulationKey::<MlKem768>::from_seed(sd);
        sd.zeroize();
        out.copy_from_slice(&dk.encapsulation_key().to_bytes());
        Ok(())
    })
}

fn kem_encaps(ek: &[u8], m: &B32, ct: &mut [u8], ss: &mut [u8]) -> Res {
    let key = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(ek).map_err(|_| ERR_ARG)?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| ERR_CRYPTO)?;
    let (c, mut k) = ek.encapsulate_deterministic(m);
    ct.copy_from_slice(&c);
    ss.copy_from_slice(&k);
    k.as_mut_slice().zeroize();
    Ok(())
}

/// Encapsulate to `ek` with fresh randomness.
/// # Safety
/// `ek` 1184 readable; `out_ct` 1088 and `out_ss` 32 writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_mlkem768_encaps(
    ek: *const u8,
    out_ct: *mut u8,
    out_ss: *mut u8,
) -> i32 {
    boundary(|| {
        let ek = unsafe { input(ek, NYX_MLKEM768_EK) }?;
        let ct = unsafe { output(out_ct, NYX_MLKEM768_CT) }?;
        let ss = unsafe { output(out_ss, NYX_MLKEM768_SS) }?;
        let mut m = B32::default();
        os_random(&mut m)?;
        let r = kem_encaps(ek, &m, ct, ss);
        m.zeroize();
        r
    })
}

/// Deterministic encapsulation with message `m`; for known-answer tests only.
/// # Safety
/// `ek` 1184 and `m` 32 readable; `out_ct` 1088 and `out_ss` 32 writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_kat_mlkem768_encaps(
    ek: *const u8,
    m: *const u8,
    out_ct: *mut u8,
    out_ss: *mut u8,
) -> i32 {
    boundary(|| {
        let ek = unsafe { input(ek, NYX_MLKEM768_EK) }?;
        let m = b32(unsafe { input(m, 32) }?)?;
        let ct = unsafe { output(out_ct, NYX_MLKEM768_CT) }?;
        let ss = unsafe { output(out_ss, NYX_MLKEM768_SS) }?;
        kem_encaps(ek, &m, ct, ss)
    })
}

/// Decapsulate with the key regenerated from `seed64` (implicit rejection on a bad ciphertext).
/// # Safety
/// `seed` 64 and `ct` 1088 readable; `out_ss` 32 writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_mlkem768_decaps(
    seed: *const u8,
    ct: *const u8,
    out_ss: *mut u8,
) -> i32 {
    boundary(|| {
        let s = unsafe { input(seed, NYX_MLKEM768_SEED) }?;
        let c = unsafe { input(ct, NYX_MLKEM768_CT) }?;
        let ss = unsafe { output(out_ss, NYX_MLKEM768_SS) }?;
        let mut sd = ml_kem::Seed::try_from(s).map_err(|_| ERR_ARG)?;
        let dk = DecapsulationKey::<MlKem768>::from_seed(sd);
        sd.zeroize();
        let c = Ciphertext::<MlKem768>::try_from(c).map_err(|_| ERR_ARG)?;
        ss.copy_from_slice(&dk.decapsulate(&c));
        Ok(())
    })
}

/// Decapsulate with an expanded 2400-byte key; for known-answer tests only.
/// # Safety
/// `dk` 2400 and `ct` 1088 readable; `out_ss` 32 writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_kat_mlkem768_decaps(
    dk: *const u8,
    ct: *const u8,
    out_ss: *mut u8,
) -> i32 {
    boundary(|| {
        let d = unsafe { input(dk, NYX_MLKEM768_DK) }?;
        let c = unsafe { input(ct, NYX_MLKEM768_CT) }?;
        let ss = unsafe { output(out_ss, NYX_MLKEM768_SS) }?;
        let mut enc = ExpandedDecapsulationKey::<MlKem768>::try_from(d).map_err(|_| ERR_ARG)?;
        #[allow(deprecated)]
        let dk =
            <DecapsulationKey<MlKem768> as ml_kem::ExpandedKeyEncoding>::from_expanded_bytes(&enc);
        enc.as_mut_slice().zeroize();
        let dk = dk.map_err(|_| ERR_CRYPTO)?;
        let c = Ciphertext::<MlKem768>::try_from(c).map_err(|_| ERR_ARG)?;
        ss.copy_from_slice(&dk.decapsulate(&c));
        Ok(())
    })
}

/// Random ML-DSA-65 key: the 32-byte seed and the public key.
/// # Safety
/// Outputs must point to 32 and 1952 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nyx_mldsa65_keygen(out_seed: *mut u8, out_pk: *mut u8) -> i32 {
    boundary(|| {
        let seed = unsafe { output(out_seed, NYX_MLDSA65_SEED) }?;
        os_random(seed)?;
        // SAFETY: forwarded caller contract.
        let rc = unsafe { nyx_mldsa65_pk_from_seed(seed.as_ptr(), out_pk) };
        if rc == 0 {
            Ok(())
        } else {
            seed.zeroize();
            Err(rc)
        }
    })
}

/// FIPS 204 `KeyGen_internal(xi)` public key.
/// # Safety
/// `seed` 32 readable; `out_pk` 1952 writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_mldsa65_pk_from_seed(seed: *const u8, out_pk: *mut u8) -> i32 {
    boundary(|| {
        let mut xi = b32(unsafe { input(seed, NYX_MLDSA65_SEED) }?)?;
        let out = unsafe { output(out_pk, NYX_MLDSA65_PK) }?;
        let sk = ExpandedSigningKey::<MlDsa65>::from_seed(&xi);
        xi.zeroize();
        out.copy_from_slice(&sk.verifying_key().encode());
        Ok(())
    })
}

/// Hedged ML-DSA-65 signature (pure, empty context).
/// # Safety
/// `seed` 32 and `msg` `len` readable; `out_sig` 3309 writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_mldsa65_sign(
    seed: *const u8,
    msg: *const u8,
    len: usize,
    out_sig: *mut u8,
) -> i32 {
    boundary(|| {
        let mut xi = b32(unsafe { input(seed, NYX_MLDSA65_SEED) }?)?;
        let m = unsafe { input(msg, len) }?;
        let out = unsafe { output(out_sig, NYX_MLDSA65_SIG) }?;
        let sk = ExpandedSigningKey::<MlDsa65>::from_seed(&xi);
        xi.zeroize();
        let mut rnd = B32::default();
        os_random(&mut rnd)?;
        dsa_sign(&sk, &[&PURE_EMPTY_CTX, m], &rnd, out);
        rnd.zeroize();
        Ok(())
    })
}

/// Verify a pure, empty-context ML-DSA-65 signature; 0 only when valid.
/// # Safety
/// `pk` 1952, `msg` `len` and `sig` 3309 readable.
#[no_mangle]
pub unsafe extern "C" fn nyx_mldsa65_verify(
    pk: *const u8,
    msg: *const u8,
    len: usize,
    sig: *const u8,
) -> i32 {
    boundary(|| {
        let pk = unsafe { input(pk, NYX_MLDSA65_PK) }?;
        let m = unsafe { input(msg, len) }?;
        let s = unsafe { input(sig, NYX_MLDSA65_SIG) }?;
        dsa_verify_internal(pk, &[&PURE_EMPTY_CTX, m], s)
    })
}

/// `Sign_internal(sk, M', rnd)` with an expanded 4032-byte key; for known-answer tests only.
/// # Safety
/// `sk` 4032, `mp` `len` and `rnd` 32 readable; `out_sig` 3309 writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_kat_mldsa65_sign_internal(
    sk: *const u8,
    mp: *const u8,
    len: usize,
    rnd: *const u8,
    out_sig: *mut u8,
) -> i32 {
    boundary(|| {
        let skb = unsafe { input(sk, NYX_MLDSA65_SK) }?;
        let m = unsafe { input(mp, len) }?;
        let rnd = b32(unsafe { input(rnd, 32) }?)?;
        let out = unsafe { output(out_sig, NYX_MLDSA65_SIG) }?;
        let enc = ExpandedSigningKeyBytes::<MlDsa65>::try_from(skb).map_err(|_| ERR_ARG)?;
        #[allow(deprecated)]
        let key = ExpandedSigningKey::<MlDsa65>::from_expanded(&enc);
        dsa_sign(&key, &[m], &rnd, out);
        Ok(())
    })
}

/// `Verify_internal(pk, M', sig)`; for known-answer tests only.
/// # Safety
/// `pk` 1952, `mp` `len` and `sig` 3309 readable.
#[no_mangle]
pub unsafe extern "C" fn nyx_kat_mldsa65_verify_internal(
    pk: *const u8,
    mp: *const u8,
    len: usize,
    sig: *const u8,
) -> i32 {
    boundary(|| {
        let pk = unsafe { input(pk, NYX_MLDSA65_PK) }?;
        let m = unsafe { input(mp, len) }?;
        let s = unsafe { input(sig, NYX_MLDSA65_SIG) }?;
        dsa_verify_internal(pk, &[m], s)
    })
}

/// Random X25519 secret and its public key.
/// # Safety
/// Outputs must point to 32 writable bytes each.
#[no_mangle]
pub unsafe extern "C" fn nyx_x25519_keygen(out_secret: *mut u8, out_public: *mut u8) -> i32 {
    boundary(|| {
        let sk = unsafe { output(out_secret, NYX_X25519) }?;
        let pk = unsafe { output(out_public, NYX_X25519) }?;
        os_random(sk)?;
        let mut s = [0_u8; 32];
        s.copy_from_slice(sk);
        pk.copy_from_slice(&x25519_dalek::x25519(
            s,
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ));
        s.zeroize();
        Ok(())
    })
}

/// X25519(sk, pk); fails on an all-zero shared secret.
/// # Safety
/// `sk` and `pk` 32 readable; `out` 32 writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_x25519(sk: *const u8, pk: *const u8, out: *mut u8) -> i32 {
    boundary(|| {
        let skb = unsafe { input(sk, NYX_X25519) }?;
        let pkb = unsafe { input(pk, NYX_X25519) }?;
        let o = unsafe { output(out, NYX_X25519) }?;
        let mut s = [0_u8; 32];
        s.copy_from_slice(skb);
        let mut u = [0_u8; 32];
        u.copy_from_slice(pkb);
        let mut r = x25519_dalek::x25519(s, u);
        s.zeroize();
        if r.iter().fold(0_u8, |a, b| a | b) == 0 {
            return Err(ERR_CRYPTO);
        }
        o.copy_from_slice(&r);
        r.zeroize();
        Ok(())
    })
}

/// ChaCha20-Poly1305 seal: `out` receives `pt_len + 16` bytes (ciphertext then tag).
/// # Safety
/// Inputs readable at their lengths; `out` `pt_len + 16` writable; `out` may equal `pt`, no other overlap.
#[no_mangle]
pub unsafe extern "C" fn nyx_aead_seal(
    key: *const u8,
    nonce: *const u8,
    ad: *const u8,
    ad_len: usize,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
) -> i32 {
    boundary(|| {
        let key_bytes = unsafe { input(key, NYX_AEAD_KEY) }?;
        let nonce_bytes = unsafe { input(nonce, NYX_AEAD_NONCE) }?;
        let aad = unsafe { input(ad, ad_len) }?;
        let total = pt_len.checked_add(NYX_AEAD_TAG).ok_or(ERR_ARG)?;
        if out.is_null() || (pt_len > 0 && pt.is_null()) {
            return Err(ERR_ARG);
        }
        // Raw memmove before any slice exists: `out == pt` (in place) is allowed.
        // SAFETY: both non-null and the caller guarantees `pt_len` bytes at each.
        if pt_len > 0 {
            unsafe { std::ptr::copy(pt, out, pt_len) };
        }
        let sealed = unsafe { output(out, total) }?;
        let cipher = ChaCha20Poly1305::new_from_slice(key_bytes).map_err(|_| ERR_ARG)?;
        let (body, tag_out) = sealed.split_at_mut(pt_len);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce_bytes), aad, body)
            .map_err(|_| ERR_CRYPTO)?;
        tag_out.copy_from_slice(&tag);
        Ok(())
    })
}

/// ChaCha20-Poly1305 open of `ct_len` bytes (ciphertext then tag) into `ct_len - 16` bytes.
/// # Safety
/// Inputs readable at their lengths; `out` `ct_len - 16` writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_aead_open(
    key: *const u8,
    nonce: *const u8,
    ad: *const u8,
    ad_len: usize,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
) -> i32 {
    boundary(|| {
        let key_bytes = unsafe { input(key, NYX_AEAD_KEY) }?;
        let nonce_bytes = unsafe { input(nonce, NYX_AEAD_NONCE) }?;
        let aad = unsafe { input(ad, ad_len) }?;
        let sealed = unsafe { input(ct, ct_len) }?;
        let pt_len = ct_len.checked_sub(NYX_AEAD_TAG).ok_or(ERR_ARG)?;
        let cipher = ChaCha20Poly1305::new_from_slice(key_bytes).map_err(|_| ERR_ARG)?;
        let mut buf = sealed[..pt_len].to_vec();
        let tag = Tag::from_slice(&sealed[pt_len..]);
        if cipher
            .decrypt_in_place_detached(Nonce::from_slice(nonce_bytes), aad, &mut buf, tag)
            .is_err()
        {
            buf.zeroize();
            return Err(ERR_CRYPTO);
        }
        if pt_len > 0 {
            let o = unsafe { output(out, pt_len) }?;
            o.copy_from_slice(&buf);
        }
        buf.zeroize();
        Ok(())
    })
}

/// HKDF-SHA256 (RFC 5869) extract-and-expand into `out_len` bytes (at most 8160).
/// # Safety
/// Inputs readable at their lengths; `out` `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn nyx_hkdf_sha256(
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    boundary(|| {
        let s = unsafe { input(salt, salt_len) }?;
        let i = unsafe { input(ikm, ikm_len) }?;
        let f = unsafe { input(info, info_len) }?;
        if out_len == 0 || out_len > NYX_HKDF_MAX {
            return Err(ERR_ARG);
        }
        let o = unsafe { output(out, out_len) }?;
        let hk = Hkdf::<Sha256>::new(if salt_len == 0 { None } else { Some(s) }, i);
        hk.expand(f, o).map_err(|_| ERR_CRYPTO)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_seal_in_place_matches_separate() {
        let key = [3_u8; 32];
        let nonce = [5_u8; 12];
        let msg = b"in place seal".to_vec();
        let mut sep = vec![0_u8; msg.len() + 16];
        let mut inplace = msg.clone();
        inplace.resize(msg.len() + 16, 0);
        unsafe {
            assert_eq!(
                nyx_aead_seal(
                    key.as_ptr(),
                    nonce.as_ptr(),
                    b"ad".as_ptr(),
                    2,
                    msg.as_ptr(),
                    msg.len(),
                    sep.as_mut_ptr()
                ),
                0
            );
            let p = inplace.as_mut_ptr();
            assert_eq!(
                nyx_aead_seal(
                    key.as_ptr(),
                    nonce.as_ptr(),
                    b"ad".as_ptr(),
                    2,
                    p,
                    msg.len(),
                    p
                ),
                0
            );
        }
        assert_eq!(sep, inplace);
    }

    #[test]
    fn dsa_round_trip_and_tamper() {
        let mut seed = [0_u8; 32];
        let mut pk = vec![0_u8; NYX_MLDSA65_PK];
        let mut sig = vec![0_u8; NYX_MLDSA65_SIG];
        let msg = b"nyx";
        unsafe {
            assert_eq!(nyx_mldsa65_keygen(seed.as_mut_ptr(), pk.as_mut_ptr()), 0);
            assert_eq!(
                nyx_mldsa65_sign(seed.as_ptr(), msg.as_ptr(), 3, sig.as_mut_ptr()),
                0
            );
            assert_eq!(
                nyx_mldsa65_verify(pk.as_ptr(), msg.as_ptr(), 3, sig.as_ptr()),
                0
            );
            sig[10] ^= 1;
            assert_ne!(
                nyx_mldsa65_verify(pk.as_ptr(), msg.as_ptr(), 3, sig.as_ptr()),
                0
            );
        }
    }

    #[test]
    fn kem_round_trip() {
        let mut seed = [0_u8; 64];
        let mut ek = vec![0_u8; NYX_MLKEM768_EK];
        let mut ct = vec![0_u8; NYX_MLKEM768_CT];
        let (mut a, mut b) = ([0_u8; 32], [0_u8; 32]);
        unsafe {
            assert_eq!(nyx_mlkem768_keygen(seed.as_mut_ptr(), ek.as_mut_ptr()), 0);
            assert_eq!(
                nyx_mlkem768_encaps(ek.as_ptr(), ct.as_mut_ptr(), a.as_mut_ptr()),
                0
            );
            assert_eq!(
                nyx_mlkem768_decaps(seed.as_ptr(), ct.as_ptr(), b.as_mut_ptr()),
                0
            );
        }
        assert_eq!(a, b);
    }

    #[test]
    fn x25519_rejects_zero_point() {
        let sk = [7_u8; 32];
        let zero = [0_u8; 32];
        let mut out = [0_u8; 32];
        unsafe {
            assert_ne!(nyx_x25519(sk.as_ptr(), zero.as_ptr(), out.as_mut_ptr()), 0);
        }
    }
}
