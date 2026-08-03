//! The code formally verified by Veridise
//! (https://github.com/VeridiseAuditing/helioselene-dafny-proofs).
//!
//! All of these functions are marked `inline(always)` as they're generally wrapped into the public
//! API, not directly published, and once inlined into the wrappers, it's up to them to decide the
//! inlining policy.

use super::*;

// These modules correspond to the explicit "Verification targets"

mod red;
#[allow(unused)]
pub(super) use red::{red256, red512};

mod pow;
pub(super) use pow::pow;

mod sqrt;
pub(super) use sqrt::sqrt;

mod invert;
pub(super) use invert::invert;

/// The distance between the modulus and 2**255.
const MODULUS_255_DISTANCE: U128 = U128::from_be_hex("08cab7e2e6960ce8067af49720ee20ad");

/// Perform an add with carry, bounding the overflow to be zero or one.
///
/// This function was not marked as formally verified but it's solely used as a helper function for
/// these functions which were formally verified. It also was formally verified:
/// https://github.com/VeridiseAuditing/helioselene-dafny-proof
///   /blob/9da40f40d62776d380f4423124ae7ca6b956f12b/src/helioselene/field/Base.dfy#L266-L280
#[inline(always)]
fn add_with_bounded_overflow(a: Limb, b: Limb, c: Limb) -> (Limb, Limb) {
  let (limb, carry1) = a.0.overflowing_add(b.0);
  let (limb, carry2) = limb.overflowing_add(c.0);
  (Limb(limb), Limb(Word::from(carry1 | carry2)))
}

// The following methods correspond to the explicit "Additional verified methods"

/// This selection formula is inherited from `subtle`.
#[inline(always)]
fn select_word(a: Limb, b: Limb, choice: Limb) -> Limb {
  a ^ ((a ^ b) & choice)
}

/// Subtract a value (`b`) from another value (`a`).
///
/// Returns `(result, 0)` if successful, or `(wrapped value, Limb::MAX)` otherwise.
#[inline(always)]
fn sub_value(a: U256, b: U256) -> (U256, Limb) {
  a.sbb(&b, Limb::ZERO)
}

/// Reduce once if appropriate.
#[inline(always)]
fn red1(a: U256) -> U256 {
  let (reduced, borrow) = sub_value(a, MODULUS);
  let mut out = U256::ZERO;
  for j in 0 .. U256::LIMBS {
    out.as_limbs_mut()[j] = select_word(reduced.as_limbs()[j], a.as_limbs()[j], borrow);
  }
  out
}

impl Add for HelioseleneField {
  type Output = Self;
  #[inline(always)]
  fn add(self, b: Self) -> Self::Output {
    HelioseleneField(red1(self.0.wrapping_add(&b.0)))
  }
}

impl Sub for HelioseleneField {
  type Output = Self;
  #[inline(always)]
  fn sub(self, b: Self) -> Self::Output {
    let (candidate, underflowed) = sub_value(self.0, b.0);
    let plus_modulus = candidate.wrapping_add(&MODULUS);
    let mut out = U256::ZERO;
    for j in 0 .. U256::LIMBS {
      out.as_limbs_mut()[j] =
        select_word(candidate.as_limbs()[j], plus_modulus.as_limbs()[j], underflowed);
    }
    Self(out)
  }
}

impl Neg for HelioseleneField {
  type Output = Self;
  #[inline(always)]
  fn neg(self) -> Self::Output {
    <_>::conditional_select(
      &HelioseleneField(MODULUS.wrapping_sub(&self.0)),
      &Self::ZERO,
      self.is_zero(),
    )
  }
}

#[inline(always)]
pub(super) fn double(value: &HelioseleneField) -> HelioseleneField {
  // This is variable-time to the shift, which is constant, not to the value shifted
  HelioseleneField(red1(value.0.shl_vartime(1)))
}

impl Mul for HelioseleneField {
  type Output = Self;
  #[inline(always)]
  fn mul(self, b: Self) -> Self::Output {
    red512(self.0.mul_wide(&b.0))
  }
}

#[inline(always)]
pub(super) fn square(value: &HelioseleneField) -> HelioseleneField {
  red512(value.0.square_wide())
}

#[inline(always)]
pub(super) fn is_zero(value: &HelioseleneField) -> Choice {
  let mut all = Limb::ZERO;
  for l in 0 .. U256::LIMBS {
    all = all | value.0.as_limbs()[l];
  }
  all.ct_eq(&Limb::ZERO)
}

#[inline(always)]
pub(super) fn is_odd(value: &HelioseleneField) -> Choice {
  #[allow(clippy::as_conversions)]
  Choice::from((value.0.as_limbs()[0].0 & 1) as u8)
}

#[inline(always)]
pub(super) fn from_repr(bytes: [u8; 32]) -> CtOption<HelioseleneField> {
  let res = U256::from_le_slice(&bytes);

  // Check if a U256 contains a value less than the modulus.
  #[inline(always)]
  fn reduced(a: U256) -> Choice {
    let mut b_limbs = MODULUS_255_DISTANCE.as_limbs().iter();
    let mut last = Limb::ZERO;
    let mut carry = Limb::ZERO;
    for a in a.as_limbs() {
      let b = b_limbs.next().unwrap_or(&Limb::ZERO);
      (last, carry) = add_with_bounded_overflow(*a, *b, carry);
    }
    ((last & (Limb::ONE << (Limb::BITS - 1))) | carry).ct_eq(&Limb::ZERO)
  }

  let reduced = reduced(res);
  CtOption::new(HelioseleneField(res), reduced)
}

#[inline(always)]
pub(super) fn to_repr(value: &HelioseleneField) -> [u8; 32] {
  value.0.to_le_bytes()
}
