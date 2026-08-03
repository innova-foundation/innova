use super::*;

/// Twice the distance from the modulus to 2**255.
const TWO_MODULUS_255_DISTANCE: U128 = U128::from_be_hex("11956fc5cd2c19d00cf5e92e41dc415a");

/// Reduce any 256-bit value
#[inline(always)]
pub(crate) fn red256(mut a: U256) -> HelioseleneField {
  // If the highest bit is set, we clear it and add the distance to the modulus
  let high_bit = (a.as_limbs()[U256::LIMBS - 1] >> (Limb::BITS - 1)).wrapping_neg();
  a.as_limbs_mut()[U256::LIMBS - 1] = a.as_limbs()[U256::LIMBS - 1] & (Limb::MAX >> 1);
  let mut carry = Limb::ZERO;
  for j in 0 .. U128::LIMBS {
    (a.as_limbs_mut()[j], carry) = add_with_bounded_overflow(
      a.as_limbs()[j],
      high_bit & MODULUS_255_DISTANCE.as_limbs()[j],
      carry,
    );
  }
  for j in U128::LIMBS .. U256::LIMBS {
    let (limb, carry_bool) = a.as_limbs()[j].0.overflowing_add(carry.0);
    (a.as_limbs_mut()[j], carry) = (Limb(limb), Limb(Word::from(carry_bool)));
  }

  // The resulting value is either reduced or within one reduction step as `3 * MODULUS > 2**256`
  HelioseleneField(red1(a))
}

#[inline(always)]
pub(crate) fn red512(wide: (U256, U256)) -> HelioseleneField {
  /*
    The premise of the Crandall reduction is how the modulus is equivalent to
    2**255 - MODULUS_255_DISTANCE, where MODULUS_255_DISTANCE is short (only two words). This means
    2**255 is congruent to MODULUS_255_DISTANCE modulo the modulus, and subtraction of 2**255 is
    congruent to subtracting MODULUS_255_DISTANCE.
  */

  let mut limbs = [Limb::ZERO; 2 * U256::LIMBS];
  limbs[.. U256::LIMBS].copy_from_slice(wide.0.as_limbs());
  limbs[U256::LIMBS ..].copy_from_slice(wide.1.as_limbs());

  /*
    Perform a 128-bit multiplication with the highest bits, producing a 256-bit value which must
    be further shifted by 128 bits.
  */
  let mut carries = [Limb::ZERO; U256::LIMBS + U128::LIMBS];
  let mut carry;
  for i in U128::LIMBS .. U256::LIMBS {
    (limbs[i], carry) =
      limbs[i].mac(limbs[U256::LIMBS + i], TWO_MODULUS_255_DISTANCE.as_limbs()[0], Limb::ZERO);
    for j in 1 .. U128::LIMBS {
      (limbs[i + j], carry) =
        limbs[i + j].mac(limbs[U256::LIMBS + i], TWO_MODULUS_255_DISTANCE.as_limbs()[j], carry);
    }
    carries[i + U128::LIMBS] = carry;
  }
  carry = Limb::ZERO;
  for j in U256::LIMBS .. (U256::LIMBS + U128::LIMBS) {
    (limbs[j], carry) = add_with_bounded_overflow(limbs[j], carries[j], carry);
  }

  /*
    The 384th bit may be set, despite just multiplying those limbs out. We resolve this by
    explicitly reducing the 384th bit out with the addition of `(2**256 % MODULUS) << 128`. The
    resulting carry is guaranteed to be non-zero as
    ```
    (2**384 - 1) + # The maximum value present in limbs
      (((2**128 - 1) * (2 * (2**255 - MODULUS))) << 128) - # Reduce out the maximum highest bits
      2**384 + # Subtract the 384th bit, if set
      ((2 * (2**255 - MODULUS)) << 128) < # The corresponding reduction for the 384th bit
      2**384 # The bound representable by the remaining limbs
    ```
  */
  let three_eighty_four_carry = carry.wrapping_neg();
  let mut carry = Limb::ZERO;
  for j in 0 .. U128::LIMBS {
    (limbs[U128::LIMBS + j], carry) = add_with_bounded_overflow(
      limbs[U128::LIMBS + j],
      three_eighty_four_carry & TWO_MODULUS_255_DISTANCE.as_limbs()[j],
      carry,
    );
  }
  for j in U128::LIMBS .. U256::LIMBS {
    (limbs[U128::LIMBS + j], carry) =
      add_with_bounded_overflow(limbs[U128::LIMBS + j], Limb::ZERO, carry);
  }

  // Perform the 128-bit multiplication with the next highest bits
  for i in 0 .. U128::LIMBS {
    (limbs[i], carry) =
      limbs[i].mac(limbs[U256::LIMBS + i], TWO_MODULUS_255_DISTANCE.as_limbs()[0], Limb::ZERO);
    for j in 1 .. U128::LIMBS {
      (limbs[i + j], carry) =
        limbs[i + j].mac(limbs[U256::LIMBS + i], TWO_MODULUS_255_DISTANCE.as_limbs()[j], carry);
    }
    carries[i + U128::LIMBS] = carry;
  }
  carry = Limb::ZERO;
  for j in U128::LIMBS .. U256::LIMBS {
    (limbs[j], carry) = add_with_bounded_overflow(limbs[j], carries[j], carry);
  }

  // As with the 384th bit, we now reduce out the 256th bit if set, which again won't overflow
  let two_fifty_six_carry = carry.wrapping_neg();
  let mut carry = Limb::ZERO;
  for i in 0 .. U128::LIMBS {
    (limbs[i], carry) = add_with_bounded_overflow(
      limbs[i],
      two_fifty_six_carry & TWO_MODULUS_255_DISTANCE.as_limbs()[i],
      carry,
    );
  }
  for i in U128::LIMBS .. U256::LIMBS {
    let (limb, carry_bool) = limbs[i].0.overflowing_add(carry.0);
    (limbs[i], carry) = (Limb(limb), Limb(Word::from(carry_bool)));
  }

  let mut res = U256::ZERO;
  res.as_limbs_mut().copy_from_slice(&limbs[.. U256::LIMBS]);
  // Convert `res` to a valid scalar
  red256(res)
}

// The following tests assume a 64-bit host as it uses crypto-bigint's limbs directly
#[cfg(test)]
#[cfg(target_pointer_width = "64")]
mod tests_assuming_64_bits {
  use super::*;

  #[inline(always)]
  fn lo_hi_split<T, S: crypto_bigint::Split<Output = T>>(a: &S) -> (T, T) {
    let (hi, lo) = a.split();
    (lo, hi)
  }

  #[inline(always)]
  fn lo_hi_concat<T, S: crypto_bigint::Concat<Output = T>>(a: &S, b: &S) -> T {
    S::concat(b, a)
  }

  #[test]
  fn test_reduction_of_each_bit() {
    for b in 0 .. 512usize {
      let to_reduce = crypto_bigint::U512::ONE << b;
      let reduced = to_reduce.checked_rem(&lo_hi_concat(&MODULUS, &U256::ZERO)).unwrap();

      if b < 256 {
        let reduced_apo = red256(lo_hi_split(&to_reduce).0);
        assert_eq!(
          &reduced.as_limbs()[.. 4],
          reduced_apo.0.as_limbs(),
          "failed to reduce the 256-bit 1 << {b}"
        );
      }

      let reduced_apo = red512(lo_hi_split(&to_reduce));
      assert_eq!(
        &reduced.as_limbs()[.. 4],
        reduced_apo.0.as_limbs(),
        "failed to reduce the 512-bit 1 << {b}"
      );
    }
  }
}
