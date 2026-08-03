use super::*;

/// The modulus, plus one, divided by four, as used for calculating square roots.
const MODULUS_PLUS_ONE_DIV_FOUR: HelioseleneField = HelioseleneField(U256::from_be_hex(
  "1ffffffffffffffffffffffffffffffffdcd5207465a7cc5fe6142da37c477d5",
));

#[inline(always)]
pub(crate) fn sqrt(value: &HelioseleneField) -> CtOption<HelioseleneField> {
  let mut table = [HelioseleneField::ONE; 16];
  table[1] = *value;
  table[2] = value.square();
  table[3] = table[2] * value;
  table[4] = table[2].square();
  table[5] = table[4] * value;
  table[6] = table[3].square();
  table[7] = table[6] * value;
  table[8] = table[4].square();
  table[9] = table[8] * value;
  table[10] = table[5].square();
  table[11] = table[10] * value;
  table[12] = table[6].square();
  table[13] = table[12] * value;
  table[14] = table[7].square();
  table[15] = table[14] * value;

  // The first 128 bits are all set, hence this ladder to produce the value
  let mut res = table[15];
  let four_zero = res.square();
  let four_zero_zero = four_zero.square();
  res = four_zero_zero.square();
  res = res.square();
  res *= &table[15];
  let old_res = res;

  for _ in 0 .. 8 {
    res = res.square();
  }
  res *= &old_res;
  let old_res = res;

  for _ in 0 .. 16 {
    res = res.square();
  }
  res *= old_res;
  let old_res = res;

  for _ in 0 .. 32 {
    res = res.square();
  }
  res *= old_res;
  let old_res = res;

  for _ in 0 .. 64 {
    res = res.square();
  }
  res *= old_res;

  let mut bits = 0;
  for bit in MODULUS_PLUS_ONE_DIV_FOUR.to_le_bits().iter().take(253).rev().skip(128) {
    bits <<= 1;
    let bit = u8::from(*bit);
    bits |= bit;

    res = res.square();

    if (bits & (1 << 3)) != 0 {
      res *= table[usize::from(bits)];
      bits = 0;
    }
  }

  // Handle the final window
  res *= table[usize::from(bits)];

  // Normalize to the even choice of square root
  // `let ()` is used to assert how `conditional_negate` operates in-place
  let () = res.conditional_negate(res.is_odd());

  CtOption::new(res, res.square().ct_eq(value))
}
