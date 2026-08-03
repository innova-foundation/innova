use super::*;

#[inline(always)]
pub(crate) fn pow(base: &HelioseleneField, exp: HelioseleneField) -> HelioseleneField {
  let mut table = [HelioseleneField::ONE; 16];
  table[1] = *base;
  table[2] = base.square();
  table[3] = table[2] * base;
  table[4] = table[2].square();
  table[5] = table[4] * base;
  table[6] = table[3].square();
  table[7] = table[6] * base;
  table[8] = table[4].square();
  table[9] = table[8] * base;
  table[10] = table[5].square();
  table[11] = table[10] * base;
  table[12] = table[6].square();
  table[13] = table[12] * base;
  table[14] = table[7].square();
  table[15] = table[14] * base;

  let mut res = HelioseleneField::ONE;
  let mut bits = 0;
  for (i, mut bit) in exp.to_le_bits().iter_mut().rev().enumerate() {
    bits <<= 1;
    let mut bit = crate::u8_from_bool(bit.deref_mut());
    bits |= bit;
    bit.zeroize();

    if ((i + 1) % 4) == 0 {
      if i != 3 {
        for _ in 0 .. 4 {
          res = res.square();
        }
      }

      let mut factor = table[0];
      for (j, candidate) in table[1 ..].iter().enumerate() {
        let j = j + 1;
        factor =
          HelioseleneField::conditional_select(&factor, candidate, usize::from(bits).ct_eq(&j));
      }
      res *= factor;
      bits = 0;
    }
  }
  res
}
