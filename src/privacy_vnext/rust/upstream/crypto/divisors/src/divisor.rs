use core::ops::Div;
use std_shims::{vec, vec::Vec};

use subtle::{Choice, ConditionallySelectable, CtOption};
use ff::{PrimeField, BatchInvert as _};

use crate::barycentric::Interpolator;

#[derive(Debug, Clone)]
pub(super) struct Evals<F: PrimeField> {
  evals: Vec<F>,
  degree: usize,
}

impl<F: PrimeField> Evals<F> {
  fn new(evals: Vec<F>, degree: usize) -> Self {
    Self { evals, degree }
  }

  fn len(&self) -> usize {
    self.evals.len()
  }

  fn from_degree_1(coeff: F, constant: F, amount_of_evals: usize) -> Self {
    let mut evals = Vec::with_capacity(amount_of_evals);
    if amount_of_evals == 0 {
      return Evals { evals, degree: 1 };
    }
    let mut last_eval = constant;
    for _ in 0 .. amount_of_evals {
      evals.push(last_eval);
      last_eval += coeff;
    }
    Self { evals, degree: 1 }
  }

  fn from_degree_0(constant: F, evals: usize) -> Self {
    let evals = vec![constant; evals];
    Evals { evals, degree: 0 }
  }
}

#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy)]
pub(super) struct SmallDivisor<F: PrimeField> {
  x_coefficient: F,
  zero_coefficient: F,
  y_coefficient: F,
}

impl<F> ConditionallySelectable for SmallDivisor<F>
where
  F: PrimeField + ConditionallySelectable,
{
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    let x_coefficient = <_>::conditional_select(&a.x_coefficient, &b.x_coefficient, choice);
    let zero_coefficient =
      <_>::conditional_select(&a.zero_coefficient, &b.zero_coefficient, choice);
    let y_coefficient = <_>::conditional_select(&a.y_coefficient, &b.y_coefficient, choice);
    SmallDivisor { x_coefficient, zero_coefficient, y_coefficient }
  }
}

impl<F: PrimeField> SmallDivisor<F> {
  pub(super) fn new(x_coefficient: F, zero_coefficient: F, y_coefficient: F) -> Self {
    Self { x_coefficient, zero_coefficient, y_coefficient }
  }
}

/// A function `f(x, y) = A(x) - yB(x)`.
///
/// `A` and `B` are represented as a sufficient amount of evaluations from them to perform
/// interpolation and recover them.
#[derive(Debug, Clone)]
pub(super) struct Divisor<F: PrimeField> {
  a: Evals<F>,
  b: Evals<F>,
}

impl<F: PrimeField> Div<Evals<F>> for Divisor<F> {
  type Output = Self;

  fn div(mut self, mut rhs: Evals<F>) -> Self::Output {
    debug_assert_eq!(self.a.len(), self.b.len());
    debug_assert_eq!(self.a.len(), rhs.len());

    (&mut rhs.evals).batch_invert();
    for ((a, b), denom) in self.a.evals.iter_mut().zip(self.b.evals.iter_mut()).zip(rhs.evals) {
      *a *= denom;
      *b *= denom;
    }
    self.a.degree -= rhs.degree;
    self.b.degree -= rhs.degree;
    self
  }
}

impl<F: PrimeField> Divisor<F> {
  pub(super) fn compute_modulus(a: F, b: F, amount_of_evals: usize) -> Evals<F> {
    // x^3 + ax + b
    let mut evals = Vec::with_capacity(amount_of_evals);
    for i in 0 .. amount_of_evals {
      let x = F::from(u64::try_from(i).unwrap());
      let cube = x.square() * x;
      let ax = x * a;
      evals.push(cube + ax + b);
    }
    Evals::new(evals, 3)
  }

  pub(super) fn from_small(small: SmallDivisor<F>, modulus: &Evals<F>) -> Self {
    let SmallDivisor { x_coefficient, zero_coefficient, y_coefficient } = small;
    let evals = modulus.len();
    let a = Evals::from_degree_1(x_coefficient, zero_coefficient, evals);
    let b = Evals::from_degree_0(y_coefficient, evals);
    Self { a, b }
  }

  fn ab(&self, i: usize) -> (F, F) {
    let a = self.a.evals[i];
    let b = self.b.evals[i];
    (a, b)
  }

  fn ab_mut(&mut self, i: usize) -> (&mut F, &mut F) {
    let a = &mut self.a.evals[i];
    let b = &mut self.b.evals[i];
    (a, b)
  }

  /// The degrees of the A/B polynomials after the multiplication of these divisors.
  fn degree_after_multiplication(
    &self,
    other_a_degree: usize,
    other_b_degree: usize,
  ) -> (usize, usize) {
    // f1 * f2 = A1A2 - y(A1B2 + A2B1) + (x^3 + ax + b) B1B2
    // A = A1A2 + (x^3 + ax + b) B1B2
    // B = A1B2 + A2B1
    // deg(A) = max(A1 + A2, 3 + B1 + B2)
    // deg(B) = max(A1 + B2, A2 + B1)
    let (a1, b1) = (self.a.degree, self.b.degree);
    let (a2, b2) = (other_a_degree, other_b_degree);
    let a = (a1 + a2).max(3 + b1 + b2);
    let b = (a1 + b2).max(a2 + b1);
    (a, b)
  }

  fn mul_mod(mut self, rhs: &Self, modulus: &Evals<F>) -> Self {
    debug_assert_eq!(self.a.len(), rhs.a.len());
    debug_assert_eq!(self.b.len(), rhs.b.len());
    debug_assert_eq!(self.a.len(), self.b.len());

    let len = self.a.len();

    let degree_after_multiplication = self.degree_after_multiplication(rhs.a.degree, rhs.b.degree);
    // f1 * f2 = A1A2 - y(A1B2 + A2B1) + y^2 B1B2
    // f1 * f2 = A1A2 - y(A1B2 + A2B1) + (x^3 + ax + b) B1B2
    // (A1+B1)(A2+B2)
    // A1A2 + A1B2 + B1A2 + B1B2
    for i in 0 .. len {
      let modulus = modulus.evals[i];
      let (a1, b1) = self.ab_mut(i);
      let (a2, b2) = rhs.ab(i);
      let a1a2 = *a1 * a2;
      let b1b2 = *b1 * b2;
      // (A1+B1)(A2+B2)
      let cross = (*a1 + *b1) * (a2 + b2);
      let b = cross - (a1a2 + b1b2);
      let a = a1a2 + (b1b2 * modulus);
      *a1 = a;
      *b1 = b;
    }
    self.a.degree = degree_after_multiplication.0;
    self.b.degree = degree_after_multiplication.1;
    self
  }

  fn mul_mod_small(mut self, rhs: SmallDivisor<F>, modulus: &Evals<F>) -> Self {
    debug_assert_eq!(self.a.len(), self.b.len());

    let len = self.a.len();

    let degree_after_multiplication = self.degree_after_multiplication(1, 0);
    // constant term for x = 0
    let mut a2 = rhs.zero_coefficient;
    let b2 = rhs.y_coefficient;
    for i in 0 .. len {
      let modulus = modulus.evals[i];
      let (a1, b1) = self.ab_mut(i);
      let a1a2 = *a1 * a2;
      let b1b2 = *b1 * b2;
      // (A1+B1)(A2+B2)
      let cross = (*a1 + *b1) * (a2 + b2);
      let b = cross - (a1a2 + b1b2);
      let a = a1a2 + b1b2 * modulus;
      a2 += rhs.x_coefficient;
      *a1 = a;
      *b1 = b;
    }
    self.a.degree = degree_after_multiplication.0;
    self.b.degree = degree_after_multiplication.1;
    self
  }

  /// Remove 2 points by dividing by `(x - x1) * (x - x2)`.
  fn remove_diff(self, x1: CtOption<F>, x2: CtOption<F>) -> Self {
    debug_assert_eq!(self.a.len(), self.b.len());

    let mut denominator = Vec::with_capacity(self.a.len());
    let (mut x_l, mut x_r) = (F::ZERO, F::ZERO);
    let inc_l = F::from(u64::from(x1.is_some().unwrap_u8()));
    let inc_r = F::from(u64::from(x2.is_some().unwrap_u8()));
    let neg1 = -F::ONE;
    let (x1, x2) = (x1.unwrap_or(neg1), x2.unwrap_or(neg1));
    for _ in 0 .. self.a.len() {
      denominator.push((x_l - x1) * (x_r - x2));
      x_l += inc_l;
      x_r += inc_r;
    }
    let denominator = Evals { evals: denominator, degree: 2 };
    self / denominator
  }

  pub(super) fn merge(
    divisors: [Self; 2],
    small: SmallDivisor<F>,
    denom: (CtOption<F>, CtOption<F>),
    modulus: &Evals<F>,
  ) -> Self {
    let [d0, d1] = divisors;
    let numerator = d0.mul_mod(&d1, modulus).mul_mod_small(small, modulus);
    let (x1, x2) = denom;
    numerator.remove_diff(x1, x2)
  }

  pub(super) fn interpolate(&self, interpolator: &Interpolator<F>) -> Option<[Vec<F>; 2]> {
    if self.a.degree.max(self.b.degree) > interpolator.degree() {
      None?;
    }
    let a = interpolator.interpolate(&self.a.evals)?;
    let b = interpolator.interpolate(&self.b.evals)?;
    Some([a, b])
  }
}
