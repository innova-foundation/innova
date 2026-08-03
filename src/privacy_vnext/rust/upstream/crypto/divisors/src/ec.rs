#![allow(clippy::many_single_char_names)]

use core::ops::{Add, Neg};
use std_shims::vec::Vec;

use zeroize::Zeroize;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use ff::{Field, BatchInvert as _};

use crate::DivisorCurve;

/// A trait representing a point with `(X, Y, _)` coordinates.
///
/// This makes no assumptions about how the point is represented yet expects the points to offer
/// cheap conversions to affine coordinates.
pub trait XyPoint<F: Field>:
  Sized
  + Clone
  + Copy
  + Neg<Output = Self>
  + Add<Output = Self>
  + Zeroize
  + ConstantTimeEq
  + ConditionallySelectable
{
  /// The additive identity.
  const IDENTITY: Self;
  /// If this point is the identity.
  fn is_identity(&self) -> Choice;
  /// Double the point.
  #[must_use]
  fn double(self) -> Self;
  /// Convert a list of points to their affine coordinates.
  ///
  /// This method MAY panic if any present points are the identity or return an undefined value.
  fn batch_to_xy(points: &[Self]) -> Vec<(F, F)>;
}

/// A point in projective coordinates.
#[derive(Debug, Clone, Copy, Eq)]
pub struct Projective<C: DivisorCurve> {
  x: C::FieldElement,
  y: C::FieldElement,
  z: C::FieldElement,
}

impl<C: DivisorCurve> Zeroize for Projective<C> {
  fn zeroize(&mut self) {
    let Self { x, y, z } = self;
    x.zeroize();
    y.zeroize();
    z.zeroize();
    self.x = Self::IDENTITY.x;
    self.y = Self::IDENTITY.y;
    self.z = Self::IDENTITY.z;
  }
}

impl<C: DivisorCurve> ConstantTimeEq for Projective<C> {
  fn ct_eq(&self, other: &Self) -> Choice {
    let c1 = (self.x * other.z).ct_eq(&(other.x * self.z));
    let c2 = (self.y * other.z).ct_eq(&(other.y * self.z));
    c1 & c2
  }
}

impl<C: DivisorCurve> PartialEq for Projective<C> {
  fn eq(&self, other: &Self) -> bool {
    self.ct_eq(other).into()
  }
}

impl<C: DivisorCurve> Neg for Projective<C> {
  type Output = Self;
  fn neg(mut self) -> Self::Output {
    self.y = -self.y;
    self
  }
}

impl<C: DivisorCurve> ConditionallySelectable for Projective<C> {
  fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
    let x = C::FieldElement::conditional_select(&a.x, &b.x, choice);
    let y = C::FieldElement::conditional_select(&a.y, &b.y, choice);
    let z = C::FieldElement::conditional_select(&a.z, &b.z, choice);
    Projective { x, y, z }
  }
}

impl<C: DivisorCurve> From<C> for Projective<C> {
  fn from(point: C) -> Self {
    let Some((x, y)) = C::to_xy(point) else { return Self::IDENTITY };
    Self { x, y, z: C::FieldElement::ONE }
  }
}

impl<C: DivisorCurve> Add for Projective<C> {
  type Output = Self;
  // add-1998-cmo-2
  fn add(self, p2: Self) -> Self {
    let Self { x: X1, y: Y1, z: Z1 } = self;
    let Self { x: X2, y: Y2, z: Z2 } = p2;

    let Y1Z2 = Y1 * Z2;
    let X1Z2 = X1 * Z2;
    let Z1Z2 = Z1 * Z2;
    let u = (Y2 * Z1) - Y1Z2;
    let uu = u.square();
    let v = (X2 * Z1) - X1Z2;
    let vv = v.square();
    let vvv = v * vv;
    let R = vv * X1Z2;
    let A = (uu * Z1Z2) - vvv - R.double();
    let X3 = v * A;
    let Y3 = (u * (R - A)) - (vvv * Y1Z2);
    let Z3 = vvv * Z1Z2;

    let res = Self { x: X3, y: Y3, z: Z3 };

    let same_x_coordinate = (self.x * p2.z).ct_eq(&(p2.x * self.z));
    let same_y_coordinate = (self.y * p2.z).ct_eq(&(p2.y * self.z));
    let res = <_>::conditional_select(
      &res,
      &Self::IDENTITY,
      (self.is_identity() & p2.is_identity()) | (same_x_coordinate & (!same_y_coordinate)),
    );
    let res = <_>::conditional_select(&res, &self.double(), same_x_coordinate & same_y_coordinate);
    let res = <_>::conditional_select(&res, &p2, self.is_identity());
    <_>::conditional_select(&res, &self, p2.is_identity())
  }
}

impl<C: DivisorCurve> XyPoint<C::FieldElement> for Projective<C> {
  const IDENTITY: Self =
    Projective { x: C::FieldElement::ZERO, y: C::FieldElement::ONE, z: C::FieldElement::ZERO };

  fn is_identity(&self) -> Choice {
    self.z.ct_eq(&C::FieldElement::ZERO)
  }

  // dbl-1998-cmo-2
  fn double(self) -> Self {
    let Self { x: X1, y: Y1, z: Z1 } = self;

    let X1X1 = X1.square();
    let w = (C::a() * Z1.square()) + X1X1.double() + X1X1;
    let s = Y1 * Z1;
    let ss = s.square();
    let sss = s * ss;
    let R = Y1 * s;
    let B = X1 * R;
    let B4 = B.double().double();
    let h = w.square() - B4.double();
    let X3 = (h * s).double();
    let Y3 = w * (B4 - h) - R.square().double().double().double();
    let Z3 = sss.double().double().double();

    let res = Self { x: X3, y: Y3, z: Z3 };
    <_>::conditional_select(&res, &Self::IDENTITY, self.is_identity())
  }

  fn batch_to_xy(points: &[Self]) -> Vec<(C::FieldElement, C::FieldElement)> {
    let mut z = points
      .iter()
      .map(|p| {
        assert!(bool::from(!p.z.is_zero()));
        p.z
      })
      .collect::<Vec<_>>();
    (&mut z).batch_invert();
    points.iter().zip(z).map(|(p, z_inv)| (p.x * z_inv, p.y * z_inv)).collect()
  }
}

#[cfg(test)]
mod ed25519_test {
  use group::{ff::Field as _, Group as _};
  use dalek_ff_group::{FieldElement, EdwardsPoint};
  use crate::{
    ec::{Projective, XyPoint as _},
    DivisorCurve as _,
  };

  #[test]
  fn projective() {
    let to_xy = |p| EdwardsPoint::to_xy(p).unwrap();

    fn to_affine_slow(p: Projective<EdwardsPoint>) -> (FieldElement, FieldElement) {
      let Projective { x, y, z } = p;
      let z_inv = z.invert().unwrap();
      (x * z_inv, y * z_inv)
    }

    let point = EdwardsPoint::generator();
    let projective = Projective::from(point);
    assert_eq!(to_affine_slow(projective), to_xy(point));

    let doubled = point.double();
    let doubled_projective = projective.double();
    assert_eq!(to_affine_slow(doubled_projective), to_xy(doubled));

    let triple = doubled + point;
    let triple_projective = projective + doubled_projective;
    assert_eq!(to_affine_slow(triple_projective), to_xy(triple));

    // Handle all possible edge cases within the addition function
    assert_eq!(
      Projective::<EdwardsPoint>::IDENTITY + Projective::<EdwardsPoint>::IDENTITY,
      Projective::<EdwardsPoint>::IDENTITY,
      "identity + identity"
    );
    assert_eq!(Projective::<EdwardsPoint>::IDENTITY + projective, projective, "identity + point");
    assert_eq!(projective + Projective::<EdwardsPoint>::IDENTITY, projective, "point + identity");
    assert_eq!(projective + projective, projective.double(), "point + point");
    assert_eq!(projective + -projective, Projective::<EdwardsPoint>::IDENTITY, "point + -point");

    // Handle edge cases with addition
    assert_eq!(Projective::<EdwardsPoint>::IDENTITY.double(), Projective::<EdwardsPoint>::IDENTITY);
  }
}
