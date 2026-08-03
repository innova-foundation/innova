//! A build script to derive the FCMP++ generators are time of compile (if enabled).

use std::{
  io::Write as _,
  env,
  path::Path,
  fs::{File, remove_file},
};

#[cfg(feature = "compile-time-generators")]
trait NewGenerators: ciphersuite::Ciphersuite {
  fn new_generators() -> monero_fcmp_plus_plus_generators::FcmpGenerators<Self>;
}
#[cfg(feature = "compile-time-generators")]
impl NewGenerators for helioselene::Helios {
  fn new_generators() -> monero_fcmp_plus_plus_generators::FcmpGenerators<Self> {
    monero_fcmp_plus_plus_generators::FcmpGenerators::<Self>::new()
  }
}
#[cfg(feature = "compile-time-generators")]
impl NewGenerators for helioselene::Selene {
  fn new_generators() -> monero_fcmp_plus_plus_generators::FcmpGenerators<Self> {
    monero_fcmp_plus_plus_generators::FcmpGenerators::<Self>::new()
  }
}

#[cfg(feature = "compile-time-generators")]
fn generator_set<C: NewGenerators>()
where
  C::G: ec_divisors::DivisorCurve,
{
  use ciphersuite::group::ff::PrimeField as _;
  use ec_divisors::DivisorCurve;

  fn read_point(point: &str, x_str: &str, y_str: &str) -> String {
    format!(
      "
        helioselene::{point}::from_xy(
          <
            <helioselene::{point} as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr({x_str}).expect(\"build script x wasn't reduced\"),
          <
            <helioselene::{point} as ec_divisors::DivisorCurve>::FieldElement
              as
            ciphersuite::group::ff::PrimeField
          >::from_repr({y_str}).expect(\"build script y wasn't reduced\"),
        ).expect(\"generator from build script wasn't on-curve\")
      "
    )
  }

  fn serialize<G: DivisorCurve>(point: &str, generator: G) -> String {
    let (x, y) = G::to_xy(generator).expect("generator was the identity?");
    read_point(
      point,
      &format!("{:?}", x.to_repr().as_ref()),
      &format!("{:?}", y.to_repr().as_ref()),
    )
  }

  let id =
    String::from_utf8(C::ID.to_vec()).expect("Helios/Selene Ciphersuite ID wasn't valid UTF-8");
  let point = format!("{id}Point");
  let path = format!("{}_generators", id.clone().to_lowercase());
  let g_bold_path = path.clone() + "_g_bold";
  let h_bold_path = path.clone() + "_h_bold";
  let path = path + ".rs";

  let generators = C::new_generators();

  let dir = env::var("OUT_DIR").expect("cargo didn't set $OUT_DIR");
  let dir = Path::new(&dir);

  let read_bytes = |path, points: &[C::G]| {
    let mut bytes: Vec<u8> = Vec::with_capacity((2 * 32) * points.len());
    for generator in points {
      let (x, y) = C::G::to_xy(*generator).expect("generator was the identity?");
      bytes.extend(x.to_repr().as_ref());
      bytes.extend(y.to_repr().as_ref());
    }

    {
      let path = dir.join(&path);
      let _ = remove_file(&path);
      File::create(&path)
        .expect("failed to create file in $OUT_DIR")
        .write_all(&bytes)
        .expect("couldn't write points as bytes to file in $OUT_DIR");
    }

    format!(
      "
        {{
          const BYTES: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{path}\"));
          let mut bytes = BYTES;
          let mut x = [0; 32];
          let mut y = [0; 32];
          let mut res = Vec::with_capacity({});
          while !bytes.is_empty() {{
            x.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            y.copy_from_slice(&bytes[.. 32]);
            bytes = &bytes[32 ..];
            res.push({});
          }}
          res
        }}
      ",
      points.len(),
      read_point(&point, "x", "y"),
    )
  };

  let path = dir.join(&path);
  let _ = remove_file(&path);
  // TODO: Don't expose these with `pub`
  File::create(&path)
    .expect("failed to create file in $OUT_DIR")
    .write_all(
      format!(
        "
          /// The FCMP generators for {id}.
          pub static {}_FCMP_GENERATORS:
            std_shims::sync::LazyLock<
              monero_fcmp_plus_plus_generators::FcmpGenerators<helioselene::{}>
            > =
              std_shims::sync::LazyLock::new(|| monero_fcmp_plus_plus_generators::FcmpGenerators {{
                generators: generalized_bulletproofs::Generators::new(
                  {},
                  {},
                  {},
                  {},
                ).unwrap()
              }});
        ",
        id.clone().to_uppercase(),
        id,
        serialize(&point, generators.generators.g()),
        serialize(&point, generators.generators.h()),
        read_bytes(g_bold_path, generators.generators.g_bold_slice()),
        read_bytes(h_bold_path, generators.generators.h_bold_slice()),
      )
      .as_bytes(),
    )
    .expect("couldn't write generated source code to file on disk");
}

#[cfg(feature = "compile-time-generators")]
fn generators() {
  generator_set::<helioselene::Helios>();
  generator_set::<helioselene::Selene>();
  let path =
    Path::new(&env::var("OUT_DIR").expect("cargo didn't set $OUT_DIR")).join("generators.rs");
  let _ = remove_file(&path);
  File::create(&path)
    .expect("failed to create file in $OUT_DIR")
    .write_all(
      b"
        include!(concat!(env!(\"OUT_DIR\"), \"/helios_generators.rs\"));
        include!(concat!(env!(\"OUT_DIR\"), \"/selene_generators.rs\"));
      ",
    )
    .expect("couldn't write generated source code to file on disk");
}

#[cfg(not(feature = "compile-time-generators"))]
fn generators() {
  let path =
    Path::new(&env::var("OUT_DIR").expect("cargo didn't set $OUT_DIR")).join("generators.rs");
  let _ = remove_file(&path);
  File::create(&path)
    .expect("failed to create file in $OUT_DIR")
    .write_all(
      format!(
        "
          /// The FCMP generators for Helios.
          pub static HELIOS_FCMP_GENERATORS: LazyLock<
            monero_fcmp_plus_plus_generators::FcmpGenerators<Helios>
          > =
            LazyLock::new(monero_fcmp_plus_plus_generators::FcmpGenerators::<Helios>::new);
          /// The FCMP generators for Selene.
          pub static SELENE_FCMP_GENERATORS: LazyLock<
            monero_fcmp_plus_plus_generators::FcmpGenerators<Selene>
          > =
            LazyLock::new(monero_fcmp_plus_plus_generators::FcmpGenerators::<Selene>::new);
      ",
      )
      .as_bytes(),
    )
    .expect("couldn't write generated source code to file on disk");
}

fn main() {
  println!("cargo:rerun-if-changed=build.rs");

  generators();
}
