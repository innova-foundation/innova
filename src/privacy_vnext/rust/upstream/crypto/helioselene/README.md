# Helioselene

An Implementation of Helios and Selene, a curve cycle towering Ed25519.
Please refer to https://gist.github.com/tevador/4524c2092178df08996487d4e272b096
for documentation of these curves, and our
[`audits/` folder](
  https://github.com/monero-oxide/monero-oxide/tree/fcmp++/audits
).

### Bespoke Field Implementation

The Helios, Selene curves use the `2**255-19` finite field used by Ed25519,
along with a finite field over the prime
`0x7ffffffffffffffffffffffffffffffff735481d1969f317f9850b68df11df53`. The
mutual field, over `2**255-19`, has its implementation provided by
`dalek-ff-group`. The bespoke field has its implementation within this crate.

The implementation is technically premised on `crypto-bigint` yet implements
most arithmetic itself for performance reasons, such as the modular reduction
premised on how the modulus is a Crandall prime. Some functions within the
implementation of this field, as of commit
`27b1c7f2918444560c7383e7a5fbddb481dbf2d2`,
[were formally verified by Veridise](
  https://github.com/VeridiseAuditing/helioselene-dafny-proofs
). While their scope did include the formal verification of the library as a
whole, only the implementation of some functions was completed within the time
constraints. The exact functions used to implement the field which were marked
as formally verified have been isolated in the `src/field/verified` folder.
Note the caveat that a translation into Dafny was formally verified, not the
literal Rust as written.

The original formal verification noted a flaw in the implementation, which was
fixed with commit `00bafcf08e9f0bbe334e68b6d89ddbaccc292c6c`.
