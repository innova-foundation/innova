//! Pinned hash-to-point over ed25519 (consensus-critical): a length-prefixed Blake2b-512
//! transcript truncated to 32 bytes, then `monero_ed25519::Point::hash` (two Elligator 2
//! maps, cofactor-cleared). The result is in the prime-order subgroup.

// Inert until the voting path calls it.
#![allow(dead_code)]

use blake2::{Blake2b512, Digest};
use curve25519_dalek::edwards::EdwardsPoint;
use monero_ed25519::Point;

/// Base for the per-epoch voting tag. Bumping the suffix retires every tag derived under it.
pub(crate) const VOTE_TAG_BASE_DOMAIN: &[u8] = b"Innova/IV5/Vote/TagBase/v1";

pub(crate) fn hash_to_point(domain: &[u8], fields: &[&[u8]]) -> EdwardsPoint {
    let mut transcript = Blake2b512::new();
    transcript.update(domain);
    for field in fields {
        transcript.update((field.len() as u64).to_le_bytes());
        transcript.update(field);
    }
    let digest = transcript.finalize();
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&digest[..32]);
    Point::hash(seed).into()
}

/// `U_e` for an epoch. Note-independent by construction: a per-note base could not be checked
/// without naming the note.
pub(crate) fn vote_tag_base(epoch: u64) -> EdwardsPoint {
    hash_to_point(VOTE_TAG_BASE_DOMAIN, &[&epoch.to_le_bytes()])
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::traits::IsIdentity as _;

    use super::*;

    /// Committed vectors for `vote_tag_base`; consensus depends on them.
    const VOTE_TAG_BASE_VECTORS: [(u64, [u8; 32]); 5] = [
        (
            0,
            [
                0xb7, 0x28, 0xc4, 0xc3, 0xdd, 0x7e, 0x4c, 0x90, 0xc4, 0x5e, 0x97, 0xe9, 0x76, 0x2f,
                0x8e, 0x7c, 0xf6, 0x6f, 0x6a, 0xf7, 0x0b, 0x4c, 0xb3, 0xa2, 0x72, 0x4b, 0x41, 0x13,
                0xc7, 0xe3, 0xc7, 0x13,
            ],
        ),
        (
            1,
            [
                0x44, 0xd4, 0xee, 0xe2, 0x6e, 0x62, 0x8d, 0x05, 0xc2, 0xf4, 0xbf, 0x8f, 0x9e, 0xc4,
                0x24, 0xb1, 0x8d, 0x7c, 0xe9, 0x9f, 0xc6, 0x1d, 0x84, 0xba, 0x7d, 0x77, 0xc8, 0x3d,
                0x37, 0x44, 0x74, 0x05,
            ],
        ),
        (
            2,
            [
                0x59, 0x37, 0xaf, 0xaf, 0x8d, 0xc3, 0x6b, 0x5d, 0xac, 0x6a, 0xb5, 0x87, 0x40, 0x1a,
                0x1a, 0x84, 0x3b, 0x67, 0xb9, 0x19, 0x55, 0xba, 0x28, 0xc5, 0x90, 0x2f, 0xf9, 0xb8,
                0xcc, 0x0e, 0x23, 0x82,
            ],
        ),
        (
            1_000,
            [
                0xa9, 0xba, 0x82, 0xe5, 0xc6, 0x94, 0xdc, 0x9d, 0x06, 0x9f, 0xb4, 0x15, 0x53, 0xab,
                0x8d, 0xf9, 0xf8, 0xc0, 0x6e, 0xc2, 0x38, 0xaa, 0x0b, 0xe9, 0xea, 0x6d, 0xe5, 0xff,
                0xb4, 0xd2, 0xfa, 0x93,
            ],
        ),
        (
            u64::MAX,
            [
                0x69, 0xed, 0x92, 0x65, 0x4a, 0x38, 0xa9, 0x7c, 0xb9, 0x83, 0xd9, 0xc5, 0x6e, 0x9a,
                0x8d, 0x6a, 0x1a, 0x5a, 0x7b, 0xa5, 0x13, 0x4e, 0x99, 0x86, 0x68, 0x0e, 0x76, 0xe1,
                0x3e, 0x4e, 0x49, 0x87,
            ],
        ),
    ];

    #[test]
    fn vote_tag_base_matches_its_committed_vectors() {
        for (epoch, expected) in VOTE_TAG_BASE_VECTORS {
            assert_eq!(
                vote_tag_base(epoch).compress().to_bytes(),
                expected,
                "epoch {epoch} derives a different base than the pinned vector"
            );
        }
    }

    // Each committed point must be rejected at every other epoch.
    #[test]
    fn vote_tag_base_vectors_reject_a_wrong_point() {
        for (epoch, expected) in VOTE_TAG_BASE_VECTORS {
            let derived = vote_tag_base(epoch).compress().to_bytes();
            for (other_epoch, other) in VOTE_TAG_BASE_VECTORS {
                assert_eq!(
                    derived == other,
                    epoch == other_epoch,
                    "epoch {epoch} and epoch {other_epoch} disagree with their vectors"
                );
            }
            let mut perturbed = expected;
            perturbed[0] ^= 1;
            assert_ne!(derived, perturbed);
            let mut tail_perturbed = expected;
            tail_perturbed[31] ^= 0x80;
            assert_ne!(derived, tail_perturbed);
        }
    }

    // The result is a discrete-log base: prime order, not identity or small order.
    #[test]
    fn derived_bases_are_prime_order_and_nonidentity() {
        for epoch in [0_u64, 1, 2, 7, 1_000, u64::MAX] {
            let point = vote_tag_base(epoch);
            assert!(!point.is_identity());
            assert!(point.is_torsion_free());
            let bytes = point.compress().to_bytes();
            assert_eq!(
                curve25519_dalek::edwards::CompressedEdwardsY(bytes)
                    .decompress()
                    .map(|round_trip| round_trip.compress().to_bytes()),
                Some(bytes),
                "a derived base must survive a compress/decompress round trip"
            );
        }
    }

    // The length prefix keeps the domain/first-field boundary injective.
    #[test]
    fn field_boundaries_are_unambiguous() {
        assert_ne!(
            hash_to_point(b"Innova/IV5/Test/A", &[b"BC"]),
            hash_to_point(b"Innova/IV5/Test/AB", &[b"C"])
        );
        assert_ne!(
            hash_to_point(b"Innova/IV5/Test", &[b"AB", b"C"]),
            hash_to_point(b"Innova/IV5/Test", &[b"A", b"BC"])
        );
        assert_ne!(
            hash_to_point(b"Innova/IV5/Test", &[b"A", b""]),
            hash_to_point(b"Innova/IV5/Test", &[b"A"])
        );
    }

    // Transcripts length-prefix only the fields, not the domain, so label separation relies on
    // no label being a prefix of another. Changing that would change every derived point
    // (fork), so the invariant is checked here against labels read from the sources.
    #[test]
    fn no_hashing_domain_is_a_prefix_of_another() {
        const LIB: &str = include_str!("lib.rs");
        const SOURCES: &[&str] = &[
            include_str!("disclosure.rs"),
            include_str!("fcmp.rs"),
            include_str!("hash_to_point.rs"),
            LIB,
            include_str!("note.rs"),
            include_str!("nullifier.rs"),
            include_str!("payload.rs"),
            include_str!("tree.rs"),
            include_str!("value.rs"),
            include_str!("vote.rs"),
        ];
        // Written escaped so the scan does not match its own needle.
        const NEEDLE: &str = "b\"Innova/";

        // The source list is hand-written; it is checked against the crate's module list.
        let declared = LIB
            .lines()
            .filter(|line| line.starts_with("mod ") && line.ends_with(';'))
            .count();
        assert_eq!(
            declared + 1,
            SOURCES.len(),
            "every module lib.rs declares must be scanned for hashing domains"
        );

        let mut domains: Vec<&str> = Vec::new();
        for source in SOURCES {
            let mut rest: &str = source;
            while let Some(start) = rest.find(NEEDLE) {
                rest = &rest[start + 2..];
                let end = rest.find('"').expect("a domain literal must be closed");
                let domain = &rest[..end];
                rest = &rest[end + 1..];
                // The fixtures above are deliberately prefix-related and are never hashed
                // into consensus data.
                if !domain.starts_with("Innova/IV5/Test") && !domains.contains(&domain) {
                    domains.push(domain);
                }
            }
        }

        // A scan that matched nothing would satisfy every check below.
        let count = domains.len();
        assert!(count >= 30, "expected the crate's domain set, found {count}");

        for domain in &domains {
            assert!(
                domain.bytes().all(|byte| (0x20..0x7f).contains(&byte)),
                "domain {domain} must stay printable NUL-free ASCII"
            );
        }
        for (i, shorter) in domains.iter().enumerate() {
            for (j, longer) in domains.iter().enumerate() {
                assert!(
                    i == j || !longer.starts_with(shorter),
                    "domain {shorter} is a prefix of {longer}, so the unprefixed domain no \
                     longer separates their transcripts"
                );
            }
        }
    }

    // The epoch must reach the transcript at a fixed width.
    #[test]
    fn the_epoch_and_its_domain_both_separate_bases() {
        assert_ne!(vote_tag_base(0), vote_tag_base(1));
        assert_ne!(vote_tag_base(1), vote_tag_base(256));
        assert_ne!(
            vote_tag_base(1),
            hash_to_point(VOTE_TAG_BASE_DOMAIN, &[&1_u32.to_le_bytes()]),
            "the epoch must be transcripted at its pinned width"
        );
        assert_ne!(
            vote_tag_base(1),
            hash_to_point(VOTE_TAG_BASE_DOMAIN, &[&1_u64.to_be_bytes()]),
            "the epoch must be transcripted in its pinned byte order"
        );
        assert_ne!(
            vote_tag_base(0),
            hash_to_point(b"Innova/IV5/Vote/TagBase/v2", &[&0_u64.to_le_bytes()])
        );
    }

    // The biased single-application map must not be the pinned one.
    #[test]
    fn the_pinned_map_is_the_unbiased_one() {
        let mut transcript = Blake2b512::new();
        transcript.update(VOTE_TAG_BASE_DOMAIN);
        transcript.update(8_u64.to_le_bytes());
        transcript.update(0_u64.to_le_bytes());
        let digest = transcript.finalize();
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&digest[..32]);
        assert_eq!(vote_tag_base(0), Point::hash(seed).into());
        assert_ne!(vote_tag_base(0), Point::biased_hash(seed).into());
    }
}
