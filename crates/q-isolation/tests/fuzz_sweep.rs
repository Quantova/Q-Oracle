// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_airlock::Artifact;
use q_isolation::{admit, PqArtifact, CROSSING_KIND_COUNT};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max_len + 1);
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            for b in self.next().to_le_bytes() {
                if v.len() < len {
                    v.push(b);
                }
            }
        }
        v
    }
}

fn assert_crossing_is_canonical_post_quantum(bytes: &[u8]) {
    if let Ok(crossing) = admit(bytes) {
        assert!(crossing.kind.index() < CROSSING_KIND_COUNT);
        let canonical = match &crossing.artifact {
            Artifact::Attestation(a) => {
                assert_eq!(crossing.kind, PqArtifact::MlDsaAttestation);
                a.encode()
            }
            Artifact::Stark(s) => {
                assert_eq!(crossing.kind, PqArtifact::HashStark);
                s.encode()
            }
        };
        let again = admit(&canonical).expect("a crossing re admits");
        assert_eq!(again, crossing);
    }
}

#[test]
fn random_bytes_never_produce_a_foreign_crossing() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_0001);
    for _ in 0..200_000 {
        let input = rng.bytes(320);
        assert_crossing_is_canonical_post_quantum(&input);
    }
}

#[test]
fn foreign_marker_bytes_never_cross() {
    let markers = [0x30u8, 0x04, 0x03, 0xf9, 0xa0, 0x80, 0x0a, 0x45, 0xff, 0x00];
    let mut rng = Rng(0xFEED_FACE_0000_0002);
    for marker in markers {
        for _ in 0..20_000 {
            let mut input = vec![marker];
            input.extend_from_slice(&rng.bytes(300));
            assert!(
                admit(&input).is_err(),
                "a foreign marker byte must never lead a crossing"
            );
        }
    }
}

#[test]
fn foreign_signature_shaped_bytes_never_cross() {
    let mut rng = Rng(0x0102_0304_0506_0708);
    for _ in 0..60_000 {
        let mut der = vec![0x30u8, 0x44, 0x02, 0x20];
        der.extend_from_slice(&rng.bytes(80));
        assert!(admit(&der).is_err(), "der signature bytes never cross");
    }
}
