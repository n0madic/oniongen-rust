#![allow(non_snake_case)]

use crate::fe::Fe;

/// Extended coordinates: (X:Y:Z:T) with x=X/Z, y=Y/Z, T=XY/Z
#[derive(Copy, Clone, Debug)]
pub struct ExtendedPoint {
    pub X: Fe,
    pub Y: Fe,
    pub Z: Fe,
    pub T: Fe,
}

/// Precomputed Niels point for fast addition: (Y+X, Y-X, Z, 2dXY)
#[derive(Copy, Clone, Debug)]
pub struct ProjectiveNielsPoint {
    pub Y_plus_X: Fe,
    pub Y_minus_X: Fe,
    pub Z: Fe,
    pub T2d: Fe,
}

/// Completed point in P1xP1 model: ((X:Z),(Y:T))
#[derive(Copy, Clone, Debug)]
struct CompletedPoint {
    X: Fe,
    Y: Fe,
    Z: Fe,
    T: Fe,
}

impl CompletedPoint {
    /// Convert to extended coordinates (4 multiplications)
    #[inline]
    fn as_extended(&self) -> ExtendedPoint {
        ExtendedPoint {
            X: self.X.mul(&self.T),
            Y: self.Y.mul(&self.Z),
            Z: self.Z.mul(&self.T),
            T: self.X.mul(&self.Y),
        }
    }
}

impl ExtendedPoint {
    pub const IDENTITY: ExtendedPoint = ExtendedPoint {
        X: Fe::ZERO,
        Y: Fe::ONE,
        Z: Fe::ONE,
        T: Fe::ZERO,
    };

    /// Decompress a CompressedEdwardsY (32 bytes) into an ExtendedPoint.
    /// Returns None if the y-coordinate is not on the curve.
    pub fn from_compressed(bytes: &[u8; 32]) -> Option<ExtendedPoint> {
        // Mask the sign bit, decode Y
        let mut y_bytes = *bytes;
        let sign_bit = y_bytes[31] >> 7;
        y_bytes[31] &= 0x7f;

        let Y = Fe::from_bytes(&y_bytes);
        let Z = Fe::ONE;
        let YY = Y.square();
        let u = YY.sub(&Z); // u = Y^2 - 1
        let v = YY.mul(&Fe::D).add(&Z); // v = d*Y^2 + 1

        let (is_valid, mut X) = Fe::sqrt_ratio_i(&u, &v);
        if !is_valid {
            return None;
        }

        // Negate X if the sign bit disagrees
        if X.is_negative() as u8 != sign_bit {
            X = X.neg();
        }

        let T = X.mul(&Y);
        Some(ExtendedPoint { X, Y, Z, T })
    }

    /// Convert to ProjectiveNielsPoint for fast readdition
    #[inline]
    pub fn as_projective_niels(&self) -> ProjectiveNielsPoint {
        ProjectiveNielsPoint {
            Y_plus_X: self.Y.add(&self.X),
            Y_minus_X: self.Y.sub(&self.X),
            Z: self.Z,
            T2d: self.T.mul(&Fe::D2),
        }
    }

    /// Add a ProjectiveNielsPoint to this point (4+4 = 8 multiplications total)
    #[inline]
    pub fn add_niels(&self, other: &ProjectiveNielsPoint) -> ExtendedPoint {
        let Y_plus_X = self.Y.add(&self.X);
        let Y_minus_X = self.Y.sub(&self.X);
        let PP = Y_plus_X.mul(&other.Y_plus_X);
        let MM = Y_minus_X.mul(&other.Y_minus_X);
        let TT2d = self.T.mul(&other.T2d);
        let ZZ = self.Z.mul(&other.Z);
        let ZZ2 = ZZ.add(&ZZ);

        let completed = CompletedPoint {
            X: PP.sub(&MM),
            Y: PP.add(&MM),
            Z: ZZ2.add(&TT2d),
            T: ZZ2.sub(&TT2d),
        };
        completed.as_extended()
    }

    /// Compress this point to 32 bytes (single point, uses inversion)
    pub fn compress(&self) -> [u8; 32] {
        let recip = self.Z.invert();
        let x = self.X.mul(&recip);
        let y = self.Y.mul(&recip);
        let mut s = y.as_bytes();
        s[31] ^= (x.is_negative() as u8) << 7;
        s
    }
}

/// Batch compress N points using only 1 field inversion + 3(N-1) multiplications.
/// This is the key optimization: ~28x faster than N individual compressions.
pub fn batch_compress(points: &[ExtendedPoint]) -> Vec<[u8; 32]> {
    let n = points.len();
    if n == 0 {
        return Vec::new();
    }

    // Collect Z coordinates and batch-invert them
    let mut z_invs: Vec<Fe> = points.iter().map(|p| p.Z).collect();
    Fe::batch_invert(&mut z_invs);

    // Compute compressed form for each point
    let mut result = Vec::with_capacity(n);
    for (point, z_inv) in points.iter().zip(z_invs.iter()) {
        let x = point.X.mul(z_inv);
        let y = point.Y.mul(z_inv);
        let mut s = y.as_bytes();
        s[31] ^= (x.is_negative() as u8) << 7;
        result.push(s);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::edwards::EdwardsPoint as DalekPoint;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn decompress_basepoint() {
        // Ed25519 basepoint compressed Y
        let basepoint_bytes: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        let pt = ExtendedPoint::from_compressed(&basepoint_bytes).unwrap();
        let compressed = pt.compress();
        assert_eq!(compressed, basepoint_bytes);
    }

    #[test]
    fn decompress_roundtrip() {
        // Generate a point using dalek, then roundtrip through our code
        let scalar = Scalar::from(42u64);
        let dalek_pt = DalekPoint::mul_base(&scalar);
        let bytes = *dalek_pt.compress().as_bytes();

        let our_pt = ExtendedPoint::from_compressed(&bytes).unwrap();
        assert_eq!(our_pt.compress(), bytes);
    }

    #[test]
    fn identity_decompress() {
        // Identity point = (0, 1)
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = 1; // y = 1 in little-endian
        let pt = ExtendedPoint::from_compressed(&id_bytes).unwrap();
        assert_eq!(pt.compress(), id_bytes);
    }

    #[test]
    fn addition_matches_dalek() {
        let scalar = Scalar::from(12345u64);
        let delta_scalar = Scalar::from(8u64);

        let dalek_pt = DalekPoint::mul_base(&scalar);
        let dalek_delta = DalekPoint::mul_base(&delta_scalar);

        let our_pt =
            ExtendedPoint::from_compressed(dalek_pt.compress().as_bytes()).unwrap();
        let our_delta =
            ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
        let delta_niels = our_delta.as_projective_niels();

        // Do 100 sequential additions and verify against dalek
        let mut d_pt = dalek_pt;
        let mut o_pt = our_pt;
        for _ in 0..100 {
            d_pt += dalek_delta;
            o_pt = o_pt.add_niels(&delta_niels);
            assert_eq!(
                o_pt.compress(),
                *d_pt.compress().as_bytes(),
                "Point addition mismatch"
            );
        }
    }

    #[test]
    fn batch_compress_matches_individual() {
        let scalar = Scalar::from(99999u64);
        let delta_scalar = Scalar::from(8u64);

        let dalek_pt = DalekPoint::mul_base(&scalar);
        let dalek_delta = DalekPoint::mul_base(&delta_scalar);

        let mut our_pt =
            ExtendedPoint::from_compressed(dalek_pt.compress().as_bytes()).unwrap();
        let our_delta =
            ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
        let delta_niels = our_delta.as_projective_niels();

        let mut points = Vec::new();
        for _ in 0..64 {
            points.push(our_pt);
            our_pt = our_pt.add_niels(&delta_niels);
        }

        let batch = batch_compress(&points);
        for (i, pt) in points.iter().enumerate() {
            assert_eq!(batch[i], pt.compress(), "Batch mismatch at index {i}");
        }
    }

    #[test]
    fn batch_compress_matches_dalek() {
        let scalar = Scalar::from(77777u64);
        let delta_scalar = Scalar::from(8u64);

        let mut dalek_pt = DalekPoint::mul_base(&scalar);
        let dalek_delta = DalekPoint::mul_base(&delta_scalar);

        let mut our_pt =
            ExtendedPoint::from_compressed(dalek_pt.compress().as_bytes()).unwrap();
        let our_delta =
            ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
        let delta_niels = our_delta.as_projective_niels();

        let mut points = Vec::new();
        let mut dalek_compressed = Vec::new();
        for _ in 0..64 {
            points.push(our_pt);
            dalek_compressed.push(*dalek_pt.compress().as_bytes());
            our_pt = our_pt.add_niels(&delta_niels);
            dalek_pt += dalek_delta;
        }

        let batch = batch_compress(&points);
        for i in 0..64 {
            assert_eq!(
                batch[i], dalek_compressed[i],
                "Batch compress != dalek at index {i}"
            );
        }
    }

    #[test]
    fn batch_compress_size_one() {
        let scalar = Scalar::from(42u64);
        let dalek_pt = DalekPoint::mul_base(&scalar);
        let bytes = *dalek_pt.compress().as_bytes();
        let pt = ExtendedPoint::from_compressed(&bytes).unwrap();
        let batch = batch_compress(&[pt]);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0], bytes);
    }

    #[test]
    fn batch_compress_empty() {
        let batch = batch_compress(&[]);
        assert!(batch.is_empty());
    }

    /// Verify that keys produced by our batch_compress generate valid Ed25519 signatures.
    /// This is the critical correctness test: it proves that our custom field arithmetic
    /// and point operations produce cryptographically valid keys.
    #[test]
    fn batch_compress_produces_valid_ed25519_signatures() {
        use crate::clamp_scalar;
        use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use sha2::Sha512;

        let delta_scalar = Scalar::from(8u64);
        let dalek_delta = DalekPoint::mul_base(&delta_scalar);
        let our_delta =
            ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
        let delta_niels = our_delta.as_projective_niels();

        // Simulate key generation as done in generate_batched()
        let mut expanded_key = [0u8; 64];
        // Use a deterministic "random" key for reproducibility
        for (i, byte) in expanded_key.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(113);
        }
        let mut scalar_bytes: [u8; 32] = expanded_key[..32].try_into().unwrap();
        clamp_scalar(&mut scalar_bytes);
        expanded_key[..32].copy_from_slice(&scalar_bytes);

        let base_scalar = Scalar::from_bytes_mod_order(scalar_bytes);
        let dalek_point = DalekPoint::mul_base(&base_scalar);
        let mut our_point =
            ExtendedPoint::from_compressed(dalek_point.compress().as_bytes()).unwrap();

        // Generate a batch of 64 points
        let mut points = Vec::with_capacity(64);
        for _ in 0..64 {
            points.push(our_point);
            our_point = our_point.add_niels(&delta_niels);
        }

        let compressed = batch_compress(&points);
        let nonce_bytes: [u8; 32] = expanded_key[32..64].try_into().unwrap();
        let message = b"test message for Ed25519 signature verification";

        // Verify each key in the batch can produce valid signatures
        for (i, pk_bytes) in compressed.iter().enumerate() {
            let match_scalar = base_scalar + delta_scalar * Scalar::from(i as u64);

            // Construct ExpandedSecretKey directly with the scalar (not via from_bytes,
            // which re-clamps and would corrupt the reduced-mod-l scalar value)
            let esk = ExpandedSecretKey {
                scalar: match_scalar,
                hash_prefix: nonce_bytes,
            };
            let vk_from_esk = VerifyingKey::from(&esk);
            let vk_from_batch =
                VerifyingKey::from_bytes(pk_bytes).expect("batch-compressed key is valid");

            // Verify that our batch-compressed public key matches dalek's derivation
            assert_eq!(
                vk_from_esk.as_bytes(),
                pk_bytes,
                "Public key mismatch at index {i}: batch_compress != dalek derivation"
            );

            // Sign the message using the expanded secret key
            let signature: Signature = raw_sign::<Sha512>(&esk, message, &vk_from_batch);

            // Verify the signature using the batch-compressed public key
            vk_from_batch
                .verify(message, &signature)
                .expect(&format!("Signature verification failed at index {i}"));

            // Also verify with strict verification
            vk_from_batch
                .verify_strict(message, &signature)
                .expect(&format!("Strict signature verification failed at index {i}"));
        }
    }

    /// Verify signatures after multiple rounds of re-randomization,
    /// simulating the actual generate_batched() lifecycle.
    #[test]
    fn signature_valid_after_rerandomization() {
        use crate::clamp_scalar;
        use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use sha2::Sha512;

        let delta_scalar = Scalar::from(8u64);
        let dalek_delta = DalekPoint::mul_base(&delta_scalar);
        let our_delta =
            ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
        let delta_niels = our_delta.as_projective_niels();

        let message = b"re-randomization signature test";

        // Simulate 3 re-randomization cycles with 64 keys each
        for round in 0..3u64 {
            let mut expanded_key = [0u8; 64];
            for (i, byte) in expanded_key.iter_mut().enumerate() {
                *byte = (i as u8)
                    .wrapping_mul(51)
                    .wrapping_add((round * 97) as u8);
            }
            let mut scalar_bytes: [u8; 32] = expanded_key[..32].try_into().unwrap();
            clamp_scalar(&mut scalar_bytes);
            expanded_key[..32].copy_from_slice(&scalar_bytes);

            let base_scalar = Scalar::from_bytes_mod_order(scalar_bytes);
            let dalek_point = DalekPoint::mul_base(&base_scalar);
            let mut our_point =
                ExtendedPoint::from_compressed(dalek_point.compress().as_bytes()).unwrap();

            let mut points = Vec::with_capacity(64);
            for _ in 0..64 {
                points.push(our_point);
                our_point = our_point.add_niels(&delta_niels);
            }

            let compressed = batch_compress(&points);
            let nonce_bytes: [u8; 32] = expanded_key[32..64].try_into().unwrap();

            // Spot-check first, middle, and last keys
            for &i in &[0, 31, 63] {
                let match_scalar = base_scalar + delta_scalar * Scalar::from(i as u64);
                // Construct ExpandedSecretKey directly (not via from_bytes to avoid re-clamping)
                let esk = ExpandedSecretKey {
                    scalar: match_scalar,
                    hash_prefix: nonce_bytes,
                };
                let vk = VerifyingKey::from_bytes(&compressed[i])
                    .expect("valid public key");

                let signature: Signature = raw_sign::<Sha512>(&esk, message, &vk);
                vk.verify(message, &signature).expect(&format!(
                    "Signature failed: round {round}, index {i}"
                ));
            }
        }
    }
}
