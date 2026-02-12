/// Field element in GF(2^255-19), radix-2^51 representation.
///
/// Modeled after curve25519-dalek's FieldElement51 but without constant-time
/// requirements (we generate public addresses, not secrets).
#[derive(Copy, Clone, Debug)]
pub struct Fe(pub [u64; 5]);

const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;

impl Fe {
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Edwards curve parameter d = -121665/121666
    pub const D: Fe = Fe([
        929955233495203,
        466365720129213,
        1662059464998953,
        2033849074728123,
        1442794654840575,
    ]);

    /// 2*d
    pub const D2: Fe = Fe([
        1859910466990425,
        932731440258426,
        1072319116312658,
        1815898335770999,
        633789495995903,
    ]);

    /// sqrt(-1) mod p
    pub const SQRT_M1: Fe = Fe([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]);

    #[inline(always)]
    fn reduce(mut limbs: [u64; 5]) -> Fe {
        let c0 = limbs[0] >> 51;
        let c1 = limbs[1] >> 51;
        let c2 = limbs[2] >> 51;
        let c3 = limbs[3] >> 51;
        let c4 = limbs[4] >> 51;

        limbs[0] &= LOW_51_BIT_MASK;
        limbs[1] &= LOW_51_BIT_MASK;
        limbs[2] &= LOW_51_BIT_MASK;
        limbs[3] &= LOW_51_BIT_MASK;
        limbs[4] &= LOW_51_BIT_MASK;

        limbs[0] += c4 * 19;
        limbs[1] += c0;
        limbs[2] += c1;
        limbs[3] += c2;
        limbs[4] += c3;

        Fe(limbs)
    }

    #[inline]
    pub fn add(&self, rhs: &Fe) -> Fe {
        Fe([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    #[inline]
    pub fn sub(&self, rhs: &Fe) -> Fe {
        // Add 16*p to avoid underflow
        Fe::reduce([
            (self.0[0] + 36028797018963664u64) - rhs.0[0],
            (self.0[1] + 36028797018963952u64) - rhs.0[1],
            (self.0[2] + 36028797018963952u64) - rhs.0[2],
            (self.0[3] + 36028797018963952u64) - rhs.0[3],
            (self.0[4] + 36028797018963952u64) - rhs.0[4],
        ])
    }

    #[inline]
    pub fn neg(&self) -> Fe {
        Fe::reduce([
            36028797018963664u64 - self.0[0],
            36028797018963952u64 - self.0[1],
            36028797018963952u64 - self.0[2],
            36028797018963952u64 - self.0[3],
            36028797018963952u64 - self.0[4],
        ])
    }

    #[inline]
    #[rustfmt::skip]
    pub fn mul(&self, rhs: &Fe) -> Fe {
        #[inline(always)]
        fn m(x: u64, y: u64) -> u128 { (x as u128) * (y as u128) }

        let a = &self.0;
        let b = &rhs.0;

        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        let     c0: u128 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        let mut c1: u128 = m(a[1], b[0]) + m(a[0],  b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        let mut c2: u128 = m(a[2], b[0]) + m(a[1],  b[1]) + m(a[0],  b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
        let mut c3: u128 = m(a[3], b[0]) + m(a[2],  b[1]) + m(a[1],  b[2]) + m(a[0],  b[3]) + m(a[4], b4_19);
        let mut c4: u128 = m(a[4], b[0]) + m(a[3],  b[1]) + m(a[2],  b[2]) + m(a[1],  b[3]) + m(a[0],  b[4]);

        let mut out = [0u64; 5];

        c1 += ((c0 >> 51) as u64) as u128;
        out[0] = (c0 as u64) & LOW_51_BIT_MASK;

        c2 += ((c1 >> 51) as u64) as u128;
        out[1] = (c1 as u64) & LOW_51_BIT_MASK;

        c3 += ((c2 >> 51) as u64) as u128;
        out[2] = (c2 as u64) & LOW_51_BIT_MASK;

        c4 += ((c3 >> 51) as u64) as u128;
        out[3] = (c3 as u64) & LOW_51_BIT_MASK;

        let carry: u64 = (c4 >> 51) as u64;
        out[4] = (c4 as u64) & LOW_51_BIT_MASK;

        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= LOW_51_BIT_MASK;

        Fe(out)
    }

    #[rustfmt::skip]
    pub fn pow2k(&self, mut k: u32) -> Fe {
        debug_assert!(k > 0);

        #[inline(always)]
        fn m(x: u64, y: u64) -> u128 { (x as u128) * (y as u128) }

        let mut a: [u64; 5] = self.0;

        loop {
            let a3_19 = 19 * a[3];
            let a4_19 = 19 * a[4];

            let     c0: u128 = m(a[0],  a[0]) + 2*( m(a[1], a4_19) + m(a[2], a3_19) );
            let mut c1: u128 = m(a[3], a3_19) + 2*( m(a[0],  a[1]) + m(a[2], a4_19) );
            let mut c2: u128 = m(a[1],  a[1]) + 2*( m(a[0],  a[2]) + m(a[4], a3_19) );
            let mut c3: u128 = m(a[4], a4_19) + 2*( m(a[0],  a[3]) + m(a[1],  a[2]) );
            let mut c4: u128 = m(a[2],  a[2]) + 2*( m(a[0],  a[4]) + m(a[1],  a[3]) );

            c1 += ((c0 >> 51) as u64) as u128;
            a[0] = (c0 as u64) & LOW_51_BIT_MASK;

            c2 += ((c1 >> 51) as u64) as u128;
            a[1] = (c1 as u64) & LOW_51_BIT_MASK;

            c3 += ((c2 >> 51) as u64) as u128;
            a[2] = (c2 as u64) & LOW_51_BIT_MASK;

            c4 += ((c3 >> 51) as u64) as u128;
            a[3] = (c3 as u64) & LOW_51_BIT_MASK;

            let carry: u64 = (c4 >> 51) as u64;
            a[4] = (c4 as u64) & LOW_51_BIT_MASK;

            a[0] += carry * 19;
            a[1] += a[0] >> 51;
            a[0] &= LOW_51_BIT_MASK;

            k -= 1;
            if k == 0 { break; }
        }

        Fe(a)
    }

    #[inline]
    pub fn square(&self) -> Fe {
        self.pow2k(1)
    }

    #[inline]
    pub fn square2(&self) -> Fe {
        let mut sq = self.pow2k(1);
        for i in 0..5 {
            sq.0[i] *= 2;
        }
        sq
    }

    /// Compute (self^(2^250-1), self^11) — helper for invert/pow_p58
    #[rustfmt::skip]
    fn pow22501(&self) -> (Fe, Fe) {
        let t0  = self.square();
        let t1  = t0.square().square();
        let t2  = self.mul(&t1);
        let t3  = t0.mul(&t2);
        let t4  = t3.square();
        let t5  = t2.mul(&t4);
        let t6  = t5.pow2k(5);
        let t7  = t6.mul(&t5);
        let t8  = t7.pow2k(10);
        let t9  = t8.mul(&t7);
        let t10 = t9.pow2k(20);
        let t11 = t10.mul(&t9);
        let t12 = t11.pow2k(10);
        let t13 = t12.mul(&t7);
        let t14 = t13.pow2k(50);
        let t15 = t14.mul(&t13);
        let t16 = t15.pow2k(100);
        let t17 = t16.mul(&t15);
        let t18 = t17.pow2k(50);
        let t19 = t18.mul(&t13);

        (t19, t3)
    }

    /// Compute self^(p-2) = self^(-1) mod p
    #[rustfmt::skip]
    pub fn invert(&self) -> Fe {
        let (t19, t3) = self.pow22501();
        let t20 = t19.pow2k(5);
        t20.mul(&t3)
    }

    /// Compute self^((p-5)/8) = self^(2^252 - 3)
    #[rustfmt::skip]
    fn pow_p58(&self) -> Fe {
        let (t19, _) = self.pow22501();
        let t20 = t19.pow2k(2);
        self.mul(&t20)
    }

    /// Montgomery's batch inversion: compute inverses of all elements
    /// using 1 inversion + 3(N-1) multiplications.
    pub fn batch_invert(inputs: &mut [Fe]) {
        let n = inputs.len();
        if n == 0 {
            return;
        }

        let mut scratch = vec![Fe::ONE; n];
        let mut acc = Fe::ONE;

        // Forward pass: accumulate products
        for (input, scratch) in inputs.iter().zip(scratch.iter_mut()) {
            *scratch = acc;
            acc = acc.mul(input);
        }

        // Invert the accumulated product
        acc = acc.invert();

        // Backward pass: compute individual inverses
        for (input, scratch) in inputs.iter_mut().rev().zip(scratch.into_iter().rev()) {
            let tmp = acc.mul(input);
            *input = acc.mul(&scratch);
            acc = tmp;
        }
    }

    /// Load from 32 bytes (little-endian), masking high bit
    #[rustfmt::skip]
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load8 = |input: &[u8]| -> u64 {
               (input[0] as u64)
            | ((input[1] as u64) <<  8)
            | ((input[2] as u64) << 16)
            | ((input[3] as u64) << 24)
            | ((input[4] as u64) << 32)
            | ((input[5] as u64) << 40)
            | ((input[6] as u64) << 48)
            | ((input[7] as u64) << 56)
        };

        Fe([
             load8(&bytes[ 0..])        & LOW_51_BIT_MASK,
            (load8(&bytes[ 6..]) >>  3) & LOW_51_BIT_MASK,
            (load8(&bytes[12..]) >>  6) & LOW_51_BIT_MASK,
            (load8(&bytes[19..]) >>  1) & LOW_51_BIT_MASK,
            (load8(&bytes[24..]) >> 12) & LOW_51_BIT_MASK,
        ])
    }

    /// Serialize to 32 bytes (canonical little-endian encoding)
    #[rustfmt::skip]
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut limbs = Fe::reduce(self.0).0;

        // Compute q = (h + 19) >> 255, which is 0 or 1
        let mut q = (limbs[0] + 19) >> 51;
        q = (limbs[1] + q) >> 51;
        q = (limbs[2] + q) >> 51;
        q = (limbs[3] + q) >> 51;
        q = (limbs[4] + q) >> 51;

        // r = h - q*p = h + 19*q - 2^255*q
        limbs[0] += 19 * q;

        limbs[1] += limbs[0] >> 51;  limbs[0] &= LOW_51_BIT_MASK;
        limbs[2] += limbs[1] >> 51;  limbs[1] &= LOW_51_BIT_MASK;
        limbs[3] += limbs[2] >> 51;  limbs[2] &= LOW_51_BIT_MASK;
        limbs[4] += limbs[3] >> 51;  limbs[3] &= LOW_51_BIT_MASK;
        limbs[4] &= LOW_51_BIT_MASK;

        let mut s = [0u8; 32];
        s[ 0] =   limbs[0]                           as u8;
        s[ 1] =  (limbs[0] >>  8)                    as u8;
        s[ 2] =  (limbs[0] >> 16)                    as u8;
        s[ 3] =  (limbs[0] >> 24)                    as u8;
        s[ 4] =  (limbs[0] >> 32)                    as u8;
        s[ 5] =  (limbs[0] >> 40)                    as u8;
        s[ 6] = ((limbs[0] >> 48) | (limbs[1] << 3)) as u8;
        s[ 7] =  (limbs[1] >>  5)                    as u8;
        s[ 8] =  (limbs[1] >> 13)                    as u8;
        s[ 9] =  (limbs[1] >> 21)                    as u8;
        s[10] =  (limbs[1] >> 29)                    as u8;
        s[11] =  (limbs[1] >> 37)                    as u8;
        s[12] = ((limbs[1] >> 45) | (limbs[2] << 6)) as u8;
        s[13] =  (limbs[2] >>  2)                    as u8;
        s[14] =  (limbs[2] >> 10)                    as u8;
        s[15] =  (limbs[2] >> 18)                    as u8;
        s[16] =  (limbs[2] >> 26)                    as u8;
        s[17] =  (limbs[2] >> 34)                    as u8;
        s[18] =  (limbs[2] >> 42)                    as u8;
        s[19] = ((limbs[2] >> 50) | (limbs[3] << 1)) as u8;
        s[20] =  (limbs[3] >>  7)                    as u8;
        s[21] =  (limbs[3] >> 15)                    as u8;
        s[22] =  (limbs[3] >> 23)                    as u8;
        s[23] =  (limbs[3] >> 31)                    as u8;
        s[24] =  (limbs[3] >> 39)                    as u8;
        s[25] = ((limbs[3] >> 47) | (limbs[4] << 4)) as u8;
        s[26] =  (limbs[4] >>  4)                    as u8;
        s[27] =  (limbs[4] >> 12)                    as u8;
        s[28] =  (limbs[4] >> 20)                    as u8;
        s[29] =  (limbs[4] >> 28)                    as u8;
        s[30] =  (limbs[4] >> 36)                    as u8;
        s[31] =  (limbs[4] >> 44)                    as u8;

        s
    }

    /// Returns true if this field element is "negative" (low bit of canonical form is set)
    #[inline]
    pub fn is_negative(&self) -> bool {
        (self.as_bytes()[0] & 1) != 0
    }

    /// Compute sqrt(u/v) or sqrt(i*u/v), returning (was_square, result).
    ///
    /// If u/v is square, returns (true, +sqrt(u/v)).
    /// If u/v is non-square, returns (false, +sqrt(i*u/v)).
    pub fn sqrt_ratio_i(u: &Fe, v: &Fe) -> (bool, Fe) {
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut r = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
        let check = v.mul(&r.square());

        let u_neg = u.neg();
        let correct_sign = fe_eq(&check, u);
        let flipped_sign = fe_eq(&check, &u_neg);
        let flipped_sign_i = fe_eq(&check, &u_neg.mul(&Fe::SQRT_M1));

        let r_prime = Fe::SQRT_M1.mul(&r);
        if flipped_sign || flipped_sign_i {
            r = r_prime;
        }

        // Choose the nonnegative square root
        if r.is_negative() {
            r = r.neg();
        }

        let was_square = correct_sign || flipped_sign;
        (was_square, r)
    }
}

/// Non-constant-time equality (sufficient for address generation)
fn fe_eq(a: &Fe, b: &Fe) -> bool {
    a.as_bytes() == b.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from curve25519-dalek
    static A_BYTES: [u8; 32] = [
        0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68, 0x84, 0x92, 0xbd, 0x59, 0x08, 0x07,
        0xa7, 0x03, 0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4, 0xa4, 0x51, 0x47, 0x36,
        0xf3, 0xc3, 0xa9, 0x17,
    ];

    static ASQ_BYTES: [u8; 32] = [
        0x75, 0x97, 0x24, 0x9e, 0xe6, 0x06, 0xfe, 0xab, 0x24, 0x04, 0x56, 0x68, 0x07, 0x91,
        0x2d, 0x5d, 0x0b, 0x0f, 0x3f, 0x1c, 0xb2, 0x6e, 0xf2, 0xe2, 0x63, 0x9c, 0x12, 0xba,
        0x73, 0x0b, 0xe3, 0x62,
    ];

    static AINV_BYTES: [u8; 32] = [
        0x96, 0x1b, 0xcd, 0x8d, 0x4d, 0x5e, 0xa2, 0x3a, 0xe9, 0x36, 0x37, 0x93, 0xdb, 0x7b,
        0x4d, 0x70, 0xb8, 0x0d, 0xc0, 0x55, 0xd0, 0x4c, 0x1d, 0x7b, 0x90, 0x71, 0xd8, 0xe9,
        0xb6, 0x18, 0xe6, 0x30,
    ];

    #[test]
    fn mul_correctness() {
        let a = Fe::from_bytes(&A_BYTES);
        let asq = Fe::from_bytes(&ASQ_BYTES);
        assert_eq!(a.mul(&a).as_bytes(), asq.as_bytes());
    }

    #[test]
    fn square_correctness() {
        let a = Fe::from_bytes(&A_BYTES);
        let asq = Fe::from_bytes(&ASQ_BYTES);
        assert_eq!(a.square().as_bytes(), asq.as_bytes());
    }

    #[test]
    fn invert_correctness() {
        let a = Fe::from_bytes(&A_BYTES);
        let ainv = Fe::from_bytes(&AINV_BYTES);
        assert_eq!(a.invert().as_bytes(), ainv.as_bytes());
        assert_eq!(a.mul(&a.invert()).as_bytes(), Fe::ONE.as_bytes());
    }

    #[test]
    fn batch_invert_matches_individual() {
        let a = Fe::from_bytes(&A_BYTES);
        let asq = Fe::from_bytes(&ASQ_BYTES);
        let ainv = Fe::from_bytes(&AINV_BYTES);
        let a2 = a.add(&a);

        let list = vec![a, asq, ainv, a2];
        let mut batch = list.clone();
        Fe::batch_invert(&mut batch);

        for (orig, batched) in list.iter().zip(batch.iter()) {
            assert_eq!(orig.invert().as_bytes(), batched.as_bytes());
        }
    }

    #[test]
    fn batch_invert_empty() {
        Fe::batch_invert(&mut []);
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = Fe::from_bytes(&A_BYTES);
        let asq = Fe::from_bytes(&ASQ_BYTES);
        let sum = a.add(&asq);
        let diff = sum.sub(&asq);
        assert_eq!(diff.as_bytes(), a.as_bytes());
    }

    #[test]
    fn neg_double_neg() {
        let a = Fe::from_bytes(&A_BYTES);
        assert_eq!(a.neg().neg().as_bytes(), a.as_bytes());
    }

    #[test]
    fn from_bytes_highbit_ignored() {
        let mut b = A_BYTES;
        b[31] |= 0x80;
        let with_high = Fe::from_bytes(&b);
        let without_high = Fe::from_bytes(&A_BYTES);
        // from_bytes masks the high bit via the 51-bit mask on the last limb
        assert_eq!(with_high.as_bytes(), without_high.as_bytes());
    }

    #[test]
    fn sqrt_ratio_i_square() {
        let four = Fe::ONE.add(&Fe::ONE).add(&Fe::ONE).add(&Fe::ONE);
        let (was_square, sqrt) = Fe::sqrt_ratio_i(&four, &Fe::ONE);
        assert!(was_square);
        assert_eq!(sqrt.square().as_bytes(), four.as_bytes());
    }

    #[test]
    fn sqrt_ratio_i_nonsquare() {
        let two = Fe::ONE.add(&Fe::ONE);
        let (was_square, sqrt) = Fe::sqrt_ratio_i(&two, &Fe::ONE);
        assert!(!was_square);
        // sqrt^2 should equal i*2
        assert_eq!(
            sqrt.square().as_bytes(),
            two.mul(&Fe::SQRT_M1).as_bytes()
        );
    }
}
