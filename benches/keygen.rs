use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use data_encoding::BASE32_NOPAD;
use oniongen::point::{batch_compress, ExtendedPoint};
use oniongen::{build_matcher, clamp_scalar, fill_onion_bytes};
use rand::rngs::SysRng;
use rand::{Rng as _, SeedableRng as _, TryRng as _};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest as _, Sha3_256};
use std::hint::black_box;

fn make_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    let mut sys_rng = SysRng;
    sys_rng.try_fill_bytes(&mut seed).unwrap();
    ChaCha20Rng::from_seed(seed)
}

fn make_clamped_scalar(rng: &mut ChaCha20Rng) -> (Scalar, [u8; 32]) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    clamp_scalar(&mut bytes);
    (Scalar::from_bytes_mod_order(bytes), bytes)
}

fn bench_point_addition(c: &mut Criterion) {
    let mut rng = make_rng();
    let (scalar, _) = make_clamped_scalar(&mut rng);
    let mut point = EdwardsPoint::mul_base(&scalar);
    let delta = EdwardsPoint::mul_base(&Scalar::from(8u64));

    c.bench_function("point_addition (dalek)", |b| {
        b.iter(|| {
            point += delta;
            black_box(&point);
        })
    });
}

fn bench_our_point_addition(c: &mut Criterion) {
    let mut rng = make_rng();
    let (scalar, _) = make_clamped_scalar(&mut rng);
    let dalek_pt = EdwardsPoint::mul_base(&scalar);
    let dalek_delta = EdwardsPoint::mul_base(&Scalar::from(8u64));

    let mut our_pt = ExtendedPoint::from_compressed(dalek_pt.compress().as_bytes()).unwrap();
    let our_delta = ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
    let delta_niels = our_delta.as_projective_niels();

    c.bench_function("point_addition (ours)", |b| {
        b.iter(|| {
            our_pt = our_pt.add_niels(&delta_niels);
            black_box(&our_pt);
        })
    });
}

fn bench_point_compress(c: &mut Criterion) {
    let mut rng = make_rng();
    let (scalar, _) = make_clamped_scalar(&mut rng);
    let point = EdwardsPoint::mul_base(&scalar);

    c.bench_function("point_compress (dalek)", |b| {
        b.iter(|| {
            let compressed = point.compress();
            black_box(compressed.as_bytes());
        })
    });
}

fn bench_our_point_compress(c: &mut Criterion) {
    let mut rng = make_rng();
    let (scalar, _) = make_clamped_scalar(&mut rng);
    let dalek_pt = EdwardsPoint::mul_base(&scalar);
    let our_pt = ExtendedPoint::from_compressed(dalek_pt.compress().as_bytes()).unwrap();

    c.bench_function("point_compress (ours, single)", |b| {
        b.iter(|| {
            let compressed = our_pt.compress();
            black_box(&compressed);
        })
    });
}

fn bench_batch_compress_64(c: &mut Criterion) {
    let mut rng = make_rng();
    let (scalar, _) = make_clamped_scalar(&mut rng);
    let dalek_pt = EdwardsPoint::mul_base(&scalar);
    let dalek_delta = EdwardsPoint::mul_base(&Scalar::from(8u64));

    let mut our_pt = ExtendedPoint::from_compressed(dalek_pt.compress().as_bytes()).unwrap();
    let our_delta = ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
    let delta_niels = our_delta.as_projective_niels();

    let mut points = Vec::with_capacity(64);
    for _ in 0..64 {
        points.push(our_pt);
        our_pt = our_pt.add_niels(&delta_niels);
    }

    c.bench_function("batch_compress_64", |b| {
        b.iter(|| {
            let result = batch_compress(black_box(&points));
            black_box(&result);
        })
    });
}

fn bench_individual_compress_64(c: &mut Criterion) {
    let mut rng = make_rng();
    let (scalar, _) = make_clamped_scalar(&mut rng);
    let mut point = EdwardsPoint::mul_base(&scalar);
    let delta = EdwardsPoint::mul_base(&Scalar::from(8u64));

    let mut points = Vec::with_capacity(64);
    for _ in 0..64 {
        points.push(point);
        point += delta;
    }

    c.bench_function("individual_compress_64 (dalek)", |b| {
        b.iter(|| {
            for pt in &points {
                let compressed = pt.compress();
                black_box(compressed.as_bytes());
            }
        })
    });
}

fn bench_keygen_batch_full(c: &mut Criterion) {
    let mut rng = make_rng();
    let (scalar, _) = make_clamped_scalar(&mut rng);
    let dalek_pt = EdwardsPoint::mul_base(&scalar);
    let dalek_delta = EdwardsPoint::mul_base(&Scalar::from(8u64));

    let mut our_pt = ExtendedPoint::from_compressed(dalek_pt.compress().as_bytes()).unwrap();
    let our_delta = ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
    let delta_niels = our_delta.as_projective_niels();

    let matcher = build_matcher("face");

    c.bench_function(
        "keygen_batch_full (64 pts: add + batch compress + raw match)",
        |b| {
            b.iter(|| {
                let mut points = Vec::with_capacity(64);
                for _ in 0..64 {
                    points.push(our_pt);
                    our_pt = our_pt.add_niels(&delta_niels);
                }
                let compressed = batch_compress(&points);
                for pk in &compressed {
                    black_box(matcher.is_match_raw(pk));
                }
            })
        },
    );
}

fn bench_sha3_checksum(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut public_key = [0u8; 32];
    rng.fill_bytes(&mut public_key);
    let mut onion_bytes = [0u8; 35];
    let mut sha3 = Sha3_256::new();

    c.bench_function("sha3_checksum (fill_onion_bytes)", |b| {
        b.iter(|| {
            fill_onion_bytes(&public_key, &mut onion_bytes, &mut sha3);
            black_box(&onion_bytes);
        })
    });
}

fn bench_base32_encode(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut public_key = [0u8; 32];
    rng.fill_bytes(&mut public_key);
    let mut pubkey_base32 = [0u8; 52];

    c.bench_function("base32_encode (pubkey 32 bytes)", |b| {
        b.iter(|| {
            BASE32_NOPAD.encode_mut(black_box(&public_key), &mut pubkey_base32);
            black_box(&pubkey_base32);
        })
    });
}

fn bench_rng(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut buf = [0u8; 32];

    c.bench_function("chacha20_rng (32 bytes)", |b| {
        b.iter(|| {
            rng.fill_bytes(&mut buf);
            black_box(&buf);
        })
    });
}

fn bench_keygen_full(c: &mut Criterion) {
    let mut rng = make_rng();
    let (mut scalar, _) = make_clamped_scalar(&mut rng);
    let mut point = EdwardsPoint::mul_base(&scalar);
    let delta_scalar = Scalar::from(8u64);
    let delta_point = EdwardsPoint::mul_base(&delta_scalar);
    let matcher = build_matcher("face");

    c.bench_function(
        "keygen_full (dalek: point add + compress + raw match)",
        |b| {
            b.iter(|| {
                point += delta_point;
                scalar += delta_scalar;
                let compressed = point.compress();
                let pk = compressed.as_bytes();
                let matched = matcher.is_match_raw(pk);
                black_box(matched);
            })
        },
    );
}

fn bench_raw_prefix_match(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut public_key = [0u8; 32];
    rng.fill_bytes(&mut public_key);
    let matcher = build_matcher("face");

    c.bench_function("raw_prefix_match (byte compare)", |b| {
        b.iter(|| {
            let pk = black_box(&public_key);
            let matched = matcher.is_match_raw(pk);
            black_box(matched);
        })
    });
}

criterion_group!(
    benches,
    bench_point_addition,
    bench_our_point_addition,
    bench_point_compress,
    bench_our_point_compress,
    bench_batch_compress_64,
    bench_individual_compress_64,
    bench_keygen_batch_full,
    bench_sha3_checksum,
    bench_base32_encode,
    bench_rng,
    bench_keygen_full,
    bench_raw_prefix_match,
);
criterion_main!(benches);
