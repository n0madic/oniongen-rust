use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use data_encoding::BASE32_NOPAD;
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

    c.bench_function("point_addition", |b| {
        b.iter(|| {
            point += delta;
            black_box(&point);
        })
    });
}

fn bench_point_compress(c: &mut Criterion) {
    let mut rng = make_rng();
    let (scalar, _) = make_clamped_scalar(&mut rng);
    let point = EdwardsPoint::mul_base(&scalar);

    c.bench_function("point_compress", |b| {
        b.iter(|| {
            let compressed = point.compress();
            black_box(compressed.as_bytes());
        })
    });
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

    c.bench_function("keygen_full (point add + compress + raw match)", |b| {
        b.iter(|| {
            point += delta_point;
            scalar += delta_scalar;
            let compressed = point.compress();
            let pk = compressed.as_bytes();
            let matched = matcher.is_match_raw(pk);
            black_box(matched);
        })
    });
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
    bench_point_compress,
    bench_sha3_checksum,
    bench_base32_encode,
    bench_rng,
    bench_keygen_full,
    bench_raw_prefix_match,
);
criterion_main!(benches);
