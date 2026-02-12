use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::SigningKey;
use rand::rngs::SysRng;
use rand::{Rng as _, SeedableRng as _, TryRng as _};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest as _, Sha512};
use sha3::Sha3_256;
use std::hint::black_box;

fn make_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    let mut sys_rng = SysRng;
    sys_rng.try_fill_bytes(&mut seed).unwrap();
    ChaCha20Rng::from_seed(seed)
}

fn bench_scalar_mul(c: &mut Criterion) {
    let mut rng = make_rng();
    c.bench_function("scalar_mul (SigningKey + verifying_key)", |b| {
        b.iter(|| {
            let mut secret_key = [0u8; 32];
            rng.fill_bytes(&mut secret_key);
            let signing_key = SigningKey::from_bytes(&secret_key);
            let vk = signing_key.verifying_key();
            black_box(vk.as_bytes());
        })
    });
}

fn bench_point_addition(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(bytes);
    let mut point = EdwardsPoint::mul_base(&scalar);
    let delta = EdwardsPoint::mul_base(&Scalar::from(8u64));

    c.bench_function("point_addition (add precomputed delta)", |b| {
        b.iter(|| {
            point += delta;
            black_box(&point);
        })
    });
}

fn bench_point_compress(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(bytes);
    let point = EdwardsPoint::mul_base(&scalar);

    c.bench_function("point_compress", |b| {
        b.iter(|| {
            let compressed = point.compress();
            black_box(compressed.as_bytes());
        })
    });
}

fn bench_sha512(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    c.bench_function("sha512 (key expansion)", |b| {
        b.iter(|| {
            let mut hasher = Sha512::new();
            hasher.update(black_box(&key));
            let result = hasher.finalize();
            black_box(&result);
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
            onion_bytes[..32].copy_from_slice(&public_key);
            sha3.update(b".onion checksum");
            sha3.update(public_key);
            sha3.update([0x03]);
            let checksum = sha3.finalize_reset();
            onion_bytes[32] = checksum[0];
            onion_bytes[33] = checksum[1];
            onion_bytes[34] = 0x03;
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

fn bench_keygen_current(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut secret_key = [0u8; 32];
    let mut pubkey_base32 = [0u8; 52];
    let prefix = b"FACE";

    c.bench_function("keygen_current (full iteration, prefix match)", |b| {
        b.iter(|| {
            rng.fill_bytes(&mut secret_key);
            let signing_key = SigningKey::from_bytes(&secret_key);
            let verifying_key = signing_key.verifying_key();
            let public_key = verifying_key.as_bytes();
            BASE32_NOPAD.encode_mut(public_key, &mut pubkey_base32);
            let matched = pubkey_base32[..prefix.len()] == prefix[..];
            black_box(matched);
        })
    });
}

fn bench_keygen_optimized(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    let mut scalar = Scalar::from_bytes_mod_order(bytes);
    let mut point = EdwardsPoint::mul_base(&scalar);
    let delta_scalar = Scalar::from(8u64);
    let delta_point = EdwardsPoint::mul_base(&delta_scalar);
    // Precomputed raw prefix for "FACE" (base32) = 0x28, 0x02, mask 0xF0 for partial byte
    let raw_prefix: [u8; 2] = [0x28, 0x02];
    let last_mask: u8 = 0xF0;
    let last_val: u8 = 0x40;

    c.bench_function("keygen_optimized (point add + compress + raw match)", |b| {
        b.iter(|| {
            point += delta_point;
            scalar += delta_scalar;
            let compressed = point.compress();
            let pk = compressed.as_bytes();
            let matched =
                pk[0] == raw_prefix[0] && pk[1] == raw_prefix[1] && (pk[2] & last_mask) == last_val;
            black_box(matched);
        })
    });
}

fn bench_raw_prefix_match(c: &mut Criterion) {
    let mut rng = make_rng();
    let mut public_key = [0u8; 32];
    rng.fill_bytes(&mut public_key);
    let raw_prefix: [u8; 2] = [0x28, 0x02];
    let last_mask: u8 = 0xF0;
    let last_val: u8 = 0x40;

    c.bench_function("raw_prefix_match (byte compare)", |b| {
        b.iter(|| {
            let pk = black_box(&public_key);
            let matched =
                pk[0] == raw_prefix[0] && pk[1] == raw_prefix[1] && (pk[2] & last_mask) == last_val;
            black_box(matched);
        })
    });
}

criterion_group!(
    benches,
    bench_scalar_mul,
    bench_point_addition,
    bench_point_compress,
    bench_sha512,
    bench_sha3_checksum,
    bench_base32_encode,
    bench_rng,
    bench_keygen_current,
    bench_keygen_optimized,
    bench_raw_prefix_match,
);
criterion_main!(benches);
