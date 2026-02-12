pub mod fe;
pub mod point;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use data_encoding::BASE32_NOPAD;
use point::{batch_compress, ExtendedPoint};
use rand::rngs::SysRng;
use rand::{Rng as _, SeedableRng as _, TryRng as _};
use rand_chacha::ChaCha20Rng;
use regex::bytes::{Regex, RegexBuilder};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub const PUBKEY_BASE32_LEN: usize = 52;
pub const ONION_BASE32_LEN: usize = 56;
pub const PREFIX_PUBKEY_ONLY_MAX: usize = 51;
pub const EXIT_CHECK_MASK: u32 = 0x3ff;
pub const RERANDOMIZE_INTERVAL: u64 = 1_000_000;
pub const BATCH_SIZE: usize = 64;

/// Tor v3 file headers (32 bytes each: 29 chars + 3 null bytes)
pub const SECRET_KEY_HEADER: &[u8; 32] = b"== ed25519v1-secret: type0 ==\0\0\0";
pub const PUBLIC_KEY_HEADER: &[u8; 32] = b"== ed25519v1-public: type0 ==\0\0\0";

pub enum AddressMatcher {
    /// Raw byte prefix comparison — avoids base32 encoding in hot path
    RawPrefix {
        full_bytes: Vec<u8>,
        last_mask: u8,
        last_value: u8,
        total_full_bytes: usize,
    },
    Prefix(Vec<u8>),
    Regex(Regex),
}

impl AddressMatcher {
    #[inline]
    pub fn is_match(&self, onion_base32: &[u8]) -> bool {
        match self {
            Self::RawPrefix { .. } => {
                unreachable!("RawPrefix should use is_match_raw")
            }
            Self::Prefix(prefix) => onion_base32.starts_with(prefix),
            Self::Regex(re) => re.is_match(onion_base32),
        }
    }

    /// Fast raw-byte match against compressed public key bytes
    #[inline]
    pub fn is_match_raw(&self, public_key: &[u8; 32]) -> bool {
        match self {
            Self::RawPrefix {
                full_bytes,
                last_mask,
                last_value,
                total_full_bytes,
            } => {
                let fb = *total_full_bytes;
                if fb > 0 && public_key[..fb] != full_bytes[..] {
                    return false;
                }
                if *last_mask != 0 {
                    return (public_key[fb] & *last_mask) == *last_value;
                }
                true
            }
            _ => unreachable!("is_match_raw called on non-RawPrefix"),
        }
    }

    #[inline]
    pub fn uses_raw_prefix(&self) -> bool {
        matches!(self, Self::RawPrefix { .. })
    }
}

#[inline]
pub fn is_base32_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'2'..=b'7')
}

#[inline]
pub fn is_regex_meta(b: u8) -> bool {
    matches!(
        b,
        b'.' | b'^'
            | b'$'
            | b'*'
            | b'+'
            | b'?'
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'|'
            | b'\\'
    )
}

/// Decode a base32 prefix string into raw bytes + a mask for the partial trailing byte.
///
/// Each base32 character encodes 5 bits. For N characters:
/// - N*5 / 8 full bytes
/// - N*5 % 8 remaining bits in the next byte (masked from the high side)
pub fn decode_raw_prefix(prefix_upper: &[u8]) -> Option<(Vec<u8>, u8, u8, usize)> {
    if prefix_upper.is_empty() {
        return None;
    }

    // Pad the prefix to a multiple of 8 chars for base32 decoding
    let pad_len = (8 - (prefix_upper.len() % 8)) % 8;
    let mut padded = Vec::with_capacity(prefix_upper.len() + pad_len);
    padded.extend_from_slice(prefix_upper);
    // Pad with 'A' (base32 zero) to fill out the block
    padded.resize(prefix_upper.len() + pad_len, b'A');

    let decoded = BASE32_NOPAD.decode(&padded).ok()?;

    let total_bits = prefix_upper.len() * 5;
    let total_full_bytes = total_bits / 8;
    let remaining_bits = total_bits % 8;

    let full_bytes = decoded[..total_full_bytes].to_vec();

    let (last_mask, last_value) = if remaining_bits > 0 {
        // Mask for the top `remaining_bits` bits of the next byte
        let mask = !((1u8 << (8 - remaining_bits)) - 1);
        let value = decoded[total_full_bytes] & mask;
        (mask, value)
    } else {
        (0u8, 0u8)
    };

    Some((full_bytes, last_mask, last_value, total_full_bytes))
}

pub fn parse_simple_prefix(pattern: &str) -> Option<Vec<u8>> {
    if let Some(prefix) = pattern.strip_prefix('^') {
        if !prefix.is_empty() && prefix.as_bytes().iter().copied().all(is_base32_char) {
            return Some(prefix.to_ascii_uppercase().into_bytes());
        }
    }
    None
}

pub fn parse_literal(pattern: &str) -> Option<Vec<u8>> {
    if pattern.is_empty()
        || pattern.as_bytes().iter().copied().any(is_regex_meta)
        || !pattern.as_bytes().iter().copied().all(is_base32_char)
    {
        return None;
    }

    Some(pattern.to_ascii_uppercase().into_bytes())
}

pub fn build_prefix_matcher(prefix: Vec<u8>) -> AddressMatcher {
    if prefix.len() <= PREFIX_PUBKEY_ONLY_MAX {
        if let Some((full_bytes, last_mask, last_value, total_full_bytes)) =
            decode_raw_prefix(&prefix)
        {
            return AddressMatcher::RawPrefix {
                full_bytes,
                last_mask,
                last_value,
                total_full_bytes,
            };
        }
    }
    AddressMatcher::Prefix(prefix)
}

pub fn build_matcher(pattern: &str) -> AddressMatcher {
    if let Some(prefix) = parse_simple_prefix(pattern) {
        return build_prefix_matcher(prefix);
    }

    // Plain base32 strings are treated as prefix matches
    if let Some(prefix) = parse_literal(pattern) {
        return build_prefix_matcher(prefix);
    }

    let re = RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .expect("Invalid regex pattern");
    AddressMatcher::Regex(re)
}

/// Clamp a 32-byte scalar for Ed25519 key generation
#[inline]
pub fn clamp_scalar(bytes: &mut [u8; 32]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

#[inline]
pub fn fill_onion_bytes(
    public_key: &[u8; 32],
    onion_address_bytes: &mut [u8; 35],
    sha3: &mut Sha3_256,
) {
    onion_address_bytes[..32].copy_from_slice(public_key);
    sha3.update(b".onion checksum");
    sha3.update(public_key);
    sha3.update([0x03]);
    let checksum = sha3.finalize_reset();

    onion_address_bytes[32] = checksum[0];
    onion_address_bytes[33] = checksum[1];
    onion_address_bytes[34] = 0x03;
}

pub fn save(onion_address: &str, expanded_key: &[u8; 64], public_key: &[u8; 32]) {
    let dir_path = Path::new(onion_address);
    fs::create_dir_all(dir_path).unwrap();

    // Secret key file: 32-byte header + 64-byte expanded key = 96 bytes
    let secret_key_file = dir_path.join("hs_ed25519_secret_key");
    let mut secret_key_contents = Vec::with_capacity(96);
    secret_key_contents.extend_from_slice(SECRET_KEY_HEADER);
    secret_key_contents.extend_from_slice(expanded_key);
    fs::write(secret_key_file, secret_key_contents).unwrap();

    // Public key file: 32-byte header + 32-byte public key = 64 bytes
    let public_key_file = dir_path.join("hs_ed25519_public_key");
    let mut public_key_contents = Vec::with_capacity(64);
    public_key_contents.extend_from_slice(PUBLIC_KEY_HEADER);
    public_key_contents.extend_from_slice(public_key);
    fs::write(public_key_file, public_key_contents).unwrap();

    let hostname_file = dir_path.join("hostname");
    fs::write(hostname_file, format!("{}.onion\n", onion_address)).unwrap();
}

/// Initialize RNG, scalar, and expanded key for a worker thread
fn init_worker() -> (ChaCha20Rng, Scalar, [u8; 64]) {
    let mut sys_rng = SysRng;
    let mut seed = [0u8; 32];
    sys_rng
        .try_fill_bytes(&mut seed)
        .expect("failed to seed thread RNG");
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut expanded_key = [0u8; 64];
    rng.fill_bytes(&mut expanded_key);

    let mut scalar_bytes: [u8; 32] = expanded_key[..32].try_into().unwrap();
    clamp_scalar(&mut scalar_bytes);
    expanded_key[..32].copy_from_slice(&scalar_bytes);

    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    (rng, scalar, expanded_key)
}

/// Re-randomize the scalar and point for a worker thread
fn rerandomize(rng: &mut ChaCha20Rng, expanded_key: &mut [u8; 64]) -> Scalar {
    rng.fill_bytes(expanded_key);
    let mut scalar_bytes: [u8; 32] = expanded_key[..32].try_into().unwrap();
    clamp_scalar(&mut scalar_bytes);
    expanded_key[..32].copy_from_slice(&scalar_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

/// Handle a match: build onion address, save files, update counters.
/// Returns true if the search should stop.
fn handle_match(
    public_key: &[u8; 32],
    scalar: &Scalar,
    expanded_key: &mut [u8; 64],
    found: &AtomicUsize,
    target: usize,
    should_exit: &AtomicBool,
) -> bool {
    let mut onion_address_bytes = [0u8; 35];
    let mut onion_base32 = [0u8; ONION_BASE32_LEN];
    let mut sha3 = Sha3_256::new();

    fill_onion_bytes(public_key, &mut onion_address_bytes, &mut sha3);
    BASE32_NOPAD.encode_mut(&onion_address_bytes, &mut onion_base32);
    for c in &mut onion_base32[..ONION_BASE32_LEN] {
        c.make_ascii_lowercase();
    }
    let onion_address =
        std::str::from_utf8(&onion_base32[..ONION_BASE32_LEN]).expect("base32 output is ASCII");

    let scalar_out = scalar.to_bytes();
    expanded_key[..32].copy_from_slice(&scalar_out);

    save(onion_address, expanded_key, public_key);

    let prev_count = found.fetch_add(1, Ordering::Relaxed);
    if target != 0 && prev_count + 1 >= target {
        should_exit.store(true, Ordering::Relaxed);
        return true;
    }
    false
}

/// Batched generate for RawPrefix matchers: uses batch Montgomery inversion
/// to compress 64 points with only 1 field inversion instead of 64.
fn generate_batched(
    matcher: &AddressMatcher,
    found: &AtomicUsize,
    target: usize,
    total_generated: &AtomicUsize,
    should_exit: &AtomicBool,
) {
    let (mut rng, mut scalar, mut expanded_key) = init_worker();
    let nonce_bytes: [u8; 32] = expanded_key[32..64].try_into().unwrap();

    let delta_scalar = Scalar::from(8u64);
    let dalek_delta = EdwardsPoint::mul_base(&delta_scalar);

    // Convert initial point to our representation
    let dalek_point = EdwardsPoint::mul_base(&scalar);
    let mut our_point =
        ExtendedPoint::from_compressed(dalek_point.compress().as_bytes()).unwrap();
    let our_delta =
        ExtendedPoint::from_compressed(dalek_delta.compress().as_bytes()).unwrap();
    let delta_niels = our_delta.as_projective_niels();

    let mut local_generated = 0usize;
    let mut iterations_since_rerandomize = 0u64;
    let mut points_buf = Vec::with_capacity(BATCH_SIZE);

    loop {
        if should_exit.load(Ordering::Relaxed) {
            break;
        }

        // Phase 1: Generate batch of points via Niels addition
        points_buf.clear();
        let batch_base_scalar = scalar;
        for _ in 0..BATCH_SIZE {
            points_buf.push(our_point);
            our_point = our_point.add_niels(&delta_niels);
            scalar += delta_scalar;
        }

        // Phase 2: Batch compress (1 inversion for BATCH_SIZE points)
        let compressed = batch_compress(&points_buf);
        local_generated += BATCH_SIZE;

        // Phase 3: Check matches
        for (i, pk_bytes) in compressed.iter().enumerate() {
            if matcher.is_match_raw(pk_bytes) {
                let match_scalar =
                    batch_base_scalar + delta_scalar * Scalar::from(i as u64);
                // Restore nonce in expanded_key
                expanded_key[32..64].copy_from_slice(&nonce_bytes);
                if handle_match(
                    pk_bytes,
                    &match_scalar,
                    &mut expanded_key,
                    found,
                    target,
                    should_exit,
                ) {
                    total_generated.fetch_add(local_generated, Ordering::Relaxed);
                    return;
                }
            }
        }

        // Re-randomize check
        iterations_since_rerandomize += BATCH_SIZE as u64;
        if iterations_since_rerandomize >= RERANDOMIZE_INTERVAL {
            iterations_since_rerandomize = 0;
            scalar = rerandomize(&mut rng, &mut expanded_key);
            let dalek_point = EdwardsPoint::mul_base(&scalar);
            our_point =
                ExtendedPoint::from_compressed(dalek_point.compress().as_bytes()).unwrap();
        }

        // Counter update
        if local_generated >= 10000 {
            total_generated.fetch_add(local_generated, Ordering::Relaxed);
            local_generated = 0;
        }
    }

    total_generated.fetch_add(local_generated, Ordering::Relaxed);
}

/// Non-batched generate for Regex/Prefix matchers (needs full base32 encoding)
fn generate_individual(
    matcher: &AddressMatcher,
    found: &AtomicUsize,
    target: usize,
    total_generated: &AtomicUsize,
    should_exit: &AtomicBool,
) {
    let (mut rng, mut scalar, mut expanded_key) = init_worker();

    let mut point = EdwardsPoint::mul_base(&scalar);
    let delta_scalar = Scalar::from(8u64);
    let delta_point = EdwardsPoint::mul_base(&delta_scalar);

    let mut onion_address_bytes = [0u8; 35];
    let mut pubkey_base32 = [0u8; PUBKEY_BASE32_LEN];
    let mut onion_base32 = [0u8; ONION_BASE32_LEN];
    let mut sha3 = Sha3_256::new();
    let mut tick = 0u32;
    let mut local_generated = 0usize;
    let mut iterations_since_rerandomize = 0u64;

    loop {
        tick = tick.wrapping_add(1);
        if (tick & EXIT_CHECK_MASK) == 0 && should_exit.load(Ordering::Relaxed) {
            break;
        }

        let compressed = point.compress();
        let public_key: &[u8; 32] = compressed.as_bytes();
        let mut full_address_ready = false;
        local_generated += 1;

        let is_match = match matcher {
            AddressMatcher::Prefix(prefix) if prefix.len() <= PREFIX_PUBKEY_ONLY_MAX => {
                BASE32_NOPAD.encode_mut(public_key, &mut pubkey_base32);
                pubkey_base32[..prefix.len()] == prefix[..]
            }
            _ => {
                fill_onion_bytes(public_key, &mut onion_address_bytes, &mut sha3);
                BASE32_NOPAD.encode_mut(&onion_address_bytes, &mut onion_base32);
                full_address_ready = true;
                matcher.is_match(&onion_base32)
            }
        };

        if is_match {
            if !full_address_ready {
                fill_onion_bytes(public_key, &mut onion_address_bytes, &mut sha3);
                BASE32_NOPAD.encode_mut(&onion_address_bytes, &mut onion_base32);
            }
            for c in &mut onion_base32[..ONION_BASE32_LEN] {
                c.make_ascii_lowercase();
            }
            let onion_address = std::str::from_utf8(&onion_base32[..ONION_BASE32_LEN])
                .expect("base32 output is ASCII");

            let scalar_out = scalar.to_bytes();
            expanded_key[..32].copy_from_slice(&scalar_out);

            save(onion_address, &expanded_key, public_key);

            let prev_count = found.fetch_add(1, Ordering::Relaxed);
            if target != 0 && prev_count + 1 >= target {
                should_exit.store(true, Ordering::Relaxed);
                break;
            }
        }

        point += delta_point;
        scalar += delta_scalar;

        iterations_since_rerandomize += 1;
        if iterations_since_rerandomize >= RERANDOMIZE_INTERVAL {
            iterations_since_rerandomize = 0;
            scalar = rerandomize(&mut rng, &mut expanded_key);
            point = EdwardsPoint::mul_base(&scalar);
        }

        if local_generated.is_multiple_of(10000) {
            total_generated.fetch_add(local_generated, Ordering::Relaxed);
            local_generated = 0;
        }
    }

    total_generated.fetch_add(local_generated, Ordering::Relaxed);
}

/// Main entry point: dispatches to batched or individual generator
pub fn generate(
    matcher: &AddressMatcher,
    found: &AtomicUsize,
    target: usize,
    total_generated: &AtomicUsize,
    should_exit: &AtomicBool,
) {
    if matcher.uses_raw_prefix() {
        generate_batched(matcher, found, target, total_generated, should_exit);
    } else {
        generate_individual(matcher, found, target, total_generated, should_exit);
    }
}
