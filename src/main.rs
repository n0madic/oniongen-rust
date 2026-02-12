use clap::{value_parser, Arg, Command};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use memchr::memmem;
use rand::rngs::SysRng;
use rand::{Rng as _, SeedableRng as _, TryRng as _};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest, Sha512};
use sha3::Sha3_256;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const PUBKEY_BASE32_LEN: usize = 52;
const ONION_BASE32_LEN: usize = 56;
const PREFIX_PUBKEY_ONLY_MAX: usize = 51;
const EXIT_CHECK_MASK: u32 = 0x3ff;

enum AddressMatcher {
    Prefix(Vec<u8>),
    Literal(Vec<u8>),
    Regex(Regex),
}

impl AddressMatcher {
    #[inline]
    fn is_match(&self, onion_base32: &[u8]) -> bool {
        match self {
            Self::Prefix(prefix) => onion_base32.starts_with(prefix),
            Self::Literal(literal) => memmem::find(onion_base32, literal).is_some(),
            Self::Regex(re) => re.is_match(onion_base32),
        }
    }
}

#[inline]
fn is_base32_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'2'..=b'7')
}

#[inline]
fn is_regex_meta(b: u8) -> bool {
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

fn parse_simple_prefix(pattern: &str) -> Option<Vec<u8>> {
    if let Some(prefix) = pattern.strip_prefix('^') {
        if !prefix.is_empty() && prefix.as_bytes().iter().copied().all(is_base32_char) {
            return Some(prefix.to_ascii_uppercase().into_bytes());
        }
    }
    None
}

fn parse_literal(pattern: &str) -> Option<Vec<u8>> {
    if pattern.is_empty()
        || pattern.as_bytes().iter().copied().any(is_regex_meta)
        || !pattern.as_bytes().iter().copied().all(is_base32_char)
    {
        return None;
    }

    Some(pattern.to_ascii_uppercase().into_bytes())
}

fn build_matcher(pattern: &str) -> AddressMatcher {
    if let Some(prefix) = parse_simple_prefix(pattern) {
        AddressMatcher::Prefix(prefix)
    } else if let Some(literal) = parse_literal(pattern) {
        AddressMatcher::Literal(literal)
    } else {
        let re = RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .expect("Invalid regex pattern");
        AddressMatcher::Regex(re)
    }
}

fn generate(
    matcher: &AddressMatcher,
    found: &AtomicUsize,
    target: usize,
    total_generated: &AtomicUsize,
    should_exit: &AtomicBool,
) {
    let mut local_generated = 0usize;
    let mut seed = [0u8; 32];
    let mut sys_rng = SysRng;
    sys_rng
        .try_fill_bytes(&mut seed)
        .expect("failed to seed thread RNG");
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut secret_key = [0u8; 32];
    let mut onion_address_bytes = [0u8; 35];
    let mut pubkey_base32 = [0u8; PUBKEY_BASE32_LEN];
    let mut onion_base32 = [0u8; ONION_BASE32_LEN];
    let mut sha3 = Sha3_256::new();
    let mut tick = 0u32;

    loop {
        tick = tick.wrapping_add(1);
        if (tick & EXIT_CHECK_MASK) == 0 && should_exit.load(Ordering::Relaxed) {
            break;
        }

        rng.fill_bytes(&mut secret_key);
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.as_bytes();
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
            save(onion_address, &signing_key, &verifying_key);

            let prev_count = found.fetch_add(1, Ordering::Relaxed);
            if target != 0 && prev_count + 1 >= target {
                should_exit.store(true, Ordering::Relaxed);
                break;
            }
        }

        if local_generated % 10000 == 0 {
            total_generated.fetch_add(local_generated, Ordering::Relaxed);
            local_generated = 0;
        }
    }

    total_generated.fetch_add(local_generated, Ordering::Relaxed);
}

#[inline]
fn expand_secret_key(secret_key: &[u8]) -> [u8; 64] {
    let mut hash = [0u8; 64];
    let mut hasher = Sha512::new();
    hasher.update(secret_key);
    hash.copy_from_slice(&hasher.finalize());
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    hash
}

#[inline]
fn fill_onion_bytes(
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

fn save(onion_address: &str, signing_key: &SigningKey, verifying_key: &VerifyingKey) {
    let dir_path = Path::new(onion_address);
    fs::create_dir_all(dir_path).unwrap();

    let secret_key_file = dir_path.join("hs_ed25519_secret_key");
    let mut secret_key_contents = Vec::with_capacity(96);
    secret_key_contents.extend_from_slice(b"== ed25519v1-secret: type0 ==");
    secret_key_contents.extend_from_slice(&expand_secret_key(signing_key.as_bytes()));
    fs::write(secret_key_file, secret_key_contents).unwrap();

    let public_key_file = dir_path.join("hs_ed25519_public_key");
    let mut public_key_contents = Vec::with_capacity(64);
    public_key_contents.extend_from_slice(b"== ed25519v1-public: type0 ==");
    public_key_contents.extend_from_slice(verifying_key.as_bytes());
    fs::write(public_key_file, public_key_contents).unwrap();

    let hostname_file = dir_path.join("hostname");
    fs::write(hostname_file, format!("{}.onion\n", onion_address)).unwrap();
}

fn main() {
    let default_threads: &'static str = Box::leak(num_cpus::get().to_string().into_boxed_str());
    let matches = Command::new("OnionGen")
        .version("1.1")
        .author("n0madic")
        .about("Generates Onion addresses matching a given pattern")
        .arg(
            Arg::new("pattern")
                .help("The regex pattern to match")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("number")
                .short('n')
                .long("number")
                .value_name("NUM")
                .help("Number of addresses to generate")
                .value_parser(value_parser!(usize))
                .default_value("1"),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_name("NUM")
                .help("Number of threads to use")
                .value_parser(value_parser!(usize))
                .default_value(&default_threads),
        )
        .get_matches();

    let pattern = matches.get_one::<String>("pattern").unwrap();
    let num_addresses = *matches.get_one::<usize>("number").unwrap();
    let num_threads = *matches.get_one::<usize>("threads").unwrap();

    let matcher = Arc::new(build_matcher(pattern));

    let found = Arc::new(AtomicUsize::new(0));
    let total_generated = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();
    let should_exit = Arc::new(AtomicBool::new(false));

    let progress_total_generated = Arc::clone(&total_generated);
    let progress_found = Arc::clone(&found);
    let progress_should_exit = Arc::clone(&should_exit);
    let progress_handle = thread::spawn(move || {
        let report_interval = Duration::from_secs(5);
        let mut last_report = Instant::now();
        while !progress_should_exit.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
            if last_report.elapsed() >= report_interval {
                let total = progress_total_generated.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = total as f64 / elapsed;
                println!(
                    "Progress: {} found, {} generated, {:.2} addresses/sec",
                    progress_found.load(Ordering::Relaxed),
                    total,
                    rate
                );
                last_report = Instant::now();
            }
        }
    });

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .expect("failed to build rayon thread pool");

    pool.install(|| {
        (0..num_threads).into_par_iter().for_each(|_| {
            generate(
                &matcher,
                &found,
                num_addresses,
                &total_generated,
                &should_exit,
            );
        });
    });

    should_exit.store(true, Ordering::Relaxed);
    progress_handle.join().unwrap();

    let total = total_generated.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let rate = total as f64 / elapsed_secs;

    println!(
        "Finished: {} found, {} generated, {:.2} addresses/sec",
        found.load(Ordering::Relaxed),
        total,
        rate
    );
    println!("Time taken: {:.2} seconds", elapsed_secs);
}
