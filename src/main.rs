use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha512, Digest};
use sha3::Sha3_256;
use base32;
use regex::bytes::Regex;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, Duration};
use rayon::prelude::*;
use std::thread;
use clap::{Arg, Command, value_parser};

fn generate(
    re: &Regex,
    found: &AtomicUsize,
    target: usize,
    total_generated: &AtomicUsize,
    should_exit: &AtomicBool,
) {
    let mut local_generated = 0;
    let mut secret_key = [0u8; 32];
    let mut onion_address_bytes = [0u8; 35];
    let mut checksum_bytes = [0u8; 67];

    while !should_exit.load(Ordering::Relaxed) {
        OsRng.fill_bytes(&mut secret_key);
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();

        encode_public_key(
            &verifying_key,
            &mut onion_address_bytes,
            &mut checksum_bytes,
        );

        local_generated += 1;

        if re.is_match(&onion_address_bytes) {
            let onion_address = base32::encode(
                base32::Alphabet::RFC4648 { padding: false },
                &onion_address_bytes,
            ).to_lowercase();
            save(&onion_address, &signing_key, &verifying_key);

            let prev_count = found.fetch_add(1, Ordering::SeqCst);
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
fn encode_public_key(
    public_key: &VerifyingKey,
    onion_address_bytes: &mut [u8],
    checksum_bytes: &mut [u8],
) {
    checksum_bytes[..15].copy_from_slice(b".onion checksum");
    checksum_bytes[15..47].copy_from_slice(public_key.as_bytes());
    checksum_bytes[47] = 0x03;

    let checksum = Sha3_256::digest(&checksum_bytes[..48]);

    onion_address_bytes[..32].copy_from_slice(public_key.as_bytes());
    onion_address_bytes[32..34].copy_from_slice(&checksum[..2]);
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
        .version("1.0")
        .author("Your Name")
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

    let re = Arc::new(Regex::new(pattern).expect("Invalid regex pattern"));

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

    (0..num_threads).into_par_iter().for_each(|_| {
        generate(&re, &found, num_addresses, &total_generated, &should_exit);
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
