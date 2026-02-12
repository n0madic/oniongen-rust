use clap::{value_parser, Arg, Command};
use oniongen::generate;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let default_threads: &'static str = Box::leak(
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .to_string()
            .into_boxed_str(),
    );
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
                .default_value(default_threads),
        )
        .get_matches();

    let pattern = matches.get_one::<String>("pattern").unwrap();
    let num_addresses = *matches.get_one::<usize>("number").unwrap();
    let num_threads = *matches.get_one::<usize>("threads").unwrap();

    let matcher = Arc::new(oniongen::build_matcher(pattern));

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
        while !progress_should_exit.load(Ordering::Acquire) {
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

    should_exit.store(true, Ordering::Release);
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
