# oniongen-rust

## Description

This is a Rust implementation of the oniongen tool, which generates vanity .onion addresses for the Tor network.

## Usage

```bash
oniongen <pattern>
```

### Pattern types

| Pattern | Type | Example | Matches |
|---------|------|---------|---------|
| `dark` | Prefix | `dark` | Addresses starting with `dark` |
| `^dark` | Prefix | `^dark` | Addresses starting with `dark` |
| `dark[0-9]` | Regex | `dark[0-9]` | Addresses matching regex anywhere |
| `^dark[0-9]` | Regex | `^dark[0-9]` | Addresses matching regex from start |

Plain base32 strings (characters `a-z`, `2-7`) are always treated as **prefix** matches. Patterns containing regex metacharacters (`.`, `*`, `+`, `[`, `]`, etc.) are treated as regular expressions.

### Examples

Generate an address starting with `dark`:

```bash
oniongen dark
```

Generate 5 addresses starting with `test` using 4 threads:

```bash
oniongen -n 5 -t 4 test
```

Generate an address matching a regex pattern:

```bash
oniongen 'dark[2-7]{2}'
```

### Options

```
Usage: oniongen [OPTIONS] <pattern>

Arguments:
  <pattern>  The regex pattern to match

Options:
  -n, --number <NUM>   Number of addresses to generate [default: 1]
  -t, --threads <NUM>  Number of threads to use [default: number of CPUs]
  -h, --help           Print help
  -V, --version        Print version
```

## Building

```bash
cargo build --release
```

The release binary will be at `target/release/oniongen`.

## Output Format

For each matching address, the tool creates a directory named after the onion address containing:

- `hs_ed25519_secret_key` — 96 bytes (32-byte header + 64-byte expanded secret key)
- `hs_ed25519_public_key` — 64 bytes (32-byte header + 32-byte public key)
- `hostname` — The `.onion` address

These files are compatible with Tor's hidden service directory format.

## Performance

The generator uses several optimizations to maximize throughput:

- **Incremental point addition**: Instead of computing a full Ed25519 scalar multiplication per key (~8μs), each iteration performs a point addition (~62ns) plus compression (~2μs), yielding ~3.8x speedup per iteration
- **Raw byte prefix matching**: For prefix patterns, the base32 prefix is decoded to raw bytes once, and matching is done directly against public key bytes (~0.4ns vs ~12ns for base32 encode + compare)
- **Native CPU instructions**: Build configuration enables `target-cpu=native` for AVX2/SIMD acceleration of field arithmetic
- **Periodic re-randomization**: Keys are re-randomized every 1M iterations to avoid long sequential scalar runs

### Benchmark Results

| Operation | Time |
|-----------|------|
| Full old iteration (scalar mul + base32 + match) | ~7.95 μs |
| Full new iteration (point add + compress + raw match) | ~2.11 μs |
| Point addition | ~62 ns |
| Point compression | ~2.05 μs |
| Raw byte prefix match | ~0.4 ns |

Run benchmarks with:

```bash
cargo bench
```
