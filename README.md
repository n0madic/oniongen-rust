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

- **Batch Montgomery inversion**: For prefix patterns, 64 points are compressed using a single field inversion + 189 multiplications instead of 64 inversions, yielding ~30x faster compression and ~16x overall speedup
- **Custom Ed25519 field arithmetic**: Self-contained `Fe` (field element) and `ExtendedPoint` modules implement GF(2^255-19) arithmetic and extended twisted Edwards point operations without constant-time overhead
- **Precomputed Niels addition**: The increment point is precomputed in Niels form `(Y+X, Y-X, Z, 2dXY)` for 8-multiply additions (~54ns each)
- **Raw byte prefix matching**: For prefix patterns, the base32 prefix is decoded to raw bytes once, and matching is done directly against public key bytes (~2.4ns)
- **Periodic re-randomization**: Keys are re-randomized every 1M iterations to avoid long sequential scalar runs

### Benchmark Results

| Operation | Time |
|-----------|------|
| **Batch keygen (64 pts: add + compress + match)** | **~8.0 μs (~125 ns/pt)** |
| Individual keygen (dalek: add + compress + match) | ~2.08 μs/pt |
| Batch compress 64 points | ~4.1 μs (~64 ns/pt) |
| Individual compress 64 points (dalek) | ~124 μs (~1.9 μs/pt) |
| Point addition (ours / dalek) | ~54 ns / ~60 ns |
| Raw byte prefix match | ~2.4 ns |

**Compression speedup: ~30x. Overall per-iteration speedup: ~16.5x.**

Run benchmarks with:

```bash
cargo bench
```

## Testing

Run unit tests:

```bash
cargo test
```

### Integration Tests

Integration tests require the `tor` binary installed and are marked `#[ignore]`.

**Quick validation** (~4s) — verifies generated keys are accepted by `tor --verify-config` and loads correctly on startup:

```bash
cargo test --test tor_integration -- --ignored --nocapture test_generated_keys_accepted_by_tor
```

**Full end-to-end** (~1-3 min, requires network) — boots a real Tor daemon, publishes the generated .onion service, and sends data through the Tor SOCKS5 proxy to a local echo server:

```bash
cargo test --test tor_integration -- --ignored --nocapture test_onion_service_echo_through_tor
```
