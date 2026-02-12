# oniongen-rust

## Description

This is a Rust implementation of the oniongen tool, which generates vanity .onion addresses for the Tor network. The tool accepts a regex pattern and generates addresses until it finds matches.

## Usage

To use the tool, simply run the following command:

```bash
oniongen <pattern>
```

Where `<pattern>` is a regex applied to the generated onion hostname (without `.onion`). For example, to generate an address that starts with `facebook`, you would run:

```bash
oniongen '^facebook'
```

The tool will then generate addresses until it finds one that matches `^facebook`, and will output the address once it finds it.

## Help

```bash
Generates Onion addresses matching a given pattern

Usage: oniongen [OPTIONS] <pattern>

Arguments:
  <pattern>  The regex pattern to match

Options:
  -n, --number <NUM>   Number of addresses to generate [default: 1]
  -t, --threads <NUM>  Number of threads to use [default: 10]
  -h, --help           Print help
  -V, --version        Print version
```

