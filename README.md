# COSET

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/coset)
[![CI Status](https://img.shields.io/github/actions/workflow/status/google/coset/ci.yml?branch=main&color=blue&style=for-the-badge)](https://github.com/google/coset/actions?query=workflow%3ACI)
[![codecov](https://img.shields.io/codecov/c/github/google/coset?style=for-the-badge)](https://codecov.io/gh/google/coset)

This crate holds a set of Rust types for working with CBOR Object Signing and Encryption (COSE) objects, as defined in
[RFC 8152](https://tools.ietf.org/html/rfc8152).  It builds on the core [CBOR](https://tools.ietf.org/html/rfc7049)
parsing functionality from the [`ciborium` crate](https://docs.rs/ciborium).

See [crate docs](https://docs.rs/coset), or the [signature
example](examples/signature.rs) for documentation on how to use the code.

**This repo is under construction** and so details of the API and the code may change without warning.

## Features

The `std` feature of the crate enables an implementation of `std::error::Error` for `CoseError`.

## `no_std` Support

This crate supports `no_std` (when the `std` feature is not set, which is the default), but uses the `alloc` crate.

## Minimum Supported Rust Version

MSRV is 1.58.

## Integer Ranges

CBOR supports integers in the range:

```text
[-18_446_744_073_709_551_616, -1] ∪ [0, 18_446_744_073_709_551_615]
```

which is [-2<sup>64</sup>, -1] ∪ [0, 2<sup>64</sup> - 1].

This does not map onto a single Rust integer type, so different CBOR crates take different approaches.

- The [`serde_cbor`](https://docs.rs/serde_cbor) crate uses a single `i128` integer type for all integer values, which
  means that all CBOR integer values can be expressed, but there are also `i128` values that cannot be encoded in CBOR.
  This also means that data size is larger.
- The [`ciborium`](https://docs.rs/ciborium) also uses a single `i128` integer type internally, but wraps it in its own
  [`Integer`](https://docs.rs/ciborium/latest/ciborium/value/struct.Integer.html) type and only implements `TryFrom`
  (not `From`) for `i128` / `u128` conversions so that unrepresentable numbers can be rejected.
- The [`sk-cbor`](https://docs.rs/sk-cbor) crate uses distinct types:
    - positive numbers as u64, covering [0, 2<sup>64</sup> - 1]
    - negative numbers as i64, covering [-2<sup>63</sup>, -1] (which means that some theoretically-valid large negative
      values are not represented).

This crate uses a single type to encompass both positive and negative values, but uses `i64` for that type to keep data
sizes smaller.  This means that:

- positive numbers in `i64` cover [0, 2<sup>63</sup> - 1]
- negative numbers in `i64` cover [-2<sup>63</sup>, -1]

and so there are large values &ndash; both positive and negative &ndash; which are not supported by this crate.

## Working on the Code

Local coding conventions are enforced by the [continuous integration jobs](.github/workflows) and include:

- Build cleanly and pass all tests.
- Free of [Clippy](https://github.com/rust-lang/rust-clippy) warnings.
- Formatted with `rustfmt` using the local [rustfmt.toml](.rustfmt.toml) settings.
- Compliance with local conventions:
    - All `TODO` markers should be of form `TODO(#99)` and refer to an open GitHub issue.
    - Calls to functions that can panic (`panic!`, `unwrap`, `expect`) should have a comment on the same line in the
      form `// safe: reason` (or `/* safe: reason */`) to document the reason why panicking is acceptable.

## Disclaimer

This is not an officially supported Google product.
