# COSET

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://google.github.io/coset)
[![CI Status](https://img.shields.io/github/workflow/status/google/coset/CI?color=blue&style=for-the-badge)](https://github.com/google/coset/actions?query=workflow%3ACI)
[![codecov](https://img.shields.io/codecov/c/github/google/coset?style=for-the-badge)](https://codecov.io/gh/google/coset)

This crate holds a set of Rust types for working with CBOR Object Signing and Encryption (COSE) objects, as defined in
[RFC 8152](https://tools.ietf.org/html/rfc8152).  It builds on the core [CBOR](https://tools.ietf.org/html/rfc7049)
parsing functionality from the [`sk-cbor` crate](https://docs.rs/sk-cbor).

See [crate docs](https://google.github.io/coset/rust/coset/index.html), or the [signature
example](examples/signature.rs) for documentation on how to use the code.

**This repo is under construction** and so details of the API and the code may change without warning.

## `no_std` Support

This crate supports `no_std`, but uses the `alloc` crate.

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
