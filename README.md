# COSET

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://google.github.io/coset)
[![CI Status](https://img.shields.io/github/workflow/status/google/coset/CI?color=blue&style=for-the-badge)](https://github.com/google/coset/actions?query=workflow%3ACI)
[![codecov](https://img.shields.io/codecov/c/github/google/coset?style=for-the-badge)](https://codecov.io/gh/google/coset)

This crate holds a set of Rust types for working with CBOR Object Signing and Encryption (COSE) objects, as defined in
[RFC 8152](https://tools.ietf.org/html/rfc8152).  It builds on the core [CBOR](https://tools.ietf.org/html/rfc7049)
parsing functionality from the [`serde_cbor` crate](https://docs.rs/serde_cbor).

See the [signature example](examples/signature.rs) for an example of use.

**This repo is under construction** and so details of the API and the code may change without warning.

## Disclaimer

This is not an officially supported Google product.
