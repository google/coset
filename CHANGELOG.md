# Change Log

## 0.4.0 - TBD

- Breaking change:  alter type of `crit` field in `Header` to support private-use labels (in accordance with
  [9052 §3.1](https://datatracker.ietf.org/doc/html/rfc9052#name-common-cose-header-paramete)).

## 0.3.8 - 2024-07-24

- Make `CoseSign[1]::tbs_[detached_]data` methods `pub`.

## 0.3.7 - 2024-04-05

- Bump MSRV to 1.58.
- Update dependencies.
- Fix bounds bug for label sorting.

## 0.3.6 - 2024-01-15

- Helpers for ordering of fields in a `COSE_Key`:
    - Add `Label::cmp_canonical()` for RFC 7049 canonical ordering.
    - Add `CborOrdering` enum to specify ordering.
    - Add `CoseKey::canonicalize()` method to order fields.

## 0.3.5 - 2023-09-29

- Add helper methods to create and verify detached signatures:
    - Add `CoseSignBuilder` methods `add_detached_signature` and `try_add_detached_signature`.
    - Add `CoseSign` method `verify_detached_signature`.
    - Add `CoseSign1Builder` methods `create_detached_signature` and `try_create_detached_signature`.
    - Add `CoseSign1` method `verify_detached_signature`.
- Implement CBOR conversion traits for `ciborium::value::Value`.
- Update `ciborium` dependency.

## 0.3.4 - 2023-01-25

- Add non-default `std` feature that turns on `impl Error for CoseError`.
- Add `cwt::ClaimsSetBuilder::private_claim` method.
- Update documentation for existing encryption methods to make it clear that they only support AEAD encryption.

## 0.3.3 - 2022-09-30

- Add `CoseKeyBuilder` methods `kty`, `key_type` and `new_okp_key`.

## 0.3.2 - 2022-04-02

- Add basic [CWT](https://datatracker.ietf.org/doc/html/rfc8392) support in `cwt` module, via the `ClaimsSet` type.

## 0.3.1 - 2022-02-23

- Implement `Display` for `CoseError`.
- Fix `Cargo.toml` to indicate reliance on `alloc` feature of `ciborium-io`.
- Make `AsCborValue` trait public.

## 0.3.0 - 2022-01-19

- Change to use `ciborium` as CBOR library. Breaking change with many knock-on effects:
    - Re-export `ciborium` as `coset::cbor` (rather than `sk-cbor`).
    - Use `ciborium`'s `Value` type rather than `sk-cbor`'s version.
    - Change `CoseError` to no longer wrap `sk-cbor` errors.
    - Drop `derive` of `Eq` for data types (`ciborium` supports float values, which are inherently non-`Eq`)
    - Add `#[must_use]` attributes to builder methods.
    - Update MSRV to 1.56.0, as `ciborium` is `edition=2021`
- Use new `ProtectedHeader` type for protected headers (breaking change).  This variant of `Header` preserves any
  originally-parsed data, so that calculations (signatures, decryption, etc.) over the data can use the bit-for-bit wire
  data instead of a reconstituted (and potentially different) version.
- Add more specific error cases to `CoseError` (breaking change):
    - Use new `OutOfRangeIntegerValue` error when an integer value is too large for the representation used in this
      crate.
    - Use new `DuplicateMapKey` error when a CBOR map contains duplicate keys (and is thus invalid).
    - Extend `DecodeFailed` error to include the underlying `ciborium::de::Error` value.
    - Use new `ExtraneousData` error when data remains after reading a CBOR value.
    - Rename `UnexpectedType` error to `UnexpectedItem` to reflect broader usage than type.
- Add a crate-specific `Result` type whose `E` field defaults to `CoseError`.

## 0.2.0 - 2021-12-09

- Change to use `sk-cbor` as CBOR library, due to deprecation of `serde-cbor`. Breaking change with many knock-on
  effects:
    - Re-export `sk-cbor` as `coset::cbor`.
    - Use `sk-cbor`'s `Value` type rather than `serde-cbor`'s version.
    - Change encoding methods to consume `self`.
    - Change encoding methods to be fallible.
    - Move to be `no_std` (but still using `alloc`)
    - Add `CoseError` error type and use throughout.
    - Use `Vec` of pairs not `BTreeMap`s for CBOR map values.
    - Use `i64` not `i128` for integer values throughout.
    - Drop use of `serde`'s `Serialize` and `Deserialize` traits; instead&hellip;
    - Add `CborSerializable` extension trait for conversion to/from bytes.
    - Drop `from_tagged_reader` / `to_tagged_writer` methods from `TaggedCborSerializable` trait.
    - Derive `Debug` for builders.
    - Convert `CoseKeySet` to a newtype, and add standard traits.

## 0.1.2 - 2021-08-24

- Add fallible variants of builder methods that invoke closures (#20):
    - `CoseRecipientBuilder::try_create_ciphertext()`
    - `CoseEncryptBuilder::try_create_ciphertext()`
    - `CoseEncrypt0Builder::try_create_ciphertext()`
    - `CoseMacBuilder::try_create_tag()`
    - `CoseMac0Builder::try_create_tag()`
    - `CoseSignBuilder::try_add_created_signature()`
    - `CoseSign1Builder::try_create_signature()`
- Upgrade dependencies.

## 0.1.1 - 2021-06-24

- Make `KeyType` and `KeyOperation` public.
- Upgrade dependencies.

## 0.1.0 - 2021-05-18

- Initial version, using `serde-cbor` as CBOR library.
