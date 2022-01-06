# Change Log

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
