// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

use super::*;
use crate::{
    cbor::value::Value, iana, util::expect_err, CborSerializable, ContentType, CoseKeyBuilder,
    CoseRecipientBuilder, CoseSignatureBuilder, HeaderBuilder, TaggedCborSerializable,
};
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

#[test]
fn test_cose_recipient_decode() {
    let tests: Vec<(CoseRecipient, &'static str)> = vec![
        (
            CoseRecipientBuilder::new().build(),
            concat!(
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
            ),
        ),
        (
            CoseRecipientBuilder::new().ciphertext(vec![]).build(),
            concat!(
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
            ),
        ),
        (
            CoseRecipientBuilder::new()
                .ciphertext(vec![])
                .add_recipient(CoseRecipientBuilder::new().build())
                .build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "81", // 1-tuple
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
            ),
        ),
    ];

    for (i, (recipient, recipient_data)) in tests.iter().enumerate() {
        let got = recipient.clone().to_vec().unwrap();
        assert_eq!(*recipient_data, hex::encode(&got), "case {i}");

        let mut got = CoseRecipient::from_slice(&got).unwrap();
        got.protected.original_data = None;
        for recip in &mut got.recipients {
            recip.protected.original_data = None;
        }
        assert_eq!(*recipient, got);
    }
}

#[test]
fn test_cose_recipient_decode_fail() {
    let tests = [
        (
            concat!(
                "a2",   // 2-map (should be tuple)
                "40",   // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",   // 0-map
                "4161", // 1-bstr
                "40",   // 0-bstr
            ),
            "expected array",
        ),
        (
            concat!(
                "82", // 2-tuple (should be 4-tuple)
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
            ),
            "expected array with 3 or 4 items",
        ),
        (
            concat!(
                "84", // 4-tuple
                "80", // 0-tuple (should be bstr)
                "a0", // 0-map
                "40", // 0-bstr
                "80", // 0-arr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40", // 0-bstr (should be map)
                "40", // 0-bstr
                "80", // 0-arr
            ),
            "expected map",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "60", // 0-tstr (should be bstr)
                "80", // 0-arr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
            ),
            "expected array",
        ),
    ];
    for (recipient_data, err_msg) in tests.iter() {
        let data = hex::decode(recipient_data).unwrap();
        let result = CoseRecipient::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_encrypt_decode() {
    let tests: Vec<(CoseEncrypt, &'static str)> = vec![
        (
            CoseEncryptBuilder::new().build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
                "80", // 0-tuple
            ),
        ),
        (
            CoseEncryptBuilder::new().ciphertext(vec![]).build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "80", // 0-tuple
            ),
        ),
    ];

    for (i, (encrypt, encrypt_data)) in tests.iter().enumerate() {
        let got = encrypt.clone().to_vec().unwrap();
        assert_eq!(*encrypt_data, hex::encode(&got), "case {i}");

        let mut got = CoseEncrypt::from_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*encrypt, got);
    }
}

#[test]
fn test_cose_encrypt_decode_fail() {
    let tests = [
        (
            concat!(
                "a2",   // 2-map (should be tuple)
                "40",   // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",   // 0-map
                "4161", // 1-bstr
                "40",   // 0-bstr
            ),
            "expected array",
        ),
        (
            concat!(
                "83", // 3-tuple (should be 4-tuple)
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "84", // 4-tuple
                "80", // 0-tuple (should be bstr)
                "a0", // 0-map
                "40", // 0-bstr
                "80", // 0-arr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40", // 0-bstr (should be map)
                "40", // 0-bstr
                "80", // 0-arr
            ),
            "expected map",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "60", // 0-tstr (should be bstr)
                "80", // 0-arr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
            ),
            "expected array",
        ),
    ];
    for (encrypt_data, err_msg) in tests.iter() {
        let data = hex::decode(encrypt_data).unwrap();
        let result = CoseEncrypt::from_slice(&data);
        expect_err(result, err_msg);
    }
}
#[test]
fn test_rfc8152_cose_encrypt_decode() {
    // COSE_Encrypt structures from RFC 8152 section C.3.
    let tests: Vec<(CoseEncrypt, &'static str)> = vec![
        (
            CoseEncryptBuilder::new()
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::A128GCM)
                        .build(),
                )
                .unprotected(
                    HeaderBuilder::new()
                        .iv(hex::decode("c9cf4df2fe6c632bf7886413").unwrap())
                        .build(),
                )
                .ciphertext(
                    hex::decode(
                        "7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0",
                    )
                    .unwrap(),
                )
                .add_recipient(
                    CoseRecipientBuilder::new()
                        .protected(
                            HeaderBuilder::new()
                                .algorithm(iana::Algorithm::ECDH_ES_HKDF_256)
                                .build(),
                        )
                        .unprotected(
                            HeaderBuilder::new()
                                .value(iana::HeaderAlgorithmParameter::EphemeralKey as i64,
                                       CoseKeyBuilder::new_ec2_pub_key_y_sign(iana::EllipticCurve::P_256,
                                                                              hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280").unwrap(),
                                                                              true)
                                       .build().to_cbor_value().unwrap())
                                .key_id(b"meriadoc.brandybuck@buckland.example".to_vec())
                                .build(),
                        )
                        .ciphertext(vec![])
                        .build(),
                )
                .build(),
            // Note: contents of maps have been re-ordered from the RFC to canonical ordering.
            concat!(
                "d860",
                "84", "43", "a10101",
                "a1", "05", "4c", "c9cf4df2fe6c632bf7886413",
                "5824", "7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0",
                "81",
                "83",
                "44", "a1013818",
                "a2",
                "04",
                "5824", "6d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65",
                "20",
                "a4",
                "01", "02",
                "20", "01",
                "21", "5820", "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
                "22", "f5",
                "40",
            ),
        ),
        (
            CoseEncryptBuilder::new()
                .protected(HeaderBuilder::new().algorithm(iana::Algorithm::AES_CCM_16_64_128).build())
                .unprotected(HeaderBuilder::new().iv(hex::decode("89f52f65a1c580933b5261a76c").unwrap()).build())
                .ciphertext(hex::decode("753548a19b1307084ca7b2056924ed95f2e3b17006dfe931b687b847").unwrap())
                .add_recipient(CoseRecipientBuilder::new()
                               .protected(HeaderBuilder::new().algorithm(iana::Algorithm::Direct_HKDF_SHA_256).build())
                               .unprotected(
                                   HeaderBuilder::new()
                                       .key_id(b"our-secret".to_vec())
                                       .value(iana::HeaderAlgorithmParameter::Salt as i64,
                                              Value::Bytes(b"aabbccddeeffgghh".to_vec()))
                                       .build())
                               .ciphertext(vec![])
                               .build())
                .build(),
            // Note: contents of maps have been re-ordered from the RFC to canonical ordering.
            concat!(
                "d860",
                "84",
                "43",
                "a1010a",
                "a1",
                "05",
                "4d", "89f52f65a1c580933b5261a76c",
                "581c", "753548a19b1307084ca7b2056924ed95f2e3b17006dfe931b687b847",
                "81",
                "83",
                "43",
                "a10129",
                "a2",
                "04", "4a", "6f75722d736563726574",
                "33", "50", "61616262636364646565666667676868",
                "40",
            ),
        ),

        (
            CoseEncryptBuilder::new()
                .protected(HeaderBuilder::new().algorithm(iana::Algorithm::A128GCM).build())
                .unprotected(HeaderBuilder::new()
                             .iv(hex::decode("c9cf4df2fe6c632bf7886413").unwrap())
                             .add_counter_signature(CoseSignatureBuilder::new()
                                                    .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES512).build())
                                                    .unprotected(HeaderBuilder::new().key_id(b"bilbo.baggins@hobbiton.example".to_vec()).build())
                                                    .signature(hex::decode("00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0700a3a7d8f3c604ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff").unwrap())
                                                    .build())
                             .build())
                .ciphertext(hex::decode("7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0").unwrap())
                .add_recipient(CoseRecipientBuilder::new()
                               .protected(
                                   HeaderBuilder::new()
                                       .algorithm(iana::Algorithm::ECDH_ES_HKDF_256)
                                       .build())
                               .unprotected(
                                   HeaderBuilder::new()
                                       .value(iana::HeaderAlgorithmParameter::EphemeralKey as i64,
                                              CoseKeyBuilder::new_ec2_pub_key_y_sign(iana::EllipticCurve::P_256,
                                                                                     hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280").unwrap(),
                                                                                     true)
                                              .build().to_cbor_value().unwrap())
                                       .key_id(b"meriadoc.brandybuck@buckland.example".to_vec())
                                       .build())
                        .ciphertext(vec![])
                               .build())
                .build(),
            // Note: contents of maps have been re-ordered from the RFC to canonical ordering.
            concat!(
                "d860",
                "84",
                "43",
                "a10101",
                "a2",
                "05",
                "4c", "c9cf4df2fe6c632bf7886413",
                "07",
                "83",
                "44",
                "a1013823",
                "a1",
                "04",
                "581e", "62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65",
                "5884",
                "00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0700a3a7d8f3c604ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff",
                "5824",
                "7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0",
                "81",
                "83",
                "44", "a1013818",
                "a2",
                "04",
                "5824", "6d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65",
                "20",
                "a4",
                "01",
                "02",
                "20",
                "01",
                "21",
                "5820", "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
                "22",
                "f5",
                "40",
            ),
        ),
        (
            CoseEncryptBuilder::new()
                .protected(HeaderBuilder::new().algorithm(iana::Algorithm::A128GCM).build())
                .unprotected(HeaderBuilder::new().iv(hex::decode("02d1f7e6f26c43d4868d87ce").unwrap()).build())
                .ciphertext(hex::decode("64f84d913ba60a76070a9a48f26e97e863e28529d8f5335e5f0165eee976b4a5f6c6f09d").unwrap())
                .add_recipient(CoseRecipientBuilder::new()
                               .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ECDH_SS_A128KW).build())
                               .unprotected(HeaderBuilder::new()
                                            .key_id(b"meriadoc.brandybuck@buckland.example".to_vec())
                                            .value(
                                                iana::HeaderAlgorithmParameter::StaticKeyId as i64,
                                                Value::Bytes(b"peregrin.took@tuckborough.example".to_vec())
                                            )
                                            .value(
                                                iana::HeaderAlgorithmParameter::PartyUNonce as i64,
                                                Value::Bytes(hex::decode("0101").unwrap())
                                            )
                                            .build())
                               .ciphertext(hex::decode("41e0d76f579dbd0d936a662d54d8582037de2e366fde1c62").unwrap())
                               .build())
                .build(),
            // Note: contents of maps have been re-ordered from the RFC to canonical ordering.
            concat!(
                "d860",
                "84",
                "43",
                "a10101",
                "a1",
                "05",
                "4c", "02d1f7e6f26c43d4868d87ce",
                "5824", "64f84d913ba60a76070a9a48f26e97e863e28529d8f5335e5f0165eee976b4a5f6c6f09d",
                "81",
                "83",
                "44", "a101381f",
                "a3",
                "04",
                "5824", "6d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65",
                "22",
                "5821", "706572656772696e2e746f6f6b407475636b626f726f7567682e6578616d706c65",
                "35",
                "42",
                "0101",
                "5818", "41e0d76f579dbd0d936a662d54d8582037de2e366fde1c62",
            ),
        ),
    ];

    for (i, (encrypt, encrypt_data)) in tests.iter().enumerate() {
        let got = encrypt.clone().to_tagged_vec().unwrap();
        assert_eq!(*encrypt_data, hex::encode(&got), "case {i}");

        let mut got = CoseEncrypt::from_tagged_slice(&got).unwrap();
        got.protected.original_data = None;
        for recip in &mut got.recipients {
            recip.protected.original_data = None;
        }
        for sig in &mut got.unprotected.counter_signatures {
            sig.protected.original_data = None;
        }
        assert_eq!(*encrypt, got);
    }
}

#[test]
fn test_cose_encrypt0_decode() {
    let tests: Vec<(CoseEncrypt0, &'static str)> = vec![
        (
            CoseEncrypt0Builder::new().build(),
            concat!(
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
            ),
        ),
        (
            CoseEncrypt0Builder::new().ciphertext(vec![]).build(),
            concat!(
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
            ),
        ),
    ];

    for (i, (encrypt, encrypt_data)) in tests.iter().enumerate() {
        let got = encrypt.clone().to_vec().unwrap();
        assert_eq!(*encrypt_data, hex::encode(&got), "case {i}");

        let mut got = CoseEncrypt0::from_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*encrypt, got);
    }
}

#[test]
fn test_cose_encrypt0_decode_fail() {
    let tests = [
        (
            concat!(
                "a2",   // 2-map (should be tuple)
                "40",   // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",   // 0-map
                "4100", // 1-bstr
                "40",   // 0-bstr
            ),
            "expected array",
        ),
        (
            concat!(
                "82", // 2-tuple (should be 3-tuple)
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
            ),
            "expected array with 3 items",
        ),
        (
            concat!(
                "83", // 3-tuple
                "80", // 0-tuple (should be bstr)
                "a0", // 0-map
                "40", // 0-bstr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40", // 0-bstr (should be map)
                "40", // 0-bstr
            ),
            "expected map",
        ),
        (
            concat!(
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "60", // 0-tstr (should be bstr)
            ),
            "expected bstr",
        ),
    ];
    for (encrypt_data, err_msg) in tests.iter() {
        let data = hex::decode(encrypt_data).unwrap();
        let result = CoseEncrypt0::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_rfc8152_cose_encrypt0_decode() {
    // COSE_Encrypt0 structures from RFC 8152 section C.4.
    let tests: Vec<(CoseEncrypt0, &'static str)> = vec![
        (
            CoseEncrypt0Builder::new()
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::AES_CCM_16_64_128)
                        .build(),
                )
                .unprotected(
                    HeaderBuilder::new()
                        .iv(hex::decode("89f52f65a1c580933b5261a78c").unwrap())
                        .build(),
                )
                .ciphertext(
                    hex::decode("5974e1b99a3a4cc09a659aa2e9e7fff161d38ce71cb45ce460ffb569")
                        .unwrap(),
                )
                .build(),
            concat!(
                "d0",
                "83",
                "43",
                "a1010a",
                "a1",
                "05",
                "4d",
                "89f52f65a1c580933b5261a78c",
                "581c",
                "5974e1b99a3a4cc09a659aa2e9e7fff161d38ce71cb45ce460ffb569",
            ),
        ),
        (
            CoseEncrypt0Builder::new()
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::AES_CCM_16_64_128)
                        .build(),
                )
                .unprotected(
                    HeaderBuilder::new()
                        .partial_iv(hex::decode("61a7").unwrap())
                        .build(),
                )
                .ciphertext(
                    hex::decode("252a8911d465c125b6764739700f0141ed09192de139e053bd09abca")
                        .unwrap(),
                )
                .build(),
            concat!(
                "d0",
                "83",
                "43",
                "a1010a",
                "a1",
                "06",
                "42",
                "61a7",
                "581c",
                "252a8911d465c125b6764739700f0141ed09192de139e053bd09abca",
            ),
        ),
    ];

    for (i, (encrypt, encrypt_data)) in tests.iter().enumerate() {
        let got = encrypt.clone().to_tagged_vec().unwrap();
        assert_eq!(*encrypt_data, hex::encode(&got), "case {i}");

        let mut got = CoseEncrypt0::from_tagged_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*encrypt, got);
    }
}

struct FakeCipher {}

impl FakeCipher {
    fn encrypt(&self, plaintext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, String> {
        let mut result = vec![];
        result.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        result.extend_from_slice(plaintext);
        result.extend_from_slice(additional_data);
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 4 {
            return Err("not long enough".to_owned());
        }
        let pt_len =
            u32::from_be_bytes([ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]])
                as usize;
        let pt = &ciphertext[4..4 + pt_len];
        let recovered_aad = &ciphertext[4 + pt_len..];
        if recovered_aad != additional_data {
            return Err("aad doesn't match".to_owned());
        }
        Ok(pt.to_vec())
    }
    fn fail_encrypt(&self, _plaintext: &[u8], _additional_data: &[u8]) -> Result<Vec<u8>, String> {
        Err("failed".to_string())
    }
}

#[test]
fn test_cose_recipient_roundtrip() {
    let pt = b"This is the plaintext";
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    for context in &[
        EncryptionContext::EncRecipient,
        EncryptionContext::MacRecipient,
        EncryptionContext::RecRecipient,
    ] {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .key_id(b"11".to_vec())
            .build();

        let mut recipient = CoseRecipientBuilder::new()
            .protected(protected)
            .create_ciphertext(*context, pt, external_aad, |pt, aad| {
                cipher.encrypt(pt, aad).unwrap()
            })
            .build();

        let recovered_pt = recipient
            .decrypt(*context, external_aad, |ct, aad| cipher.decrypt(ct, aad))
            .unwrap();
        assert_eq!(&pt[..], recovered_pt);

        // Changing an unprotected header leaves the ciphertext decipherable.
        recipient.unprotected.content_type = Some(ContentType::Text("text/plain".to_owned()));
        assert!(recipient
            .decrypt(*context, external_aad, |ct, aad| {
                cipher.decrypt(ct, aad)
            })
            .is_ok());

        // Providing a different `aad` means the ciphertext won't validate.
        assert!(recipient
            .decrypt(*context, b"not aad", |ct, aad| { cipher.decrypt(ct, aad) })
            .is_err());

        // Changing a protected header invalidates the ciphertext.
        recipient.protected = ProtectedHeader::default();
        assert!(recipient
            .decrypt(*context, external_aad, |ct, aad| {
                cipher.decrypt(ct, aad)
            })
            .is_err());
    }
}

#[test]
fn test_cose_recipient_noncanonical() {
    let pt = b"aa";
    let aad = b"bb";
    let cipher = FakeCipher {};
    let context = EncryptionContext::EncRecipient;

    // Build an empty protected header from a non-canonical input of 41a0 rather than 40.
    let protected = ProtectedHeader::from_cbor_bstr(Value::Bytes(vec![0xa0])).unwrap();
    assert_eq!(protected.header, Header::default());
    assert_eq!(protected.original_data, Some(vec![0xa0]));

    let mut recipient = CoseRecipient {
        protected: protected.clone(),
        ..Default::default()
    };
    let internal_aad = crate::encrypt::enc_structure_data(context, protected, aad);
    recipient.ciphertext = Some(cipher.encrypt(pt, &internal_aad).unwrap());

    // Deciphering the ciphertext should still succeed, because the `ProtectedHeader`
    // includes the wire data and uses it for building the decryption input.
    let recovered_pt = recipient
        .decrypt(context, aad, |ct, aad| cipher.decrypt(ct, aad))
        .unwrap();
    assert_eq!(&pt[..], recovered_pt);

    // However, if we attempt to build the same decryption inputs by hand (thus not including the
    // non-canonical wire data)...
    let recreated_recipient = CoseRecipientBuilder::new()
        .ciphertext(recipient.ciphertext.unwrap())
        .build();

    // ...then the transplanted cipher text will not decipher, because the re-building of the
    // inputs will use the canonical encoding of the protected header, which is not what was
    // originally used for the input.
    assert!(recreated_recipient
        .decrypt(context, aad, |ct, aad| cipher.decrypt(ct, aad))
        .is_err());
}

#[test]
fn test_cose_recipient_result() {
    let pt = b"This is the plaintext";
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let _recipient = CoseRecipientBuilder::new()
        .protected(protected.clone())
        .try_create_ciphertext(
            EncryptionContext::EncRecipient,
            pt,
            external_aad,
            |pt, aad| cipher.encrypt(pt, aad),
        )
        .unwrap()
        .build();
    let status = CoseRecipientBuilder::new()
        .protected(protected)
        .try_create_ciphertext(
            EncryptionContext::EncRecipient,
            pt,
            external_aad,
            |pt, aad| cipher.fail_encrypt(pt, aad),
        );
    expect_err(status, "failed");
}

#[test]
#[should_panic]
fn test_cose_recipient_missing_ciphertext() {
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let recipient = CoseRecipient::default();

    // No ciphertext has been set, do decryption will panic.
    let _result = recipient.decrypt(EncryptionContext::EncRecipient, external_aad, |ct, aad| {
        cipher.decrypt(ct, aad)
    });
}

#[test]
#[should_panic]
fn test_cose_recipient_builder_invalid_context() {
    let pt = b"This is the plaintext";
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    // Can't use a non-recipient context.
    let _recipient = CoseRecipientBuilder::new()
        .create_ciphertext(
            EncryptionContext::CoseEncrypt,
            pt,
            external_aad,
            |pt, aad| cipher.encrypt(pt, aad).unwrap(),
        )
        .build();
}

#[test]
#[should_panic]
fn test_cose_recipient_decrypt_invalid_context() {
    let pt = b"This is the plaintext";
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let recipient = CoseRecipientBuilder::new()
        .create_ciphertext(
            EncryptionContext::EncRecipient,
            pt,
            external_aad,
            |pt, aad| cipher.encrypt(pt, aad).unwrap(),
        )
        .build();

    // Can't use a non-recipient context.
    let _result = recipient.decrypt(EncryptionContext::CoseEncrypt, external_aad, |ct, aad| {
        cipher.decrypt(ct, aad)
    });
}

#[test]
fn test_cose_encrypt_roundtrip() {
    let pt = b"This is the plaintext";
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let mut encrypt = CoseEncryptBuilder::new()
        .protected(protected)
        .create_ciphertext(pt, external_aad, |pt, aad| cipher.encrypt(pt, aad).unwrap())
        .build();

    let recovered_pt = encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .unwrap();
    assert_eq!(&pt[..], recovered_pt);

    // Changing an unprotected header leaves the ciphertext decipherable.
    encrypt.unprotected.content_type = Some(ContentType::Text("text/plain".to_owned()));
    assert!(encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .is_ok());

    // Providing a different `aad` means the signature won't validate.
    assert!(encrypt
        .decrypt(b"not aad", |ct, aad| cipher.decrypt(ct, aad))
        .is_err());

    // Changing a protected header invalidates the ciphertext.
    encrypt.protected = ProtectedHeader::default();
    assert!(encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .is_err());
}

#[test]
fn test_cose_encrypt_noncanonical() {
    let pt = b"aa";
    let external_aad = b"bb";
    let cipher = FakeCipher {};

    // Build an empty protected header from a non-canonical input of 41a0 rather than 40.
    let protected = ProtectedHeader::from_cbor_bstr(Value::Bytes(vec![0xa0])).unwrap();
    assert_eq!(protected.header, Header::default());
    assert_eq!(protected.original_data, Some(vec![0xa0]));

    let mut encrypt = CoseEncrypt {
        protected: protected.clone(),
        ..Default::default()
    };
    let aad = enc_structure_data(
        EncryptionContext::CoseEncrypt,
        protected.clone(),
        external_aad,
    );
    encrypt.ciphertext = Some(cipher.encrypt(pt, &aad).unwrap());

    // Deciphering the ciphertext should still succeed, because the `ProtectedHeader`
    // includes the wire data and uses it for building the decryption input.
    let recovered_pt = encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .unwrap();
    assert_eq!(&pt[..], recovered_pt);

    // However, if we attempt to build the same decryption inputs by hand (thus not including the
    // non-canonical wire data)...
    let recreated_encrypt = CoseEncryptBuilder::new()
        .protected(protected.header)
        .ciphertext(encrypt.ciphertext.unwrap())
        .build();

    // ...then the transplanted cipher text will not decipher, because the re-building of the
    // inputs will use the canonical encoding of the protected header, which is not what was
    // originally used for the input.
    assert!(recreated_encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .is_err());
}

#[test]
fn test_cose_encrypt_status() {
    let pt = b"This is the plaintext";
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let _encrypt = CoseEncryptBuilder::new()
        .protected(protected.clone())
        .try_create_ciphertext(pt, external_aad, |pt, aad| cipher.encrypt(pt, aad))
        .unwrap()
        .build();
    let status = CoseEncryptBuilder::new()
        .protected(protected)
        .try_create_ciphertext(pt, external_aad, |pt, aad| cipher.fail_encrypt(pt, aad));
    expect_err(status, "failed");
}

#[test]
#[should_panic]
fn test_cose_encrypt_missing_ciphertext() {
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let encrypt = CoseEncrypt::default();

    // No ciphertext has been set, do decryption will panic.
    let _result = encrypt.decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad));
}

#[test]
fn test_cose_encrypt0_roundtrip() {
    let pt = b"This is the plaintext";
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let mut encrypt = CoseEncrypt0Builder::new()
        .protected(protected)
        .create_ciphertext(pt, external_aad, |pt, aad| cipher.encrypt(pt, aad).unwrap())
        .build();

    let recovered_pt = encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .unwrap();
    assert_eq!(&pt[..], recovered_pt);

    // Changing an unprotected header leaves the ciphertext decipherable.
    encrypt.unprotected.content_type = Some(ContentType::Text("text/plain".to_owned()));
    assert!(encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .is_ok());

    // Providing a different `aad` means the ciphertext won't decrypt.
    assert!(encrypt
        .decrypt(b"not aad", |ct, aad| cipher.decrypt(ct, aad))
        .is_err());

    // Changing a protected header invalidates the ciphertext.
    encrypt.protected = ProtectedHeader::default();
    assert!(encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .is_err());
}

#[test]
fn test_cose_encrypt0_noncanonical() {
    let pt = b"aa";
    let external_aad = b"bb";
    let cipher = FakeCipher {};

    // Build an empty protected header from a non-canonical input of 41a0 rather than 40.
    let protected = ProtectedHeader::from_cbor_bstr(Value::Bytes(vec![0xa0])).unwrap();
    assert_eq!(protected.header, Header::default());
    assert_eq!(protected.original_data, Some(vec![0xa0]));

    let mut encrypt = CoseEncrypt0 {
        protected: protected.clone(),
        ..Default::default()
    };
    let aad = enc_structure_data(
        EncryptionContext::CoseEncrypt0,
        protected.clone(),
        external_aad,
    );
    encrypt.ciphertext = Some(cipher.encrypt(pt, &aad).unwrap());

    // Deciphering the ciphertext should still succeed, because the `ProtectedHeader`
    // includes the wire data and uses it for building the decryption input.
    let recovered_pt = encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .unwrap();
    assert_eq!(&pt[..], recovered_pt);

    // However, if we attempt to build the same decryption inputs by hand (thus not including the
    // non-canonical wire data)...
    let recreated_encrypt = CoseEncrypt0Builder::new()
        .protected(protected.header)
        .ciphertext(encrypt.ciphertext.unwrap())
        .build();

    // ...then the transplanted cipher text will not decipher, because the re-building of the
    // inputs will use the canonical encoding of the protected header, which is not what was
    // originally used for the input.
    assert!(recreated_encrypt
        .decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad))
        .is_err());
}
#[test]
fn test_cose_encrypt0_status() {
    let pt = b"This is the plaintext";
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let _encrypt = CoseEncrypt0Builder::new()
        .protected(protected.clone())
        .try_create_ciphertext(pt, external_aad, |pt, aad| cipher.encrypt(pt, aad))
        .unwrap()
        .build();
    let status = CoseEncrypt0Builder::new()
        .protected(protected)
        .try_create_ciphertext(pt, external_aad, |pt, aad| cipher.fail_encrypt(pt, aad));
    expect_err(status, "failed");
}

#[test]
#[should_panic]
fn test_cose_encrypt0_missing_ciphertext() {
    let external_aad = b"This is the external aad";
    let cipher = FakeCipher {};

    let encrypt = CoseEncrypt0::default();

    // No ciphertext has been set, do decryption will panic.
    let _result = encrypt.decrypt(external_aad, |ct, aad| cipher.decrypt(ct, aad));
}
