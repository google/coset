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
    cbor::value::Value, iana, util::expect_err, Algorithm, CborSerializable, ContentType,
    HeaderBuilder, RegisteredLabel, TaggedCborSerializable,
};
use alloc::{
    format,
    string::{String, ToString},
    vec,
};

#[test]
fn test_cose_signature_encode() {
    let tests = vec![
        (
            CoseSignature::default(),
            concat!(
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
            ),
        ),
        (
            CoseSignature {
                signature: vec![1, 2, 3],
                ..Default::default()
            },
            concat!(
                "83",       // 3-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",       // 0-map
                "43010203", // 3-bstr
            ),
        ),
        (
            CoseSignature {
                protected: ProtectedHeader {
                    original_data: None,
                    header: Header {
                        alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                        key_id: vec![1, 2, 3],
                        partial_iv: vec![1, 2, 3],
                        ..Default::default()
                    },
                },
                signature: vec![1, 2, 3],
                ..Default::default()
            },
            concat!(
                "83", // 3-tuple
                "4d", // 13-bstr
                "a3", // 3-map
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "06", "43", "010203",   // 6 (partial-iv) => 3-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
            ),
        ),
        (
            CoseSignature {
                unprotected: Header {
                    alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                    key_id: vec![1, 2, 3],
                    partial_iv: vec![1, 2, 3],
                    ..Default::default()
                },
                signature: vec![1, 2, 3],
                ..Default::default()
            },
            concat!(
                "83", // 3-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a3", // 3-map
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "06", "43", "010203",   // 6 (partial-iv) => 3-bstr
                "43010203", // 3-bstr
            ),
        ),
    ];
    for (i, (sig, sig_data)) in tests.iter().enumerate() {
        let got = sig.clone().to_vec().unwrap();
        assert_eq!(*sig_data, hex::encode(&got), "case {}", i);

        let mut got = CoseSignature::from_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*sig, got);
    }
}

#[test]
fn test_cose_signature_decode_noncanonical() {
    // RFC8152 section 3: "Recipients MUST accept both a zero-length binary value and a zero-length
    // map encoded in the binary value."
    let sig_data = hex::decode(concat!(
        "83",   // 3-tuple
        "41a0", // 1-bstr holding 0-map (not a 0-bstr)
        "a0",   // 0-map
        "40",   // 0-bstr
    ))
    .unwrap();
    let sig = CoseSignature::default();
    let mut got = CoseSignature::from_slice(&sig_data).unwrap();
    got.protected.original_data = None;
    assert_eq!(sig, got);
}

#[test]
fn test_cose_signature_decode_fail() {
    let tests = vec![
        (
            concat!(
                "a2",       // 2-map
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",       // 0-map
                "43010203", // 3-bstr
                "40",       // 0-bstr
            ),
            "expected array",
        ),
        (
            concat!(
                "83",       // 3-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40",       // 0-bstr (invalid: should be map)
                "43010203", // 3-bstr
            ),
            "expected map",
        ),
        (
            concat!(
                "83",       // 3-tuple
                "a0",       // 0-map (invalid: should be bstr)
                "a0",       // 0-map
                "43010203", // 3-bstr
            ),
            "expected bstr encoded map",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "43010203", // 3-bstr
            ),
            "expected array with 3 items",
        ),
        (
            concat!(
                "82", // 4-tuple
                "40", // 0-bstr
                "a0", // 0-map
            ),
            "expected array with 3 items",
        ),
        (
            concat!(
                "83",       // 3-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40",       // 0-bstr (invalid: should be map)
                "63616263", // 3-tstr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "83", // 3-tuple
                "45", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a1", // 1-map
                "03", "81", "4101",     // 3 (content-type) => [bstr] (invalid value type)
                "a0",       // 0-map
                "43616263", // 0-bstr
            ),
            "expected int/tstr",
        ),
    ];
    for (sig_data, err_msg) in tests.iter() {
        let data = hex::decode(sig_data).unwrap();
        let result = CoseSignature::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_signature_builder() {
    let tests = vec![
        (
            CoseSignatureBuilder::new().build(),
            CoseSignature::default(),
        ),
        (
            CoseSignatureBuilder::new().signature(vec![1, 2, 3]).build(),
            CoseSignature {
                signature: vec![1, 2, 3],
                ..Default::default()
            },
        ),
        (
            CoseSignatureBuilder::new()
                .signature(vec![1, 2, 3])
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::A128GCM)
                        .key_id(vec![1, 2, 3])
                        .iv(vec![1, 2, 3])
                        .build(),
                )
                .build(),
            CoseSignature {
                protected: ProtectedHeader {
                    original_data: None,
                    header: Header {
                        alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                        key_id: vec![1, 2, 3],
                        iv: vec![1, 2, 3],
                        ..Default::default()
                    },
                },
                signature: vec![1, 2, 3],
                ..Default::default()
            },
        ),
        (
            CoseSignatureBuilder::new()
                .signature(vec![1, 2, 3])
                .unprotected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::A128GCM)
                        .key_id(vec![1, 2, 3])
                        .partial_iv(vec![1, 2, 3])
                        .build(),
                )
                .build(),
            CoseSignature {
                unprotected: Header {
                    alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                    key_id: vec![1, 2, 3],
                    partial_iv: vec![1, 2, 3],
                    ..Default::default()
                },
                signature: vec![1, 2, 3],
                ..Default::default()
            },
        ),
    ];
    for (got, want) in tests {
        assert_eq!(got, want);
    }
}

#[test]
fn test_cose_sign_encode() {
    let tests = vec![
        (
            CoseSign::default(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
                "80", // 0-tuple
            ),
        ),
        (
            CoseSignBuilder::new()
                .add_signature(CoseSignature::default())
                .build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
                "81", // 1-tuple
                "83", "40a040", // 3-tuple
            ),
        ),
        (
            CoseSignBuilder::new()
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::A128GCM)
                        .key_id(vec![1, 2, 3])
                        .build(),
                )
                .payload(vec![4, 5, 6])
                .add_signature(
                    CoseSignatureBuilder::new()
                        .signature(vec![1, 2, 3])
                        .protected(
                            HeaderBuilder::new()
                                .algorithm(iana::Algorithm::A128GCM)
                                .key_id(vec![1, 2, 3])
                                .iv(vec![1, 2, 3])
                                .build(),
                        )
                        .build(),
                )
                .build(),
            concat!(
                "84", // 4-tuple
                "48", // 8-bstr (protected)
                "a2", // 2-map
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "a0",     // 0-map (unprotected)
                "43", "040506", // 3-bstr (payload)
                "81",     // 1-tuple (signatures)
                "83",     // 3-tuple (COSE_Signature)
                "4d",     // 14-bstr (protected)
                "a3",     // 3-map
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "05", "43", "010203", // 5 (iv) => 3-bstr
                "a0",     // 0-map (unprotected)
                "43", "010203", // 0-bstr (signature)
            ),
        ),
        (
            CoseSignBuilder::new()
                .unprotected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::A128GCM)
                        .key_id(vec![1, 2, 3])
                        .build(),
                )
                .payload(vec![4, 5, 6])
                .add_signature(
                    CoseSignatureBuilder::new()
                        .signature(vec![1, 2, 3])
                        .protected(
                            HeaderBuilder::new()
                                .algorithm(iana::Algorithm::A128GCM)
                                .key_id(vec![1, 2, 3])
                                .iv(vec![1, 2, 3])
                                .build(),
                        )
                        .build(),
                )
                .build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (protected)
                "a2", // 2-map (unprotected)
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "43", "040506", // 3-bstr (payload)
                "81",     // 1-tuple (signatures)
                "83",     // 3-tuple (COSE_Signature)
                "4d",     // 14-bstr (protected)
                "a3",     // 3-map
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "05", "43", "010203", // 5 (iv) => 3-bstr
                "a0",     // 0-map (unprotected)
                "43", "010203", // 0-bstr (signature)
            ),
        ),
    ];
    for (i, (sign, sign_data)) in tests.iter().enumerate() {
        let got = sign.clone().to_vec().unwrap();
        assert_eq!(*sign_data, hex::encode(&got), "case {}", i);

        let mut got = CoseSign::from_slice(&got).unwrap();
        got.protected.original_data = None;
        for mut sig in &mut got.signatures {
            sig.protected.original_data = None;
        }
        assert_eq!(*sign, got);

        // Repeat with tagged variant.
        let got = sign.clone().to_tagged_vec().unwrap();
        let tagged_sign_data = format!("d862{}", sign_data);
        assert_eq!(tagged_sign_data, hex::encode(&got), "tagged case {}", i);

        let mut got = CoseSign::from_tagged_slice(&got).unwrap();
        got.protected.original_data = None;
        for mut sig in &mut got.signatures {
            sig.protected.original_data = None;
        }
        assert_eq!(*sign, got);
    }
}

#[test]
fn test_cose_sign_decode_fail() {
    let tests = vec![
        (
            concat!(
                "a2",       // 2-map
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40",       // 0-bstr (invalid: should be map)
                "43010203", // 3-bstr
                "80",       // 0-tuple
            ),
            "expected array",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40",       // 0-bstr (invalid: should be map)
                "43010203", // 3-bstr
                "80",       // 0-tuple
            ),
            "expected map",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "a0",       // 0-map (invalid: should be bstr)
                "a0",       // 0-map
                "43010203", // 3-bstr
                "80",       // 0-tuple
            ),
            "expected bstr encoded map",
        ),
        (
            concat!(
                "85",       // 5-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "80",       // 0-tuple
                "43010203", // 3-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "83",       // 3-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "43010203", // 3-bstr
            ),
            "expected array of COSE_Signature",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "63616263", // 3-tstr
                "80",       // 0-tuple
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",       // 0-map
                "43010203", // 3-bstr
                "81",       // 1-tuple
                "83",       // 3-tuple
                "a0",       // 0-map (invalid: should be bstr)
                "a0",       // 0-map
                "43010203", // 3-bstr
            ),
            "expected map for COSE_Signature",
        ),
        (
            concat!(
                "84", // 4-tuple
                "45", // 5-bstr
                "a1", // 1-map
                "03", "81", "4101",     // 3 (content-type) => [bstr] (invalid value type)
                "a0",       // 0-map
                "43616263", // 3-bstr
                "80",       // 0-tuple
            ),
            "expected int/tstr",
        ),
    ];
    for (sign_data, err_msg) in tests.iter() {
        let data = hex::decode(sign_data).unwrap();
        let result = CoseSign::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_sign_tagged_decode_fail() {
    let tests = vec![
        (
            concat!(
                "d862",     // tag(98)
                "84",       // 4-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40",       // 0-bstr (invalid: should be map)
                "43010203", // 3-bstr
                "80",       // 0-tuple
            ),
            "expected map",
        ),
        (
            concat!(
                "d862",     // tag(98)
                "84",       // 4-tuple
                "a0",       // 0-map (invalid: should be bstr)
                "a0",       // 0-map
                "43010203", // 3-bstr
                "80",       // 0-tuple
            ),
            "expected bstr encoded map",
        ),
        (
            concat!(
                "d862",     // tag(98)
                "85",       // 5-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "80",       // 0-tuple
                "43010203", // 3-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "d862",     // tag(98)
                "83",       // 3-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "d861",     // tag(97) : wrong tag
                "84",       // 4-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "80",       // 0-tuple
            ),
            "expected tag",
        ),
        (
            concat!(
                "1861",     // int (97) : not a tag
                "84",       // 4-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "80",       // 0-tuple
            ),
            "got int, expected tag",
        ),
        (
            concat!(
                "18",     // incomplete int
            ),
            "decode CBOR failure: Io(EndOfFile",
        ),
    ];
    for (sign_data, err_msg) in tests.iter() {
        let data = hex::decode(sign_data).unwrap();
        let result = CoseSign::from_tagged_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_rfc8152_cose_sign_decode() {
    // COSE_Sign structures from RFC 8152 section C.1.
    let tests = vec![
        (
            CoseSignBuilder::new()
                .payload(b"This is the content.".to_vec())
                .add_signature(
                    CoseSignatureBuilder::new()
                        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build())
                        .unprotected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
                        .signature(hex::decode(
                            "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a"
                        ).unwrap())
                        .build()
                )
                .build(),
            concat!(
                "d862",
                "84",
                "40",
                "a0",
                "54", "546869732069732074686520636f6e74656e742e",
                "81", "83",
                "43", "a10126",
                "a1", "04", "42", "3131",
                "5840", "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a"
            ),
        ),
        (
            CoseSignBuilder::new()
                .payload(b"This is the content.".to_vec())
                .add_signature(
                    CoseSignatureBuilder::new()
                        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build())
                        .unprotected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
                        .signature(hex::decode(
                            "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a"
                        ).unwrap())
                        .build()
                )
                .add_signature(
                    CoseSignatureBuilder::new()
                        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES512).build())
                        .unprotected(HeaderBuilder::new().key_id(b"bilbo.baggins@hobbiton.example".to_vec()).build())
                        .signature(hex::decode(
                            "00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297"
                        ).unwrap())
                        .build()
                )
                .build(),
            concat!(
                "d862",
                "84",
                "40",
                "a0", "54", "546869732069732074686520636f6e74656e742e",
                "82",
                "83",
                "43", "a10126",
                "a1", "04", "42", "3131",
                "5840", "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a",
                "83",
                "44", "a1013823",
                "a1", "04", "581e", "62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65",
                "5884", "00a2d28a7c2bdb1587877420f65adf7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e8705524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb13877dd2582866883535de3bb03d01753f83ab87bb4f7a0297",
            )
        ),
        (
            CoseSignBuilder::new()
                .unprotected(HeaderBuilder::new()
                             .add_counter_signature(
                                 CoseSignatureBuilder::new()
                                     .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build())
                                     .unprotected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
                                     .signature(hex::decode(
                                         "5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c"
                                     ).unwrap())
                                     .build()
                             )
                             .build())
                .payload(b"This is the content.".to_vec())
                .add_signature(
                    CoseSignatureBuilder::new()
                        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build())
                        .unprotected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
                        .signature(hex::decode(
                            "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a"
                        ).unwrap())
                        .build()
                )
                .build(),
            concat!(
                "d862",
                "84",
                "40",
                "a1", "07",
                "83",
                "43", "a10126",
                "a1", "04", "42", "3131",
                "5840", "5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c",
                "54", "546869732069732074686520636f6e74656e742e",
                "81",
                "83",
                "43", "a10126",
                "a1", "04", "42", "3131",
                "5840", "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a",
            ),
        ),
        (
            CoseSignBuilder::new()
                .protected(HeaderBuilder::new()
                           .text_value("reserved".to_owned(), Value::Bool(false))
                           .add_critical_label(RegisteredLabel::Text("reserved".to_owned()))
                           .build())
                .payload(b"This is the content.".to_vec())
                .add_signature(
                    CoseSignatureBuilder::new()
                        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build())
                        .unprotected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
                        .signature(hex::decode(
                            "3fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c"
                        ).unwrap())
                        .build()
                )
                .build(),
            // Note: contents of protected header changed from RFC to be put in canonical order.
            concat!(
                "d862",
                "84",
                "56",
                "a2",
                "02", "81687265736572766564",
                "687265736572766564", "f4",
                "a0",
                "54", "546869732069732074686520636f6e74656e742e",
                "81", "83",
                "43", "a10126",
                "a1", "04", "42", "3131",
                "5840", "3fc54702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd9c",
            ),
        ),
    ];

    for (i, (sign, sign_data)) in tests.iter().enumerate() {
        let got = sign.clone().to_tagged_vec().unwrap();
        assert_eq!(
            *sign_data,
            hex::encode(&got),
            "case {}: encode {:?}",
            i,
            sign
        );

        let mut got = CoseSign::from_tagged_slice(&got).unwrap();
        got.protected.original_data = None;
        for mut sig in &mut got.signatures {
            sig.protected.original_data = None;
        }
        for mut sig in &mut got.unprotected.counter_signatures {
            sig.protected.original_data = None;
        }
        assert_eq!(*sign, got);
    }
}

#[test]
fn test_cose_sign1_encode() {
    let tests = vec![
        (
            CoseSign1Builder::new().payload(vec![]).build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
            ),
        ),
        (
            CoseSign1Builder::new().signature(vec![1, 2, 3]).build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
                "43", "010203", // 3-bstr
            ),
        ),
        (
            CoseSign1Builder::new()
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::A128GCM)
                        .key_id(vec![1, 2, 3])
                        .build(),
                )
                .payload(vec![])
                .signature(vec![1, 2, 3])
                .build(),
            concat!(
                "84", // 4-tuple
                "48", // 8-bstr (protected)
                "a2", // 2-map
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "a0",     // 0-map
                "40",     // 0-bstr
                "43", "010203", // 3-bstr
            ),
        ),
        (
            CoseSign1Builder::new()
                .unprotected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::A128GCM)
                        .key_id(vec![1, 2, 3])
                        .build(),
                )
                .payload(vec![])
                .signature(vec![1, 2, 3])
                .build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a2", // 2-map
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "40",     // 0-bstr
                "43", "010203", // 3-bstr
            ),
        ),
    ];
    for (i, (sign, sign_data)) in tests.iter().enumerate() {
        let got = sign.clone().to_vec().unwrap();
        assert_eq!(*sign_data, hex::encode(&got), "case {}", i);

        let mut got = CoseSign1::from_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*sign, got);

        // Repeat with tagged variant.
        let got = sign.clone().to_tagged_vec().unwrap();
        let want_hex = format!("d2{}", sign_data);
        assert_eq!(want_hex, hex::encode(&got), "tagged case {}", i);

        let mut got = CoseSign1::from_tagged_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*sign, got);
    }
}

#[test]
fn test_cose_sign1_decode_fail() {
    let tests = vec![
        (
            concat!(
                "a2",       // 2-map
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",       // 0-map
                "43010203", // 3-bstr
                "40",       // 0-bstr
            ),
            "expected array",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40",       // 0-bstr (invalid: should be map)
                "43010203", // 3-bstr
                "40",       // 0-bstr
            ),
            "expected map",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "a0",       // 0-map (invalid: should be bstr)
                "a0",       // 0-map
                "43010203", // 3-bstr
                "40",       // 0-bstr
            ),
            "expected bstr encoded map",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",       // 0-map
                "63616263", // 3-tstr
                "40",       // 0-bstr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84",       // 4-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "80",       // 0-arr (invalid: should be bstr)
            ),
            "expected bstr",
        ),
        (
            concat!(
                "85",       // 5-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "40",       // 0-bstr
                "43010203", // 3-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "83",       // 3-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "84", // 4-tuple
                "45", // 5-bstr
                "a1", // 1-map
                "03", "81", "4101",     // 3 (content-type) => [bstr] (invalid value type)
                "a0",       // 0-map
                "43616263", // 3-bstr
                "40",       // 0-bstr
            ),
            "expected int/tstr",
        ),
    ];
    for (sign_data, err_msg) in tests.iter() {
        let data = hex::decode(sign_data).unwrap();
        let result = CoseSign1::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_sign1_decode_noncanonical() {
    let tests = vec![(
        CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::ES256)
                    .key_id(vec![0x31, 0x31])
                    .build(),
            )
            .payload(vec![0x61, 0x61])
            .build(),
        concat!(
            "84", // 4-tuple
            "47", // bstr len 7 (protected)
            concat!(
                "a2", // 2-map
                // The contents of the bstr-encoded header are not in canonical order.
                "04", "42", "3131", // 4 (kid) => 2-bstr "11"
                "01", "26", // 1 (alg) => ES256
            ),
            "a0",   // 0-map (unprotected)
            "42",   // 2-bstr (payload)
            "6161", // "aa"
            "40",   // 0-bstr
        ),
    )];
    for (sign, sign_data) in tests.iter() {
        let data = hex::decode(sign_data).unwrap();
        let mut got = CoseSign1::from_slice(&data).unwrap();
        got.protected.original_data = None;
        assert_eq!(*sign, got);

        // Repeat with tagged variant.
        let mut tagged_data = vec![0xd2];
        tagged_data.extend_from_slice(&data);
        let mut got = CoseSign1::from_tagged_slice(&tagged_data).unwrap();
        got.protected.original_data = None;
        assert_eq!(*sign, got);
    }
}

#[test]
fn test_cose_sign1_tagged_decode_fail() {
    let tests = vec![
        (
            concat!(
                "d2",       // tag(18)
                "84",       // 4-tuple
                "40",       // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40",       // 0-bstr (invalid: should be map)
                "43010203", // 3-bstr
                "40",       // 0-bstr
            ),
            "expected map",
        ),
        (
            concat!(
                "d2",       // tag(18)
                "84",       // 4-tuple
                "a0",       // 0-map (invalid: should be bstr)
                "a0",       // 0-map
                "43010203", // 3-bstr
                "40",       // 0-bstr
            ),
            "expected bstr encoded map",
        ),
        (
            concat!(
                "d2",       // tag(18)
                "85",       // 5-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "80",       // 0-tuple
                "40",       // 0-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "d2",       // tag(18)
                "83",       // 3-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
            ),
            "expected array with 4 items",
        ),
        (
            concat!(
                "d1",       // tag(17) : wrong tag
                "84",       // 4-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "40",       // 0-bstr
            ),
            "expected tag",
        ),
        (
            concat!(
                "12",       // int (18) : not a tag
                "84",       // 4-tuple
                "40",       // 0-bstr
                "a0",       // 0-map
                "43010203", // 3-bstr
                "40",       // 0-bstr
            ),
            "got int, expected tag",
        ),
        (
            concat!(
                "12",     // incomplete int
            ),
            "expected tag",
        ),
    ];
    for (sign_data, err_msg) in tests.iter() {
        let data = hex::decode(sign_data).unwrap();
        let result = CoseSign1::from_tagged_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_rfc8152_cose_sign1_decode() {
    // COSE_Sign1 structures from RFC 8152 section C.2.
    let tests = vec![
        (
            CoseSign1Builder::new()
                .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build())
                .unprotected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
                .payload(b"This is the content.".to_vec())
                .signature(hex::decode(
                    "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36",
                ).unwrap())
                .build(),
            concat!(
                "d2",
                "84",
                "43", "a10126",
                "a1", "04", "42", "3131",
                "54", "546869732069732074686520636f6e74656e742e",
                "5840", "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36",
            ),
        ),
    ];

    for (i, (sign, sign_data)) in tests.iter().enumerate() {
        let got = sign.clone().to_tagged_vec().unwrap();
        assert_eq!(*sign_data, hex::encode(&got), "case {}", i);

        let mut got = CoseSign1::from_tagged_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*sign, got);
    }
}

#[derive(Copy, Clone)]
struct FakeSigner {}

extern crate std;
impl FakeSigner {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn verify(&self, sig: &[u8], data: &[u8]) -> Result<(), String> {
        if sig != self.sign(data) {
            Err("failed to verify".to_owned())
        } else {
            Ok(())
        }
    }
    fn try_sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.sign(data))
    }

    fn fail_sign(&self, _data: &[u8]) -> Result<Vec<u8>, String> {
        Err("failed".to_string())
    }
}

#[test]
fn test_sign_roundtrip() {
    let signer = FakeSigner {};
    let verifier = signer;

    let pt = b"This is the content";
    let aad = b"this is additional data";

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let sign = CoseSignBuilder::new()
        .protected(protected.clone())
        .payload(pt.to_vec())
        .add_created_signature(
            CoseSignatureBuilder::new().protected(protected).build(),
            aad,
            |pt| signer.sign(pt),
        )
        .build();

    let sign_data = sign.to_vec().unwrap();
    let mut sign = CoseSign::from_slice(&sign_data).unwrap();

    assert!(sign
        .verify_signature(0, aad, |sig, data| verifier.verify(sig, data))
        .is_ok());

    // Changing an unprotected header leaves the signature valid.
    sign.unprotected.content_type = Some(ContentType::Text("text/plain".to_owned()));
    assert!(sign
        .verify_signature(0, aad, |sig, data| verifier.verify(sig, data))
        .is_ok());

    // Providing a different `aad` means the signature won't validate.
    assert!(sign
        .verify_signature(0, b"not aad", |sig, data| verifier.verify(sig, data))
        .is_err());

    // Changing a protected header invalidates the signature.
    let mut sign2 = sign.clone();
    sign2.protected = ProtectedHeader::default();
    assert!(sign2
        .verify_signature(0, aad, |sig, data| verifier.verify(sig, data))
        .is_err());
    let mut sign3 = sign;
    sign3.signatures[0].protected = ProtectedHeader::default();
    assert!(sign2
        .verify_signature(0, aad, |sig, data| verifier.verify(sig, data))
        .is_err());
}

#[test]
fn test_sign_noncanonical() {
    let signer = FakeSigner {};
    let verifier = signer;
    let pt = b"aa";
    let aad = b"bb";

    let tests = vec![
        // Non-canonical: empty map can just be an empty bstr, not a bstr holding an empty map.
        ("a0", Header::default()),
        // Non-canonical: the map length (of 0) is non-minimally encoded as the 0x00 following
        // 0xb8; it is short enough that it would normally be folded into the type byte
        // (0xa0).
        ("b800", Header::default()),
        // Non-canonical: map not in canonical order.
        (
            concat!(
                "a2", // 2-map
                // The contents of the bstr-encoded header are not in canonical order.
                "04", "42", "3131", // 4 (kid) => 2-bstr "11"
                "01", "26", // 1 (alg) => ES256
            ),
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES256)
                .key_id(vec![0x31, 0x31])
                .build(),
        ),
    ];

    for (protected_data, header) in tests {
        // Build a protected header from a non-canonically encoded input.
        let protected_data = hex::decode(protected_data).unwrap();
        let protected =
            ProtectedHeader::from_cbor_bstr(Value::Bytes(protected_data.clone())).unwrap();
        assert_eq!(protected.header, header);
        assert_eq!(protected.original_data, Some(protected_data));

        // Build a signature whose inputs include the non-canonically encoded protected header.
        let mut sign = CoseSign {
            payload: Some(pt.to_vec()),
            protected: protected.clone(),
            ..Default::default()
        };
        let mut sig = CoseSignature {
            protected: protected.clone(),
            ..Default::default()
        };
        sig.protected = protected.clone();
        sig.signature = signer.sign(&sign.tbs_data(aad, &sig));
        sign.signatures.push(sig.clone());
        let sign_data = sign.to_vec().unwrap();

        // Parsing and verifying this signature should still succeed, because the `ProtectedHeader`
        // includes the wire data and uses it for building the signature input.
        let sign = CoseSign::from_slice(&sign_data).unwrap();
        assert!(sign
            .verify_signature(0, aad, |sig, data| verifier.verify(sig, data))
            .is_ok());

        // However, if we attempt to build the same signature inputs by hand (thus not including the
        // non-canonical wire data)...
        let recreated_sign = CoseSignBuilder::new()
            .protected(protected.header)
            .payload(pt.to_vec())
            .add_signature(sig)
            .build();

        // ...then the transplanted signature will not verify, because the re-building of the
        // signature inputs will use the canonical encoding of the protected header, which
        // is not what was originally used for the signature input.
        assert!(recreated_sign
            .verify_signature(0, aad, |sig, data| verifier.verify(sig, data))
            .is_err());
    }
}

#[test]
fn test_sign_create_result() {
    let signer = FakeSigner {};

    let pt = b"This is the content";
    let aad = b"this is additional data";

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let _sign = CoseSignBuilder::new()
        .protected(protected.clone())
        .payload(pt.to_vec())
        .try_add_created_signature(
            CoseSignatureBuilder::new()
                .protected(protected.clone())
                .build(),
            aad,
            |pt| signer.try_sign(pt),
        )
        .unwrap()
        .build();

    let result = CoseSignBuilder::new()
        .protected(protected.clone())
        .payload(pt.to_vec())
        .try_add_created_signature(
            CoseSignatureBuilder::new().protected(protected).build(),
            aad,
            |pt| signer.fail_sign(pt),
        );
    expect_err(result, "failed");
}

#[test]
#[should_panic]
fn test_sign_sig_index_invalid() {
    let signer = FakeSigner {};
    let verifier = signer;

    let pt = b"This is the content";
    let aad = b"this is additional data";

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let sign = CoseSignBuilder::new()
        .protected(protected)
        .payload(pt.to_vec())
        .add_created_signature(CoseSignatureBuilder::new().build(), aad, |pt| {
            signer.sign(pt)
        })
        .build();

    // Attempt to verify an out-of-range signature
    let _ = sign.verify_signature(sign.signatures.len(), aad, |sig, data| {
        verifier.verify(sig, data)
    });
}

#[test]
fn test_sign1_roundtrip() {
    let signer = FakeSigner {};
    let verifier = signer;

    let pt = b"This is the content";
    let aad = b"this is additional data";

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(pt.to_vec())
        .create_signature(aad, |pt| signer.sign(pt))
        .build();

    let sign1_data = sign1.to_vec().unwrap();
    let mut sign1 = CoseSign1::from_slice(&sign1_data).unwrap();

    assert!(sign1
        .verify_signature(aad, |sig, data| verifier.verify(sig, data))
        .is_ok());

    // Changing an unprotected header leaves the signature valid.
    sign1.unprotected.content_type = Some(ContentType::Text("text/plain".to_owned()));
    assert!(sign1
        .verify_signature(aad, |sig, data| verifier.verify(sig, data))
        .is_ok());

    // Providing a different `aad` means the signature won't validate.
    assert!(sign1
        .verify_signature(b"not aad", |sig, data| verifier.verify(sig, data))
        .is_err());

    // Changing a protected header invalidates the signature.
    sign1.protected.original_data = None;
    sign1.protected.header.content_type = Some(ContentType::Text("text/plain".to_owned()));
    assert!(sign1
        .verify_signature(aad, |sig, data| verifier.verify(sig, data))
        .is_err());
}

#[test]
fn test_sign1_create_result() {
    let signer = FakeSigner {};

    let pt = b"This is the content";
    let aad = b"this is additional data";

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .key_id(b"11".to_vec())
        .build();
    let _sign = CoseSign1Builder::new()
        .protected(protected.clone())
        .payload(pt.to_vec())
        .try_create_signature(aad, |pt| signer.try_sign(pt))
        .unwrap()
        .build();

    let result = CoseSign1Builder::new()
        .protected(protected)
        .payload(pt.to_vec())
        .try_create_signature(aad, |pt| signer.fail_sign(pt));
    expect_err(result, "failed");
}

#[test]
fn test_sign1_noncanonical() {
    let signer = FakeSigner {};
    let verifier = signer;
    let pt = b"aa";
    let aad = b"bb";

    // Build an empty protected header from a non-canonical input of 41a0 rather than 40.
    let protected = ProtectedHeader::from_cbor_bstr(Value::Bytes(vec![0xa0])).unwrap();
    assert_eq!(protected.header, Header::default());
    assert_eq!(protected.original_data, Some(vec![0xa0]));

    // Build a signature whose inputs include the non-canonically encoded protected header.
    let mut sign1 = CoseSign1::default();
    sign1.payload = Some(pt.to_vec());
    sign1.protected = protected.clone();
    sign1.signature = signer.sign(&sign1.tbs_data(aad));
    let sign1_data = sign1.to_vec().unwrap();

    // Parsing and verifying this signature should still succeed, because the `ProtectedHeader`
    // includes the wire data and uses it for building the signature input.
    let sign1 = CoseSign1::from_slice(&sign1_data).unwrap();
    assert!(sign1
        .verify_signature(aad, |sig, data| verifier.verify(sig, data))
        .is_ok());

    // However, if we attempt to build the same signature inputs by hand (thus not including the
    // non-canonical wire data)...
    let recreated_sign1 = CoseSign1Builder::new()
        .protected(protected.header)
        .payload(pt.to_vec())
        .signature(sign1.signature)
        .build();

    // ...then the transplanted signature will not verify, because the re-building of the signature
    // inputs will use the canonical encoding of the protected header, which is not what was
    // originally used for the signature input.
    assert!(recreated_sign1
        .verify_signature(aad, |sig, data| verifier.verify(sig, data))
        .is_err());
}
