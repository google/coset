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
    cbor::values::{SimpleValue, Value},
    iana,
    util::expect_err,
    CborSerializable, Label,
};
use alloc::{borrow::ToOwned, vec};

// The most negative integer value that can be encoded in CBOR is:
//    0x3B (0b001_11011) 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
// which is -18_446_744_073_709_551_616 (-1 - 18_446_744_073_709_551_615).
//
// However, the underlying sk-cbor crate encodes negative integers as:
//    Value::Negative(i64)
// meaning that the most negative integer available in practice is
//    i64::MIN = -9_223_372_036_854_775_808
// which is 0x8000000000000000 in hex, and which CBOR-encodes as:
//    0x3b 0x7fffffffffffffff
const MOST_NEGATIVE_NINT: i128 = i64::MIN as i128;

#[test]
fn test_header_encode() {
    let tests = vec![
        (
            Header {
                alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                key_id: vec![1, 2, 3],
                partial_iv: vec![1, 2, 3],
                ..Default::default()
            },
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (alg) => A128GCM
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "06", "43", "010203", // 6 (partial-iv) => 3-bstr
            ),
        ),
        (
            Header {
                alg: Some(Algorithm::PrivateUse(MOST_NEGATIVE_NINT)),
                ..Default::default()
            },
            concat!(
                "a1", // 1-map
                "01",
                "3b7fffffffffffffff", // 1 (alg) => -lots
            ),
        ),
        (
            Header {
                alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                crit: vec![RegisteredLabel::Assigned(iana::HeaderParameter::Alg)],
                content_type: Some(ContentType::Assigned(iana::CoapContentFormat::CoseEncrypt0)),
                key_id: vec![1, 2, 3],
                iv: vec![1, 2, 3],
                rest: vec![
                    (Label::Int(0x46), Value::Unsigned(0x47)),
                    (Label::Int(0x66), Value::Unsigned(0x67)),
                ],
                ..Default::default()
            },
            concat!(
                "a7", // 7-map
                "01", "01", // 1 (alg) => A128GCM
                "02", "81", "01", // 2 (crit) => 1-arr [x01]
                "03", "10", // 3 (content-type) => 16
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "05", "43", "010203", // 5 (iv) => 3-bstr
                "1846", "1847", // 46 => 47  (note canonical ordering)
                "1866", "1867", // 66 => 67
            ),
        ),
        (
            Header {
                alg: Some(Algorithm::Text("abc".to_owned())),
                crit: vec![RegisteredLabel::Text("d".to_owned())],
                content_type: Some(ContentType::Text("a/b".to_owned())),
                key_id: vec![1, 2, 3],
                iv: vec![1, 2, 3],
                rest: vec![
                    (Label::Int(0x46), Value::Unsigned(0x47)),
                    (Label::Text("a".to_owned()), Value::Unsigned(0x47)),
                ],
                counter_signatures: vec![CoseSignature {
                    signature: vec![1, 2, 3],
                    ..Default::default()
                }],
                ..Default::default()
            },
            concat!(
                "a8", // 8-map
                "01", "63616263", // 1 (alg) => "abc"
                "02", "81", "6164", // 2 (crit) => 1-arr ["d"]
                "03", "63612f62", // 3 (content-type) => "a/b"
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "05", "43", "010203", // 5 (iv) => 3-bstr
                "07", "83", // 7 (sig) => [3-arr for COSE_Signature
                "40", "a0", "43010203", // ]
                "1846", "1847", // 46 => 47  (note canonical ordering)
                "6161", "1847", // "a" => 47
            ),
        ),
        (
            Header {
                alg: Some(Algorithm::Text("abc".to_owned())),
                crit: vec![RegisteredLabel::Text("d".to_owned())],
                content_type: Some(ContentType::Text("a/b".to_owned())),
                key_id: vec![1, 2, 3],
                iv: vec![1, 2, 3],
                rest: vec![
                    (Label::Int(0x46), Value::Unsigned(0x47)),
                    (Label::Text("a".to_owned()), Value::Unsigned(0x47)),
                ],
                counter_signatures: vec![
                    CoseSignature {
                        signature: vec![1, 2, 3],
                        ..Default::default()
                    },
                    CoseSignature {
                        signature: vec![3, 4, 5],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            concat!(
                "a8", // 8-map
                "01", "63616263", // 1 (alg) => "abc"
                "02", "81", "6164", // 2 (crit) => 1-arr ["d"]
                "03", "63612f62", // 3 (content-type) => "a/b"
                "04", "43", "010203", // 4 (kid) => 3-bstr
                "05", "43", "010203", // 5 (iv) => 3-bstr
                "07", "82", // 7 (sig) => 2-array
                "83", "40", "a0", "43010203", // [3-arr for COSE_Signature]
                "83", "40", "a0", "43030405", // [3-arr for COSE_Signature]
                "1846", "1847", // 46 => 47  (note canonical ordering)
                "6161", "1847", // "a" => 47
            ),
        ),
        (
            HeaderBuilder::new()
                .add_critical(iana::HeaderParameter::Alg)
                .add_critical(iana::HeaderParameter::Alg)
                .build(),
            concat!(
                "a1", // 1-map
                "02", "820101", // crit => 2-arr [1, 1]
            ),
        ),
    ];
    for (i, (header, header_data)) in tests.iter().enumerate() {
        let got = header.clone().to_vec().unwrap();
        assert_eq!(*header_data, hex::encode(&got), "case {}", i);

        let got = Header::from_slice(&got).unwrap();
        assert_eq!(*header, got);
        assert!(!got.is_empty());
    }
}

#[test]
fn test_header_decode_fail() {
    let tests = vec![
        (
            concat!(
                "a1", // 1-map
                "01", "08", // 1 (alg) => invalid value
            ),
            "expected value in IANA or private use range",
        ),
        (
            concat!(
                "a1", // 1-map
                "01", "4101", // 1 (alg) => bstr (invalid value type)
            ),
            "expected int/tstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "02", "4101", // 2 (crit) => bstr (invalid value type)
            ),
            "expected array",
        ),
        (
            concat!(
                "a1", // 1-map
                "02", "81", "4101", // 2 (crit) => [bstr] (invalid value type)
            ),
            "expected int/tstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "02", "80", // 2 (crit) => []
            ),
            "expected non-empty array",
        ),
        (
            concat!(
                "a1", // 1-map
                "03", "81", "4101", // 3 (content-type) => [bstr] (invalid value type)
            ),
            "expected int/tstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "03", "19", "0606", // 3 (content-type) => invalid value 1542
            ),
            "expected recognized IANA value",
        ),
        (
            concat!(
                "a1", // 1-map
                "03", "64", "20612f62" // 3 (content-type) => invalid value " a/b"
            ),
            "expected no leading/trailing whitespace",
        ),
        (
            concat!(
                "a1", // 1-map
                "03", "64", "612f6220" // 3 (content-type) => invalid value "a/b "
            ),
            "expected no leading/trailing whitespace",
        ),
        (
            concat!(
                "a1", // 1-map
                "03", "62", "6162" // 3 (content-type) => invalid value "ab"
            ),
            "expected text of form type/subtype",
        ),
        (
            concat!(
                "a1", // 1-map
                "03", "60", // 3 (content-type) => invalid value ""
            ),
            "expected non-empty tstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "04", "40", // 4 (key-id) => 0-bstr
            ),
            "expected non-empty bstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "04", "01", // 4 (key-id) => invalid value type
            ),
            "expected bstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "05", "40", // 5 (iv) => 0-bstr
            ),
            "expected non-empty bstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "05", "01", // 5 (iv) => invalid value type
            ),
            "expected bstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "06", "40", // 6 (partial-iv) => 0-bstr
            ),
            "expected non-empty bstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "06", "01", // 6 (partial-iv) => invalid value type
            ),
            "expected bstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "07", "01", // 7 (counter-sig) => invalid value type
            ),
            "expected array value",
        ),
        (
            concat!(
                "a1", // 1-map
                "07", "80", // 7 (counter-sig) => 0-arr
            ),
            "expected non-empty sig array",
        ),
        (
            concat!(
                "a2", // 1-map
                "05", "4101", // 5 (iv) => 1-bstr
                "06", "4101", // 6 (partial-iv) => 1-bstr
            ),
            "expected only one of IV and partial IV",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "63616263", // 1 (alg) => "abc"
                "07", "82",       // 7 (sig) => 2-array
                "63616263", // tstr (invalid)
                "83", "40", "a0", "43010203", // [3-arr for COSE_Signature]
            ),
            "array or bstr value",
        ),
    ];
    for (header_data, err_msg) in tests.iter() {
        let data = hex::decode(header_data).unwrap();
        let result = Header::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_header_decode_dup_fail() {
    let tests = vec![
        (
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (alg) => A128GCM
                "1866", "1867", // 66 => 67
                "1866", "1847", // 66 => 47
            ),
            "OutOfOrderKey",
        ),
        (
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (alg) => A128GCM
                "1866", "1867", // 66 => 67
                "01", "01", // 1 (alg) => A128GCM (duplicate label)
            ),
            "OutOfOrderKey",
        ),
    ];
    for (header_data, err_msg) in tests.iter() {
        let data = hex::decode(header_data).unwrap();
        let result = Header::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_header_encode_dup_fail() {
    let tests = vec![
        Header {
            alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
            crit: vec![RegisteredLabel::Assigned(iana::HeaderParameter::Alg)],
            content_type: Some(ContentType::Assigned(iana::CoapContentFormat::CoseEncrypt0)),
            key_id: vec![1, 2, 3],
            iv: vec![1, 2, 3],
            rest: vec![
                (Label::Int(0x46), Value::Unsigned(0x47)),
                (Label::Int(0x46), Value::Unsigned(0x67)),
            ],
            ..Default::default()
        },
        HeaderBuilder::new()
            .text_value("doop".to_owned(), Value::Unsigned(1))
            .text_value("doop".to_owned(), Value::Unsigned(2))
            .build(),
    ];
    for header in tests {
        let result = header.clone().to_vec();
        expect_err(result, "encode CBOR failure");
    }
}

#[test]
fn test_header_encode_int_out_of_range_fail() {
    // Unfortunately, it is possible to build Rust COSE structures that hold values that cannot be
    // serialized to CBOR -- we use i128 for integer values for convenience, but the
    // serializable range is more like an i65 (!) in theory and [i64::MIN, u64::MAX] in
    // practice.
    let header = HeaderBuilder::new()
        .value(
            0x10000000000000000i128,
            Value::TextString("boom!".to_owned()),
        )
        .build();
    let result = header.to_vec();
    expect_err(result, "expected u64");

    let header = Header {
        // "What we do, is if we need that extra push over the cliff, you know what we do?"
        alg: Some(Algorithm::PrivateUse(MOST_NEGATIVE_NINT - 1)),
        ..Default::default()
    };
    let result = header.to_vec();
    expect_err(result, "expected i64");
}

#[test]
fn test_header_builder() {
    let tests = vec![
        (
            HeaderBuilder::new().build(),
            Header {
                ..Default::default()
            },
        ),
        (
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::A128GCM)
                .add_critical(iana::HeaderParameter::Alg)
                .add_critical_label(RegisteredLabel::Text("abc".to_owned()))
                .content_format(iana::CoapContentFormat::CoseEncrypt0)
                .key_id(vec![1, 2, 3])
                .partial_iv(vec![4, 5, 6]) // removed by .iv() call
                .iv(vec![1, 2, 3])
                .value(0x46, Value::Unsigned(0x47))
                .value(0x66, Value::Unsigned(0x67))
                .build(),
            Header {
                alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                crit: vec![
                    RegisteredLabel::Assigned(iana::HeaderParameter::Alg),
                    RegisteredLabel::Text("abc".to_owned()),
                ],
                content_type: Some(ContentType::Assigned(iana::CoapContentFormat::CoseEncrypt0)),
                key_id: vec![1, 2, 3],
                iv: vec![1, 2, 3],
                rest: vec![
                    (Label::Int(0x46), Value::Unsigned(0x47)),
                    (Label::Int(0x66), Value::Unsigned(0x67)),
                ],
                ..Default::default()
            },
        ),
        (
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::A128GCM)
                .add_critical(iana::HeaderParameter::Alg)
                .add_critical_label(RegisteredLabel::Text("abc".to_owned()))
                .content_type("type/subtype".to_owned())
                .key_id(vec![1, 2, 3])
                .iv(vec![1, 2, 3]) // removed by .partial_iv() call
                .partial_iv(vec![4, 5, 6])
                .build(),
            Header {
                alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                crit: vec![
                    RegisteredLabel::Assigned(iana::HeaderParameter::Alg),
                    RegisteredLabel::Text("abc".to_owned()),
                ],
                content_type: Some(ContentType::Text("type/subtype".to_owned())),
                key_id: vec![1, 2, 3],
                partial_iv: vec![4, 5, 6],
                ..Default::default()
            },
        ),
    ];
    for (got, want) in tests {
        assert_eq!(got, want);
    }
}

#[test]
#[should_panic]
fn test_header_builder_core_param_panic() {
    // Attempting to set a core header parameter (in range [1,7]) via `.param()` panics.
    let _hdr = HeaderBuilder::new()
        .value(1, Value::Simple(SimpleValue::NullValue))
        .build();
}
