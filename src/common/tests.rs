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
use crate::util::expect_err;
use alloc::{borrow::ToOwned, format, vec};
use core::cmp::Ordering;

#[test]
fn test_error_convert() {
    let e = CoseError::from(crate::cbor::ser::Error::<String>::Value(
        "error message lost".to_owned(),
    ));
    match e {
        CoseError::EncodeFailed => {
            assert!(format!("{e:?}").contains("encode CBOR failure"));
            assert!(format!("{e}").contains("encode CBOR failure"));
        }
        _ => panic!("unexpected error enum after conversion"),
    }
}

#[test]
fn test_label_encode() {
    let tests = [
        (Label::Int(2), "02"),
        (Label::Int(-1), "20"),
        (Label::Text("abc".to_owned()), "63616263"),
    ];

    for (i, (label, label_data)) in tests.iter().enumerate() {
        let got = label.clone().to_vec().unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {i}");

        let got = Label::from_slice(&got).unwrap();
        assert_eq!(*label, got);
    }
}

#[test]
fn test_label_sort() {
    // Pairs of `Label`s with the "smaller" first.
    let pairs = vec![
        (Label::Int(0x1234), Label::Text("a".to_owned())),
        (Label::Int(0x1234), Label::Text("ab".to_owned())),
        (Label::Int(0x12345678), Label::Text("ab".to_owned())),
        (Label::Int(0), Label::Text("ab".to_owned())),
        (Label::Int(-1), Label::Text("ab".to_owned())),
        (Label::Int(0), Label::Int(10)),
        (Label::Int(0), Label::Int(-10)),
        (Label::Int(10), Label::Int(-1)),
        (Label::Int(-1), Label::Int(-2)),
        (Label::Int(0x12), Label::Int(0x1234)),
        (Label::Int(0x99), Label::Int(0x1234)),
        (Label::Int(0x1234), Label::Int(0x1235)),
        (Label::Text("a".to_owned()), Label::Text("ab".to_owned())),
        (Label::Text("aa".to_owned()), Label::Text("ab".to_owned())),
        (Label::Int(i64::MAX - 2), Label::Int(i64::MAX - 1)),
        (Label::Int(i64::MAX - 1), Label::Int(i64::MAX)),
        (Label::Int(i64::MIN + 2), Label::Int(i64::MIN + 1)),
        (Label::Int(i64::MIN + 1), Label::Int(i64::MIN)),
    ];
    for (left, right) in pairs.into_iter() {
        let value_cmp = left.cmp(&right);
        let value_partial_cmp = left.partial_cmp(&right);
        let left_data = left.clone().to_vec().unwrap();
        let right_data = right.clone().to_vec().unwrap();
        let data_cmp = left_data.cmp(&right_data);
        let reverse_cmp = right.cmp(&left);
        let equal_cmp = left.cmp(&left);

        assert_eq!(value_cmp, Ordering::Less, "{left:?} < {right:?}");
        assert_eq!(
            value_partial_cmp,
            Some(Ordering::Less),
            "{left:?} < {right:?}",
        );
        assert_eq!(
            data_cmp,
            Ordering::Less,
            "{left:?}={} < {right:?}={}",
            hex::encode(&left_data),
            hex::encode(&right_data)
        );
        assert_eq!(reverse_cmp, Ordering::Greater, "{right:?} > {left:?}");
        assert_eq!(equal_cmp, Ordering::Equal, "{left:?} = {left:?}");
    }
}

#[test]
fn test_label_canonical_sort() {
    // Pairs of `Label`s with the "smaller" first, as per RFC7049 "canonical" ordering.
    let pairs = vec![
        (Label::Text("a".to_owned()), Label::Int(0x1234)), // different than above
        (Label::Int(0x1234), Label::Text("ab".to_owned())),
        (Label::Text("ab".to_owned()), Label::Int(0x12345678)), // different than above
        (Label::Int(0), Label::Text("ab".to_owned())),
        (Label::Int(-1), Label::Text("ab".to_owned())),
        (Label::Int(0), Label::Int(10)),
        (Label::Int(0), Label::Int(-10)),
        (Label::Int(10), Label::Int(-1)),
        (Label::Int(-1), Label::Int(-2)),
        (Label::Int(0x12), Label::Int(0x1234)),
        (Label::Int(0x99), Label::Int(0x1234)),
        (Label::Int(0x1234), Label::Int(0x1235)),
        (Label::Text("a".to_owned()), Label::Text("ab".to_owned())),
        (Label::Text("aa".to_owned()), Label::Text("ab".to_owned())),
    ];
    for (left, right) in pairs.into_iter() {
        let value_cmp = left.cmp_canonical(&right);

        let left_data = left.clone().to_vec().unwrap();
        let right_data = right.clone().to_vec().unwrap();

        let len_cmp = left_data.len().cmp(&right_data.len());
        let data_cmp = left_data.cmp(&right_data);
        let reverse_cmp = right.cmp_canonical(&left);
        let equal_cmp = left.cmp_canonical(&left);

        assert_eq!(
            value_cmp,
            Ordering::Less,
            "{:?} (encoded: {}) < {:?} (encoded: {})",
            left,
            hex::encode(&left_data),
            right,
            hex::encode(&right_data)
        );
        if len_cmp != Ordering::Equal {
            assert_eq!(
                len_cmp,
                Ordering::Less,
                "{:?}={} < {:?}={} by len",
                left,
                hex::encode(&left_data),
                right,
                hex::encode(&right_data)
            );
        } else {
            assert_eq!(
                data_cmp,
                Ordering::Less,
                "{:?}={} < {:?}={} by data",
                left,
                hex::encode(&left_data),
                right,
                hex::encode(&right_data)
            );
        }
        assert_eq!(reverse_cmp, Ordering::Greater, "{right:?} > {left:?}");
        assert_eq!(equal_cmp, Ordering::Equal, "{left:?} = {left:?}");
    }
}

#[test]
fn test_label_decode_fail() {
    let tests = [
        ("43010203", "expected int/tstr"),
        ("", "decode CBOR failure: Io(EndOfFile"),
        ("1e", "decode CBOR failure: Syntax"),
        ("0202", "extraneous data"),
    ];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = Label::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_registered_label_encode() {
    let tests = [
        (RegisteredLabel::Assigned(iana::Algorithm::A192GCM), "02"),
        (RegisteredLabel::Assigned(iana::Algorithm::EdDSA), "27"),
        (RegisteredLabel::Text("abc".to_owned()), "63616263"),
    ];

    for (i, (label, label_data)) in tests.iter().enumerate() {
        let got = label.clone().to_vec().unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {i}");

        let got = RegisteredLabel::from_slice(&got).unwrap();
        assert_eq!(*label, got);
    }
}

#[test]
fn test_registered_label_sort() {
    use RegisteredLabel::{Assigned, Text};
    // Pairs of `RegisteredLabel`s with the "smaller" first.
    let pairs = vec![
        (Assigned(iana::Algorithm::A192GCM), Text("a".to_owned())),
        (Assigned(iana::Algorithm::WalnutDSA), Text("ab".to_owned())),
        (Text("ab".to_owned()), Text("cd".to_owned())),
        (Text("ab".to_owned()), Text("abcd".to_owned())),
        (
            Assigned(iana::Algorithm::AES_CCM_16_64_128),
            Assigned(iana::Algorithm::A128KW),
        ),
        (
            Assigned(iana::Algorithm::A192GCM),
            Assigned(iana::Algorithm::AES_CCM_16_64_128),
        ),
    ];
    for (left, right) in pairs.into_iter() {
        let value_cmp = left.cmp(&right);
        let value_partial_cmp = left.partial_cmp(&right);
        let left_data = left.clone().to_vec().unwrap();
        let right_data = right.clone().to_vec().unwrap();
        let data_cmp = left_data.cmp(&right_data);
        let reverse_cmp = right.cmp(&left);
        let equal_cmp = left.cmp(&left);

        assert_eq!(value_cmp, Ordering::Less, "{left:?} < {right:?}");
        assert_eq!(
            value_partial_cmp,
            Some(Ordering::Less),
            "{left:?} < {right:?}",
        );
        assert_eq!(
            data_cmp,
            Ordering::Less,
            "{left:?}={} < {right:?}={}",
            hex::encode(&left_data),
            hex::encode(&right_data)
        );
        assert_eq!(reverse_cmp, Ordering::Greater, "{right:?} > {left:?}");
        assert_eq!(equal_cmp, Ordering::Equal, "{left:?} = {left:?}");
    }
}

#[test]
fn test_registered_label_decode_fail() {
    let tests = [
        ("43010203", "expected int/tstr"),
        ("", "decode CBOR failure: Io(EndOfFile"),
        ("09", "expected recognized IANA value"),
        ("394e1f", "expected recognized IANA value"),
    ];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = RegisteredLabel::<iana::EllipticCurve>::from_slice(&data);
        expect_err(result, err_msg);
    }
}

iana_registry! {
    TestPrivateLabel {
        Reserved: 0,
        Something: 1,
    }
}

impl WithPrivateRange for TestPrivateLabel {
    fn is_private(i: i64) -> bool {
        i > 10 || i < 1000
    }
}

#[test]
fn test_registered_label_with_private_encode() {
    let tests = [
        (
            RegisteredLabelWithPrivate::Assigned(TestPrivateLabel::Something),
            "01",
        ),
        (
            RegisteredLabelWithPrivate::Text("abc".to_owned()),
            "63616263",
        ),
        (
            RegisteredLabelWithPrivate::PrivateUse(-70_000),
            "3a0001116f",
        ),
        (RegisteredLabelWithPrivate::PrivateUse(11), "0b"),
    ];

    for (i, (label, label_data)) in tests.iter().enumerate() {
        let got = label.clone().to_vec().unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {i}");

        let got = RegisteredLabelWithPrivate::from_slice(&got).unwrap();
        assert_eq!(*label, got);
    }
}

#[test]
fn test_registered_label_with_private_sort() {
    use RegisteredLabelWithPrivate::{Assigned, PrivateUse, Text};
    // Pairs of `RegisteredLabelWithPrivate`s with the "smaller" first.
    let pairs = vec![
        (Assigned(iana::Algorithm::A192GCM), Text("a".to_owned())),
        (Assigned(iana::Algorithm::WalnutDSA), Text("ab".to_owned())),
        (Text("ab".to_owned()), Text("cd".to_owned())),
        (Text("ab".to_owned()), Text("abcd".to_owned())),
        (
            Assigned(iana::Algorithm::AES_CCM_16_64_128),
            Assigned(iana::Algorithm::A128KW),
        ),
        (
            Assigned(iana::Algorithm::A192GCM),
            Assigned(iana::Algorithm::AES_CCM_16_64_128),
        ),
        (
            Assigned(iana::Algorithm::AES_CCM_16_64_128),
            PrivateUse(-70_000),
        ),
        (PrivateUse(-70_000), PrivateUse(-70_001)),
        (PrivateUse(-70_000), Text("a".to_owned())),
    ];
    for (left, right) in pairs.into_iter() {
        let value_cmp = left.cmp(&right);
        let value_partial_cmp = left.partial_cmp(&right);
        let left_data = left.clone().to_vec().unwrap();
        let right_data = right.clone().to_vec().unwrap();
        let data_cmp = left_data.cmp(&right_data);
        let reverse_cmp = right.cmp(&left);
        let equal_cmp = left.cmp(&left);

        assert_eq!(value_cmp, Ordering::Less, "{left:?} < {right:?}");
        assert_eq!(
            value_partial_cmp,
            Some(Ordering::Less),
            "{left:?} < {right:?}",
        );
        assert_eq!(
            data_cmp,
            Ordering::Less,
            "{left:?}={} < {right:?}={}",
            hex::encode(&left_data),
            hex::encode(&right_data)
        );
        assert_eq!(reverse_cmp, Ordering::Greater, "{right:?} > {left:?}");
        assert_eq!(equal_cmp, Ordering::Equal, "{left:?} = {left:?}");
    }
}

#[test]
fn test_registered_label_with_private_decode_fail() {
    let tests = [
        ("43010203", "expected int/tstr"),
        ("", "decode CBOR failure: Io(EndOfFile"),
        ("09", "expected value in IANA or private use range"),
        ("394e1f", "expected value in IANA or private use range"),
    ];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = RegisteredLabelWithPrivate::<iana::Algorithm>::from_slice(&data);
        expect_err(result, err_msg);
    }
}

// The most negative integer value that can be encoded in CBOR is:
//    0x3B (0b001_11011) 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
// which is -18_446_744_073_709_551_616 (-1 - 18_446_744_073_709_551_615).
//
// However, this crate uses `i64` for all integers, which cannot hold
// negative values below `i64::MIN` (=-2^63 = 0x8000000000000000).
const CBOR_NINT_MIN_HEX: &str = "3b7fffffffffffffff";
const CBOR_NINT_OUT_OF_RANGE_HEX: &str = "3b8000000000000000";

// The largest positive integer value that can be encoded in CBOR is:
//    0x1B (0b000_11011) 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
// which is 18_446_744_073_709_551_615.
//
// However, this crate uses `i64` for all integers, which cannot hold
// positive values above `i64::MAX` (=-2^63 - 1 = 0x7fffffffffffffff).
const CBOR_INT_MAX_HEX: &str = "1b7fffffffffffffff";
const CBOR_INT_OUT_OF_RANGE_HEX: &str = "1b8000000000000000";

#[test]
fn test_large_label_decode() {
    let tests = [(CBOR_NINT_MIN_HEX, i64::MIN), (CBOR_INT_MAX_HEX, i64::MAX)];
    for (label_data, want) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let got = Label::from_slice(&data).unwrap();
        assert_eq!(got, Label::Int(*want))
    }
}

#[test]
fn test_large_label_decode_fail() {
    let tests = [
        (CBOR_NINT_OUT_OF_RANGE_HEX, "out of range integer value"),
        (CBOR_INT_OUT_OF_RANGE_HEX, "out of range integer value"),
    ];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = Label::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_large_registered_label_decode_fail() {
    let tests = [
        (CBOR_NINT_OUT_OF_RANGE_HEX, "out of range integer value"),
        (CBOR_INT_OUT_OF_RANGE_HEX, "out of range integer value"),
    ];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = RegisteredLabel::<crate::iana::HeaderParameter>::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_large_registered_label_with_private_decode_fail() {
    let tests = [
        (CBOR_NINT_OUT_OF_RANGE_HEX, "out of range integer value"),
        (CBOR_INT_OUT_OF_RANGE_HEX, "out of range integer value"),
    ];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = RegisteredLabelWithPrivate::<crate::iana::HeaderParameter>::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_as_cbor_value() {
    let cases = [
        Value::Null,
        Value::Bool(true),
        Value::Bool(false),
        Value::from(128),
        Value::from(-1),
        Value::Bytes(vec![1, 2]),
        Value::Text("string".to_owned()),
        Value::Array(vec![Value::from(0)]),
        Value::Map(vec![]),
        Value::Tag(1, Box::new(Value::from(0))),
        Value::Float(1.054571817),
    ];
    for val in cases {
        assert_eq!(val, Value::from_cbor_value(val.clone()).unwrap());
        assert_eq!(val, val.clone().to_cbor_value().unwrap());
    }
}
