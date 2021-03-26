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

#[test]
fn test_label_encode() {
    let tests = vec![
        (Label::Int(2), "02"),
        (Label::Int(-1), "20"),
        (Label::Text("abc".to_owned()), "63616263"),
    ];

    for (i, (label, label_data)) in tests.iter().enumerate() {
        let got = label.to_vec().unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {}", i);

        let got = Label::from_slice(&got).unwrap();
        assert_eq!(*label, got);

        // Also exercise the `Read` / `Write` versions.
        let mut got = vec![];
        label.to_writer(&mut got).unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {}", i);

        let got = Label::from_reader(std::io::Cursor::new(&got)).unwrap();
        assert_eq!(*label, got);
    }
}

#[test]
fn test_label_sort() {
    // Pairs of `Label`s with the "smaller" first.
    let pairs = vec![
        (Label::Int(0x1234), Label::Text("a".to_owned())),
        (Label::Int(0x1234), Label::Text("ab".to_owned())),
        (Label::Int(10), Label::Int(-1)),
        (Label::Int(0x12), Label::Int(0x1234)),
        (Label::Int(0x99), Label::Int(0x1234)),
        (Label::Int(0x1234), Label::Int(0x1235)),
    ];
    for (left, right) in pairs.into_iter() {
        let value_cmp = left.cmp(&right);
        let value_partial_cmp = left.partial_cmp(&right);
        let left_data = cbor::to_vec(&left).unwrap();
        let right_data = cbor::to_vec(&right).unwrap();
        let data_cmp = left_data.cmp(&right_data);

        assert_eq!(value_cmp, std::cmp::Ordering::Less);
        assert_eq!(value_partial_cmp, Some(std::cmp::Ordering::Less));
        assert_eq!(data_cmp, std::cmp::Ordering::Less);
    }
}

#[test]
fn test_label_decode_fail() {
    let tests = vec![("43010203", "expected int/tstr"), ("", "EofWhileParsing")];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = Label::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_registered_label_encode() {
    let tests = vec![
        (RegisteredLabel::Assigned(iana::Algorithm::A192GCM), "02"),
        (RegisteredLabel::Text("abc".to_owned()), "63616263"),
    ];

    for (i, (label, label_data)) in tests.iter().enumerate() {
        let got = label.to_vec().unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {}", i);

        let got = RegisteredLabel::from_slice(&got).unwrap();
        assert_eq!(*label, got);

        // Also exercise the `Read` / `Write` versions.
        let mut got = vec![];
        label.to_writer(&mut got).unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {}", i);

        let got = RegisteredLabel::from_reader(std::io::Cursor::new(&got)).unwrap();
        assert_eq!(*label, got);
    }
}

#[test]
fn test_registered_label_sort() {
    // Pairs of `RegisteredLabel`s with the "smaller" first.
    let pairs = vec![
        (
            RegisteredLabel::Assigned(iana::Algorithm::A192GCM),
            RegisteredLabel::Text("a".to_owned()),
        ),
        (
            RegisteredLabel::Assigned(iana::Algorithm::WalnutDSA),
            RegisteredLabel::Text("ab".to_owned()),
        ),
        (
            RegisteredLabel::Assigned(iana::Algorithm::AES_CCM_16_64_128),
            RegisteredLabel::Assigned(iana::Algorithm::A128KW),
        ),
        (
            RegisteredLabel::Assigned(iana::Algorithm::A192GCM),
            RegisteredLabel::Assigned(iana::Algorithm::AES_CCM_16_64_128),
        ),
    ];
    for (left, right) in pairs.into_iter() {
        let value_cmp = left.cmp(&right);
        let value_partial_cmp = left.partial_cmp(&right);
        let left_data = cbor::to_vec(&left).unwrap();
        let right_data = cbor::to_vec(&right).unwrap();
        let data_cmp = left_data.cmp(&right_data);

        assert_eq!(value_cmp, std::cmp::Ordering::Less);
        assert_eq!(value_partial_cmp, Some(std::cmp::Ordering::Less));
        assert_eq!(data_cmp, std::cmp::Ordering::Less);
    }
}

#[test]
fn test_registered_label_decode_fail() {
    let tests = vec![
        ("43010203", "expected int/tstr"),
        ("", "EofWhileParsing"),
        ("09", "expected recognized IANA value"),
    ];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = RegisteredLabel::<iana::EllipticCurve>::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_registered_label_with_private_encode() {
    let tests = vec![
        (
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A192GCM),
            "02",
        ),
        (
            RegisteredLabelWithPrivate::Text("abc".to_owned()),
            "63616263",
        ),
        (
            RegisteredLabelWithPrivate::PrivateUse(-70_000),
            "3a0001116f",
        ),
    ];

    for (i, (label, label_data)) in tests.iter().enumerate() {
        let got = label.to_vec().unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {}", i);

        let got = RegisteredLabelWithPrivate::from_slice(&got).unwrap();
        assert_eq!(*label, got);

        // Also exercise the `Read` / `Write` versions.
        let mut got = vec![];
        label.to_writer(&mut got).unwrap();
        assert_eq!(*label_data, hex::encode(&got), "case {}", i);

        let got = RegisteredLabelWithPrivate::from_reader(std::io::Cursor::new(&got)).unwrap();
        assert_eq!(*label, got);
    }
}

#[test]
fn test_registered_label_with_private_sort() {
    // Pairs of `RegisteredLabelWithPrivate`s with the "smaller" first.
    let pairs = vec![
        (
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A192GCM),
            RegisteredLabelWithPrivate::Text("a".to_owned()),
        ),
        (
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::WalnutDSA),
            RegisteredLabelWithPrivate::Text("ab".to_owned()),
        ),
        (
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::AES_CCM_16_64_128),
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A128KW),
        ),
        (
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A192GCM),
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::AES_CCM_16_64_128),
        ),
        (
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::AES_CCM_16_64_128),
            RegisteredLabelWithPrivate::PrivateUse(-70_000),
        ),
    ];
    for (left, right) in pairs.into_iter() {
        let value_cmp = left.cmp(&right);
        let value_partial_cmp = left.partial_cmp(&right);
        let left_data = cbor::to_vec(&left).unwrap();
        let right_data = cbor::to_vec(&right).unwrap();
        let data_cmp = left_data.cmp(&right_data);

        assert_eq!(value_cmp, std::cmp::Ordering::Less);
        assert_eq!(value_partial_cmp, Some(std::cmp::Ordering::Less));
        assert_eq!(data_cmp, std::cmp::Ordering::Less);
    }
}

#[test]
fn test_registered_label_with_private_decode_fail() {
    let tests = vec![
        ("43010203", "expected int/tstr"),
        ("", "EofWhileParsing"),
        ("09", "expected value in IANA or private use range"),
    ];
    for (label_data, err_msg) in tests.iter() {
        let data = hex::decode(label_data).unwrap();
        let result = RegisteredLabelWithPrivate::<iana::Algorithm>::from_slice(&data);
        expect_err(result, err_msg);
    }
}
