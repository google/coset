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
use crate::{iana, util::expect_err, Algorithm, CborSerializable, TaggedCborSerializable};
use serde_cbor as cbor;

#[test]
fn test_cose_signature_encode() {
    let tests = vec![
        (
            CoseSignature {
                ..Default::default()
            },
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
                protected: Header {
                    alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                    kid: vec![1, 2, 3],
                    partial_iv: vec![1, 2, 3],
                    ..Default::default()
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
                    kid: vec![1, 2, 3],
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
        let got = cbor::ser::to_vec(&sig).unwrap();
        assert_eq!(*sig_data, hex::encode(&got), "case {}", i);

        let got = CoseSignature::from_slice(&got).unwrap();
        assert_eq!(*sig, got);
    }
}

#[test]
fn test_cose_signature_decode_fail() {
    let tests = vec![
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
    ];
    for (sig_data, err_msg) in tests.iter() {
        let data = hex::decode(sig_data).unwrap();
        let result = CoseSignature::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_sign_encode() {
    let tests = vec![
        (
            CoseSign {
                payload: Some(vec![]),
                ..Default::default()
            },
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "80", // 0-tuple
            ),
        ),
        (
            CoseSign {
                payload: None,
                signatures: vec![CoseSignature::default()],
                ..Default::default()
            },
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
                "81", // 1-tuple
                "83", "40a040", // 3-tuple
            ),
        ),
    ];
    for (i, (sign, sign_data)) in tests.iter().enumerate() {
        let got = cbor::ser::to_vec(&sign).unwrap();
        assert_eq!(*sign_data, hex::encode(&got), "case {}", i);

        let got = CoseSign::from_slice(&got).unwrap();
        assert_eq!(*sign, got);

        // Repeat with tagged variant.
        let got = sign.to_tagged_vec().unwrap();
        let want_hex = format!("d862{}", sign_data);
        assert_eq!(want_hex, hex::encode(&got), "tagged case {}", i);

        let got = CoseSign::from_tagged_slice(&got).unwrap();
        assert_eq!(*sign, got);
    }
}

#[test]
fn test_cose_sign_decode_fail() {
    let tests = vec![
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
            "expected registered tag prefix",
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
            "expected registered tag prefix",
        ),
        (
            concat!(
                "18",     // incomplete int
            ),
            "expected registered tag prefix",
        ),
    ];
    for (sign_data, err_msg) in tests.iter() {
        let data = hex::decode(sign_data).unwrap();
        let result = CoseSign::from_tagged_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_sign1_encode() {
    let tests = vec![
        (
            CoseSign1 {
                payload: Some(vec![]),
                ..Default::default()
            },
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
            ),
        ),
        (
            CoseSign1 {
                payload: None,
                signature: vec![1, 2, 3],
                ..Default::default()
            },
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
                "43", "010203", // 3-bstr
            ),
        ),
    ];
    for (i, (sign, sign_data)) in tests.iter().enumerate() {
        let got = cbor::ser::to_vec(&sign).unwrap();
        assert_eq!(*sign_data, hex::encode(&got), "case {}", i);

        let got = CoseSign1::from_slice(&got).unwrap();
        assert_eq!(*sign, got);

        // Repeat with tagged variant.
        let got = sign.to_tagged_vec().unwrap();
        let want_hex = format!("d2{}", sign_data);
        assert_eq!(want_hex, hex::encode(&got), "tagged case {}", i);

        let got = CoseSign1::from_tagged_slice(&got).unwrap();
        assert_eq!(*sign, got);
    }
}

#[test]
fn test_cose_sign1_decode_fail() {
    let tests = vec![
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
    ];
    for (sign_data, err_msg) in tests.iter() {
        let data = hex::decode(sign_data).unwrap();
        let result = CoseSign1::from_slice(&data);
        expect_err(result, err_msg);
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
            "expected registered tag prefix",
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
            "expected registered tag prefix",
        ),
        (
            concat!(
                "12",     // incomplete int
            ),
            "expected registered tag prefix",
        ),
    ];
    for (sign_data, err_msg) in tests.iter() {
        let data = hex::decode(sign_data).unwrap();
        let result = CoseSign1::from_tagged_slice(&data);
        expect_err(result, err_msg);
    }
}
