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
use crate::{iana, util::expect_err, Algorithm, CborSerializable};
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
