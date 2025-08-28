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
use crate::{cbor::value::Value, iana, iana::WithPrivateRange, util::expect_err, CborSerializable};
use alloc::{borrow::ToOwned, vec};

#[test]
fn test_cwt_encode() {
    let tests = vec![
        (
            ClaimsSet {
                issuer: Some("abc".to_owned()),
                ..Default::default()
            },
            concat!(
                "a1", // 1-map
                "01", "63", "616263" // 1 (iss) => 3-tstr
            ),
        ),
        (ClaimsSetBuilder::new().build(), "a0"),
        (
            ClaimsSetBuilder::new()
                .issuer("aaa".to_owned())
                .subject("bb".to_owned())
                .audience("c".to_owned())
                .expiration_time(Timestamp::WholeSeconds(0x100))
                .not_before(Timestamp::WholeSeconds(0x200))
                .issued_at(Timestamp::WholeSeconds(0x10))
                .cwt_id(vec![1, 2, 3, 4])
                .private_claim(-70_000, Value::Integer(0.into()))
                .build(),
            concat!(
                "a8", // 8-map
                "01",
                "63",
                "616161", // 1 (iss) => 3-tstr
                "02",
                "62",
                "6262", // 2 (sub) => 2-tstr
                "03",
                "61",
                "63", // 3 (aud) => 1-tstr
                "04",
                "19",
                "0100", // 4 (exp) => uint
                "05",
                "19",
                "0200", // 5 (nbf) => uint
                "06",
                "10", // 6 (iat) => uint
                "07",
                "44",
                "01020304", // 7 => bstr
                "3a0001116f",
                "00" // -70000 => uint
            ),
        ),
        (
            ClaimsSetBuilder::new()
                .claim(
                    iana::CwtClaimName::Cnf,
                    Value::Map(vec![(Value::Integer(0.into()), Value::Integer(0.into()))]),
                )
                .build(),
            concat!(
                "a1", // 1-map
                "08", "a1", "00", "00"
            ),
        ),
        (
            ClaimsSetBuilder::new()
                .text_claim("aa".to_owned(), Value::Integer(0.into()))
                .build(),
            concat!(
                "a1", // 1-map
                "62", "6161", "00",
            ),
        ),
        (
            ClaimsSetBuilder::new()
                .expiration_time(Timestamp::FractionalSeconds(1.5))
                .build(),
            concat!(
                "a1", // 1-map
                "04", // 4 (exp) =>
                // Note: ciborium serializes floats as the smallest float type that
                // will parse back to the original f64!  As a result, 1.5 is encoded
                // as an f16.
                "f9", "3e00",
            ),
        ),
    ];
    for (i, (claims, claims_data)) in tests.iter().enumerate() {
        let got = claims.clone().to_vec().unwrap();
        assert_eq!(*claims_data, hex::encode(&got), "case {i}");

        let got = ClaimsSet::from_slice(&got).unwrap();
        assert_eq!(*claims, got);
    }
}

#[test]
fn test_cwt_decode_fail() {
    let tests = vec![
        (
            concat!(
                "81", // 1-arr
                "01",
            ),
            "expected map",
        ),
        (
            concat!(
                "a1", // 1-map
                "01", "08", // 1 (iss) => int (invalid value type)
            ),
            "expected tstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "02", "08", // 2 (sub) => int (invalid value type)
            ),
            "expected tstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "03", "08", // 3 (aud) => int (invalid value type)
            ),
            "expected tstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "04", "40", // 4 (exp) => bstr (invalid value type)
            ),
            "expected int/float",
        ),
        (
            concat!(
                "a1", // 1-map
                "05", "40", // 5 (nbf) => bstr (invalid value type)
            ),
            "expected int/float",
        ),
        (
            concat!(
                "a1", // 1-map
                "06", "40", // 6 (iat) => bstr (invalid value type)
            ),
            "expected int/float",
        ),
        (
            concat!(
                "a1", // 1-map
                "07", "01", // 5 (cti) => uint (invalid value type)
            ),
            "expected bstr",
        ),
        (
            concat!(
                "a1", // 1-map
                "07", "40", // 5 (cti) => 0-bstr
                "06", "01", // 6 (iat) => 1
            ),
            "extraneous data",
        ),
        (
            concat!(
                "a2", // 1-map
                "07", "40", // 5 (cti) => 0-bstr
                "07", "40", // 5 (cti) => 0-bstr
            ),
            "duplicate map key",
        ),
    ];
    for (claims_data, err_msg) in tests.iter() {
        let data = hex::decode(claims_data).unwrap();
        let result = ClaimsSet::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cwt_is_private() {
    assert!(!iana::CwtClaimName::is_private(1));
    assert!(iana::CwtClaimName::is_private(-500_000));
}

#[test]
#[should_panic]
fn test_cwt_claims_builder_core_param_panic() {
    // Attempting to set a core claim (in range [1,7]) via `.claim()` panics.
    let _claims = ClaimsSetBuilder::new()
        .claim(iana::CwtClaimName::Iss, Value::Null)
        .build();
}

#[test]
#[should_panic]
fn test_cwt_claims_builder_non_private_panic() {
    // Attempting to set a claim outside of private range via `.private_claim()` panics.
    let _claims = ClaimsSetBuilder::new()
        .private_claim(100, Value::Null)
        .build();
}

#[test]
fn test_cwt_dup_claim() {
    // Set a duplicate map key.
    let claims = ClaimsSetBuilder::new()
        .claim(iana::CwtClaimName::AceProfile, Value::Integer(1.into()))
        .claim(iana::CwtClaimName::AceProfile, Value::Integer(2.into()))
        .build();
    // Encoding succeeds.
    let data = claims.to_vec().unwrap();
    // But an attempt to parse the encoded data fails.
    let result = ClaimsSet::from_slice(&data);
    expect_err(result, "duplicate map key");
}
