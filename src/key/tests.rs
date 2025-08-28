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
use crate::{cbor::value::Value, iana, util::expect_err, CborOrdering, CborSerializable};
use alloc::{borrow::ToOwned, string::ToString, vec};

#[test]
fn test_cose_key_encode() {
    let tests = vec![
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                key_id: vec![1, 2, 3],
                ..Default::default()
            },
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "02", "43", "010203" // 2 (kid) => 3-bstr
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                ..Default::default()
            },
            concat!(
                "a1", // 1-map
                "01", "01", // 1 (kty) => OKP
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Text("bc".to_owned()),
                ..Default::default()
            },
            concat!(
                "a1", // 1-map
                "01", "62", "6263" // 1 (kty) => "bc"
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                base_iv: vec![3, 2, 1],
                ..Default::default()
            },
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "05", "43", "030201", // 5 (base_iv) => 3-bstr
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
                ..Default::default()
            },
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "03", "26", // 3 (alg) => -7
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::PrivateUse(-70_000)),
                ..Default::default()
            },
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "03", "3a", "0001116f", // 3 (alg) => -70000
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::Text("abc".to_owned())),
                ..Default::default()
            },
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "03", "63", "616263", // 3 (alg) => "abc"
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                key_id: vec![1, 2, 3],
                key_ops: vec![
                    KeyOperation::Assigned(iana::KeyOperation::Encrypt),
                    KeyOperation::Assigned(iana::KeyOperation::Decrypt),
                    KeyOperation::Text("abc".to_owned()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (kty) => OKP
                "02", "43", "010203", // 2 (kid) => 3-bstr
                "04", "83", "03", "04", "63616263", // 4 (key_ops) => 3-tuple [3,4,"abc"]
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                params: vec![
                    (Label::Int(0x46), Value::from(0x47)),
                    (Label::Int(0x66), Value::from(0x67)),
                ],
                ..Default::default()
            },
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (kty) => OKP
                "1846", "1847", // 46 => 47  (note canonical ordering)
                "1866", "1867", // 66 => 67
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                params: vec![
                    (Label::Int(0x1234), Value::from(0x47)),
                    (Label::Text("a".to_owned()), Value::from(0x67)),
                ],
                ..Default::default()
            },
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (kty) => OKP
                // note canonical ordering: lexicographic
                "191234", "1847", // 0x1234 => 47
                "6161", "1867", // "a" => 67
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                params: vec![
                    (Label::Int(0x66), Value::from(0x67)),
                    (Label::Text("a".to_owned()), Value::from(0x47)),
                ],
                ..Default::default()
            },
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (kty) => OKP
                "1866", "1867", // 66 => 67
                "6161", "1847", // "a" => 47
            ),
        ),
        (
            CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_256,
                hex::decode("6b4ad240073b99cad65ab8417ce29c6844ad0ae77ce8b3f7e41233f5b9129465")
                    .unwrap(),
                hex::decode("a7dc1c39391ab300f7b1787b6e569a031dd0750fe2509b880a41f06666fff785")
                    .unwrap(),
            )
            .algorithm(iana::Algorithm::ES256)
            .param(-70000, Value::Null)
            .build(),
            concat!(
                "a60102032620012158206b4ad240073b",
                "99cad65ab8417ce29c6844ad0ae77ce8",
                "b3f7e41233f5b9129465225820a7dc1c",
                "39391ab300f7b1787b6e569a031dd075",
                "0fe2509b880a41f06666fff7853a0001",
                "116ff6"
            ),
        ),
        (
            CoseKeyBuilder::new_ec2_pub_key_y_sign(
                iana::EllipticCurve::P_256,
                hex::decode("aabbcc").unwrap(),
                false,
            )
            .build(),
            concat!(
                "a4", // 3-map
                "01", "02", // 1 (kty) => 2 (EC2)
                "20", "01", // -1 (crv) => 1 (P_256)
                "21", "43", "aabbcc", // -2 (x) => 3-bstr
                "22", "f4" // -3 (y) => false
            ),
        ),
    ];
    for (i, (key, key_data)) in tests.iter().enumerate() {
        let got = key.clone().to_vec().unwrap();
        assert_eq!(*key_data, hex::encode(&got), "case {i}");

        let got = CoseKey::from_slice(&got).unwrap();
        assert_eq!(*key, got);
    }

    // Now combine all of the keys into a `CoseKeySet`
    let keyset = CoseKeySet(tests.iter().map(|(l, _v)| l.clone()).collect());
    let mut keyset_data: Vec<u8> = vec![0x80u8 + (tests.len() as u8)]; // assumes fewer than 24 keys
    for (_, key_data) in tests.iter() {
        keyset_data.extend_from_slice(&hex::decode(key_data).unwrap());
    }
    let got_data = keyset.clone().to_vec().unwrap();
    assert_eq!(hex::encode(keyset_data), hex::encode(&got_data));

    let got = CoseKeySet::from_slice(&got_data).unwrap();
    assert_eq!(got, keyset);
}

#[test]
fn test_rfc8152_public_cose_key_decode() {
    // Public keys from RFC8152 section 6.7.1.
    // Note that map contents have been reordered into canonical order.
    let tests = vec![
        (
            CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_256,
                hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d").unwrap(),
                hex::decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c").unwrap(),
            ).key_id(b"meriadoc.brandybuck@buckland.example".to_vec()).build(),
            concat!(
                "a5",
                "0102",
                "0258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65",
                "2001",
                "21582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
                "2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c",
            ),
        ),
        (
            CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_256,
                hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap(),
                hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap(),
            ).key_id(b"11".to_vec()).build(),
            concat!("a5",
                    "0102",
                    "02423131",
                    "2001",
                    "215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
                    "22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
            ),
        ),
        (
            CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_521,
                hex::decode("0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad").unwrap(),
                hex::decode("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475").unwrap(),
            ).key_id(
                b"bilbo.baggins@hobbiton.example".to_vec()).build(),
            concat!("a5",
                    "0102",
                    "02581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65",
                    "2003",
                    "2158420072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
                    "22584201dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475",
            ),
        ),
        (
            CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_256,
                hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280").unwrap(),
                hex::decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb").unwrap(),
            ).key_id(b"peregrin.took@tuckborough.example".to_vec()).build(),
            concat!("a5",
                    "0102",
                    "025821706572656772696e2e746f6f6b407475636b626f726f7567682e6578616d706c65",
                    "2001",
                    "21582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
                    "225820f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb",
            )
        ),
    ];
    for (i, (key, key_data)) in tests.iter().enumerate() {
        let got = key.clone().to_vec().unwrap();
        assert_eq!(*key_data, hex::encode(&got), "case {i}");

        let got = CoseKey::from_slice(&got).unwrap();
        assert_eq!(*key, got);
    }

    // Now combine all of the keys into a `CoseKeySet`
    let keyset = CoseKeySet(tests.iter().map(|(l, _v)| l.clone()).collect());
    let mut keyset_data: Vec<u8> = vec![0x80u8 + (tests.len() as u8)]; // assumes fewer than 24 keys
    for (_, key_data) in tests.iter() {
        keyset_data.extend_from_slice(&hex::decode(key_data).unwrap());
    }
    let got = keyset.to_vec().unwrap();
    assert_eq!(hex::encode(keyset_data), hex::encode(got));
}

#[test]
fn test_rfc8152_private_cose_key_decode() {
    // Private keys from RFC8152 section 6.7.2.
    // Note that map contents have been reordered into canonical order.
    let tests = vec![
        (
            CoseKeyBuilder::new_ec2_priv_key(
                iana::EllipticCurve::P_256,
                hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d").unwrap(),
                hex::decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c").unwrap(),
                hex::decode("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf").unwrap(),
            ).key_id(b"meriadoc.brandybuck@buckland.example".to_vec()).build(),
            concat!(
                "a6",
                "0102",
                "0258246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65",
                "2001",
                "21582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
                "2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c",
                "235820aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf",
            ),
        ),
        (
            CoseKeyBuilder::new_ec2_priv_key(
                iana::EllipticCurve::P_256,
                hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap(),
                hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap(),
                hex::decode("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3").unwrap(),
            ).key_id(b"11".to_vec()).build(),
            concat!("a6",
                    "0102",
                    "02423131",
                    "2001",
                    "215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
                    "22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
                    "23582057c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3",
            ),
        ),
        (
            CoseKeyBuilder::new_ec2_priv_key(
                iana::EllipticCurve::P_521,
                hex::decode("0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad").unwrap(),
                hex::decode("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475").unwrap(),
                hex::decode("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d").unwrap(),
            ).key_id(b"bilbo.baggins@hobbiton.example".to_vec()).build(),
            concat!("a6",
                    "0102",
                    "02581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65",
                    "2003",
                    "2158420072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
                    "22584201dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475",
                    "23584200085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d",
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::Symmetric),
                key_id: b"our-secret".to_vec(),
                params: vec![
                    (Label::Int(iana::SymmetricKeyParameter::K as i64) ,
                        Value::Bytes(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap())),
                ],
                ..Default::default()
            },
            concat!("a3",
                    "0104",
                    "024a6f75722d736563726574",
                    "205820849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188",
            ),
        ),
        (
            CoseKeyBuilder::new_ec2_priv_key(
                iana::EllipticCurve::P_256,
                hex::decode("98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280").unwrap(),
                hex::decode("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb").unwrap(),
                hex::decode("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3").unwrap(),
            ).key_id(b"peregrin.took@tuckborough.example".to_vec()).build(),
            concat!("a6",
                    "0102",
                    "025821706572656772696e2e746f6f6b407475636b626f726f7567682e6578616d706c65",
                    "2001",
                    "21582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
                    "225820f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb",
                    "23582002d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3",
            )
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::Symmetric),
                key_id: b"our-secret2".to_vec(),
                params: vec![(
                    Label::Int(iana::SymmetricKeyParameter::K as i64) ,
                        Value::Bytes(hex::decode("849b5786457c1491be3a76dcea6c4271").unwrap()),
                )],
                ..Default::default()
            },
            concat!("a3",
                    "0104",
                    "024b6f75722d73656372657432",
                    "2050849b5786457c1491be3a76dcea6c4271",
            ),
        ),
        (
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::Symmetric),
                key_id: b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec(),
                params: vec![(
                    Label::Int(iana::SymmetricKeyParameter::K as i64) ,
                        Value::Bytes(hex::decode("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188").unwrap()),
                )],
                ..Default::default()
            },
            concat!("a3",
                    "0104",
                    "02582430313863306165352d346439622d343731622d626664362d656566333134626337303337",
                    "205820849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188",
            ),
        ),
    ];
    for (i, (key, key_data)) in tests.iter().enumerate() {
        let got = key.clone().to_vec().unwrap();
        assert_eq!(*key_data, hex::encode(&got), "case {i}");

        let got = CoseKey::from_slice(&got).unwrap();
        assert_eq!(*key, got);
    }

    // Now combine all of the keys into a `CoseKeySet`
    let keyset = CoseKeySet(tests.iter().map(|(l, _v)| l.clone()).collect());
    let mut keyset_data: Vec<u8> = vec![0x80u8 + (tests.len() as u8)]; // assumes fewer than 24 keys
    for (_, key_data) in tests.iter() {
        keyset_data.extend_from_slice(&hex::decode(key_data).unwrap());
    }
    let got = keyset.to_vec().unwrap();
    assert_eq!(hex::encode(keyset_data), hex::encode(got));
}

#[test]
fn test_cose_key_decode_fail() {
    let tests = vec![
        (
            concat!(
                "82", // 2-tuple (invalid)
                "01", "01", // 1 (kty) => OKP
            ),
            "expected map",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "11", // 1 (kty) => invalid value
                "02", "43", "010203" // 2 (kid) => 3-bstr
            ),
            "expected recognized IANA value",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "4101", // 1 (kty) => 1-bstr (invalid value type)
                "02", "43", "010203" // 2 (kid) => 3-bstr
            ),
            "expected int/tstr",
        ),
        (
            concat!(
                "a1", // 1-map (no kty value)
                "02", "41", "01", // 2 (kid) => 1-bstr
            ),
            "expected mandatory kty label",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "02", "40", // 2 (kid) => 0-bstr
            ),
            "expected non-empty bstr",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "02", "01", // 2 (kid) => int (invalid value type)
            ),
            "expected bstr",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "03", "1899", // 3 (alg) => 0x99
            ),
            "expected value in IANA or private use range",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "03", "4101", // 3 (alg) => 1-bstr (invalid value type)
            ),
            "expected int/tstr",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "04", "4101", // 4 (key_ops) => 1-bstr (invalid value type)
            ),
            "expected array",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "04", "82", "03", "03", // 4 (key_ops) => 3-tuple [3,3]
            ),
            "expected unique array label",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "04", "80", // 4 (key_ops) => 0-tuple []
            ),
            "expected non-empty array",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "04", "82", "03", "0b", // 4 (key_ops) => 3-tuple [3,11]
            ),
            "expected recognized IANA value",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "05", "40", // 5 (base_iv) => 0-bstr
            ),
            "expected non-empty bstr",
        ),
        (
            concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "05", "01", // 5 (base_iv) => int (invalid value type)
            ),
            "expected bstr",
        ),
    ];
    for (key_data, err_msg) in tests.iter() {
        let data = hex::decode(key_data).unwrap();
        let result = CoseKey::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_keyset_decode_fail() {
    let tests = [(
        concat!(
            "a1", // 1-map
            "a1", // 1-map
            "01", "01", // 1 (kty) => OKP
            "00"
        ),
        "expected array",
    )];
    for (keyset_data, err_msg) in tests.iter() {
        let data = hex::decode(keyset_data).unwrap();
        let result = CoseKeySet::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_key_decode_dup_fail() {
    let tests = [
        (
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (kty) => OKP
                "1866", "1867", // 66 => 67
                "1866", "1847", // 66 => 47
            ),
            "duplicate map key",
        ),
        (
            concat!(
                "a3", // 3-map
                "01", "01", // 1 (kty) => OKP
                "02", "41", "01", // 2 (kid) => 1-bstr
                "01", "01", // 1 (kty) => OKP  (duplicate label)
            ),
            "duplicate map key",
        ),
    ];
    for (key_data, err_msg) in tests.iter() {
        let data = hex::decode(key_data).unwrap();
        let result = CoseKey::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_cose_key_encode_dup_fail() {
    let tests = vec![CoseKeyBuilder::new()
        .param(10, Value::from(0))
        .param(10, Value::from(0))
        .build()];
    for key in tests {
        let result = key.clone().to_vec();
        expect_err(result, "duplicate map key");
    }
}

#[test]
fn test_key_builder() {
    let tests = vec![
        (
            CoseKeyBuilder::new_symmetric_key(vec![1, 2, 3]).build(),
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::Symmetric),
                params: vec![(
                    Label::Int(iana::SymmetricKeyParameter::K as i64),
                    Value::Bytes(vec![1, 2, 3]),
                )],
                ..Default::default()
            },
        ),
        (
            CoseKeyBuilder::new_symmetric_key(vec![1, 2, 3])
                .algorithm(iana::Algorithm::A128GCM)
                .build(),
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::Symmetric),
                alg: Some(Algorithm::Assigned(iana::Algorithm::A128GCM)),
                params: vec![(
                    Label::Int(iana::SymmetricKeyParameter::K as i64),
                    Value::Bytes(vec![1, 2, 3]),
                )],
                ..Default::default()
            },
        ),
        (
            CoseKeyBuilder::new_symmetric_key(vec![1, 2, 3])
                .key_id(vec![4, 5])
                .build(),
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::Symmetric),
                key_id: vec![4, 5],
                params: vec![(
                    Label::Int(iana::SymmetricKeyParameter::K as i64),
                    Value::Bytes(vec![1, 2, 3]),
                )],
                ..Default::default()
            },
        ),
        (
            CoseKeyBuilder::new_symmetric_key(vec![1, 2, 3])
                .add_key_op(iana::KeyOperation::Encrypt)
                .add_key_op(iana::KeyOperation::Decrypt)
                .build(),
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::Symmetric),
                key_ops: vec![
                    KeyOperation::Assigned(iana::KeyOperation::Encrypt),
                    KeyOperation::Assigned(iana::KeyOperation::Decrypt),
                ]
                .into_iter()
                .collect(),
                params: vec![(
                    Label::Int(iana::SymmetricKeyParameter::K as i64),
                    Value::Bytes(vec![1, 2, 3]),
                )],
                ..Default::default()
            },
        ),
        (
            CoseKeyBuilder::new_symmetric_key(vec![1, 2, 3])
                .base_iv(vec![4, 5])
                .build(),
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::Symmetric),
                base_iv: vec![4, 5],
                params: vec![(
                    Label::Int(iana::SymmetricKeyParameter::K as i64),
                    Value::Bytes(vec![1, 2, 3]),
                )],
                ..Default::default()
            },
        ),
        (
            CoseKeyBuilder::new_okp_key().build(),
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                ..Default::default()
            },
        ),
        (
            CoseKeyBuilder::new()
                .key_type(iana::KeyType::WalnutDSA)
                .build(),
            CoseKey {
                kty: KeyType::Assigned(iana::KeyType::WalnutDSA),
                ..Default::default()
            },
        ),
        (
            CoseKeyBuilder::new()
                .kty(KeyType::Text("test".to_string()))
                .build(),
            CoseKey {
                kty: KeyType::Text("test".to_string()),
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
fn test_key_builder_core_param_panic() {
    // Attempting to set a core `KeyParameter` (in range [1,5]) via `.param()` panics.
    let _key =
        CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![1, 2, 3], vec![2, 3, 4])
            .param(1, Value::Null)
            .build();
}

#[test]
fn test_key_canonicalize() {
    struct TestCase {
        key_data: &'static str, // hex
        rfc7049_key: CoseKey,
        rfc8949_key: CoseKey,
        rfc7049_data: Option<&'static str>, // hex, `None` indicates same as `key_data`
        rfc8949_data: Option<&'static str>, // hex, `None` indicates same as `key_data`
    }
    let tests = [
        TestCase {
            key_data: concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "03", "26", // 3 (alg) => -7
            ),
            rfc7049_key: CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
                ..Default::default()
            },
            rfc8949_key: CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
                ..Default::default()
            },
            rfc7049_data: None,
            rfc8949_data: None,
        },
        TestCase {
            key_data: concat!(
                "a2", // 2-map
                "03", "26", // 3 (alg) => -7
                "01", "01", // 1 (kty) => OKP
            ),
            rfc7049_key: CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
                ..Default::default()
            },
            rfc8949_key: CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
                ..Default::default()
            },
            rfc7049_data: Some(concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "03", "26", // 3 (alg) => -7
            )),
            rfc8949_data: Some(concat!(
                "a2", // 2-map
                "01", "01", // 1 (kty) => OKP
                "03", "26", // 3 (alg) => -7
            )),
        },
        TestCase {
            key_data: concat!(
                "a4", // 4-map
                "03", "26", // 3 (alg) => -7
                "1904d2", "01", // 1234 => 1
                "01", "01", // 1 (kty) => OKP
                "6161", "01", // "a" => 1
            ),
            // "a" encodes shorter than 1234, so appears first
            rfc7049_key: CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
                params: vec![
                    (Label::Text("a".to_string()), Value::Integer(1.into())),
                    (Label::Int(1234), Value::Integer(1.into())),
                ],
                ..Default::default()
            },
            // 1234 encodes with leading byte 0x19, so appears before a tstr
            rfc8949_key: CoseKey {
                kty: KeyType::Assigned(iana::KeyType::OKP),
                alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
                params: vec![
                    (Label::Int(1234), Value::Integer(1.into())),
                    (Label::Text("a".to_string()), Value::Integer(1.into())),
                ],
                ..Default::default()
            },
            rfc7049_data: Some(concat!(
                "a4", // 4-map
                "01", "01", // 1 (kty) => OKP
                "03", "26", // 3 (alg) => -7
                "6161", "01", // "a" => 1
                "1904d2", "01", // 1234 => 1
            )),
            rfc8949_data: Some(concat!(
                "a4", // 4-map
                "01", "01", // 1 (kty) => OKP
                "03", "26", // 3 (alg) => -7
                "1904d2", "01", // 1234 => 1
                "6161", "01", // "a" => 1
            )),
        },
    ];
    for testcase in tests {
        let key_data = hex::decode(testcase.key_data).unwrap();
        let mut key = CoseKey::from_slice(&key_data)
            .unwrap_or_else(|e| panic!("Failed to deserialize {}: {e:?}", testcase.key_data));

        // Canonicalize according to RFC 7049.
        key.canonicalize(CborOrdering::LengthFirstLexicographic);
        assert_eq!(
            key, testcase.rfc7049_key,
            "Mismatch for {}",
            testcase.key_data
        );
        let got = testcase.rfc7049_key.to_vec().unwrap();
        let want = testcase.rfc7049_data.unwrap_or(testcase.key_data);
        assert_eq!(hex::encode(got), want, "Mismatch for {}", testcase.key_data);

        // Canonicalize according to RFC 8949.
        key.canonicalize(CborOrdering::Lexicographic);
        assert_eq!(
            key, testcase.rfc8949_key,
            "Mismatch for {}",
            testcase.key_data
        );

        let got = testcase.rfc8949_key.to_vec().unwrap();
        let want = testcase.rfc8949_data.unwrap_or(testcase.key_data);
        assert_eq!(hex::encode(got), want, "Mismatch for {}", testcase.key_data);
    }
}
