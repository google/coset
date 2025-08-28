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
    cbor::value::Value, util::expect_err, CborSerializable, ContentType, CoseKeyBuilder,
    CoseRecipientBuilder, HeaderBuilder, TaggedCborSerializable,
};
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

#[test]
fn test_cose_mac_decode() {
    let tests: Vec<(CoseMac, &'static str)> = vec![
        (
            CoseMacBuilder::new().build(),
            concat!(
                "85", // 5-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
                "40", // 0-bstr
                "80", // 0-arr
            ),
        ),
        (
            CoseMacBuilder::new().payload(vec![]).build(),
            concat!(
                "85", // 5-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
                "80", // 0-arr
            ),
        ),
    ];
    for (i, (mac, mac_data)) in tests.iter().enumerate() {
        let got = mac.clone().to_vec().unwrap();
        assert_eq!(*mac_data, hex::encode(&got), "case {i}");

        let mut got = CoseMac::from_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*mac, got);
    }
}

#[test]
fn test_cose_mac_decode_fail() {
    let tests = vec![
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
                "84", // 4-tuple (should be 5-tuple)
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
            ),
            "expected array with 5 items",
        ),
        (
            concat!(
                "85", // 5-tuple
                "80", // 0-tuple (should be bstr)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
                "80", // 0-arr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "85", // 5-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40", // 0-bstr (should be map)
                "40", // 0-bstr
                "40", // 0-bstr
                "80", // 0-arr
            ),
            "expected map",
        ),
        (
            concat!(
                "85", // 5-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "60", // 0-tstr (should be bstr)
                "40", // 0-bstr
                "80", // 0-arr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "85", // 5-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "60", // 0-tstr
                "80", // 0-arr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "85", // 5-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
                "40", // 0-bstr
            ),
            "expected array",
        ),
    ];
    for (mac_data, err_msg) in tests.iter() {
        let data = hex::decode(mac_data).unwrap();
        let result = CoseMac::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_rfc8152_cose_mac_decode() {
    // COSE_Mac structures from RFC 8152 section C.5.
    let tests: Vec<(CoseMac, &'static str)> = vec![
        (
            CoseMacBuilder::new()
                .protected(
                    HeaderBuilder::new()
                        .algorithm(iana::Algorithm::AES_MAC_256_64)
                        .build(),
                )
                .payload(b"This is the content.".to_vec())
                .tag(hex::decode("9e1226ba1f81b848").unwrap())
                .add_recipient(
                    CoseRecipientBuilder::new()
                        .unprotected(
                            HeaderBuilder::new()
                                .algorithm(iana::Algorithm::Direct)
                                .key_id(b"our-secret".to_vec())
                                .build(),
                        )
                        .ciphertext(vec![])
                        .build(),
                )
                .build(),
            concat!(
                "d861",
                "85",
                "43",
                "a1010f",
                "a0",
                "54",
                "546869732069732074686520636f6e74656e742e",
                "48",
                "9e1226ba1f81b848",
                "81",
                "83",
                "40",
                "a2",
                "01",
                "25",
                "04",
                "4a",
                "6f75722d736563726574",
                "40",
            ),
        ),
        (
            CoseMacBuilder::new()
                .protected(HeaderBuilder::new().algorithm(iana::Algorithm::HMAC_256_256).build())
                .payload(b"This is the content.".to_vec())
                .tag(hex::decode("81a03448acd3d305376eaa11fb3fe416a955be2cbe7ec96f012c994bc3f16a41").unwrap())
                .add_recipient(
                    CoseRecipientBuilder::new()
                        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ECDH_SS_HKDF_256).build())
                        .unprotected(
                            HeaderBuilder::new()
                                .key_id(b"meriadoc.brandybuck@buckland.example".to_vec())
                                .value(
                                    iana::HeaderAlgorithmParameter::StaticKeyId as i64,
                                    Value::Bytes(b"peregrin.took@tuckborough.example".to_vec())
                                )
                                .value(
                                    iana::HeaderAlgorithmParameter::PartyUNonce as i64,
                                    Value::Bytes(hex::decode("4d8553e7e74f3c6a3a9dd3ef286a8195cbf8a23d19558ccfec7d34b824f42d92bd06bd2c7f0271f0214e141fb779ae2856abf585a58368b017e7f2a9e5ce4db5").unwrap())
                                )
                                .build(),
                        )
                        .ciphertext(vec![])
                        .build(),
                )
                .build(),
            // Note: contents of maps have been re-ordered from the RFC to canonical ordering.
            concat!(
                "d861",
                "85",
                "43", "a10105",
                "a0",
                "54", "546869732069732074686520636f6e74656e742e",
                "5820", "81a03448acd3d305376eaa11fb3fe416a955be2cbe7ec96f012c994bc3f16a41",
                "81",
                "83",
                "44", "a101381a",
                "a3",
                "04",
                "5824", "6d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c65",
                "22",
                "5821", "706572656772696e2e746f6f6b407475636b626f726f7567682e6578616d706c65",
                "35",
                "5840", "4d8553e7e74f3c6a3a9dd3ef286a8195cbf8a23d19558ccfec7d34b824f42d92bd06bd2c7f0271f0214e141fb779ae2856abf585a58368b017e7f2a9e5ce4db5",
                "40",
            ),
        ),
        (
            CoseMacBuilder::new()
                .protected(HeaderBuilder::new().algorithm(iana::Algorithm::AES_MAC_128_64).build())
                .payload(b"This is the content.".to_vec())
                .tag(hex::decode("36f5afaf0bab5d43").unwrap())
                .add_recipient(
                    CoseRecipientBuilder::new()
                        .unprotected(
                            HeaderBuilder::new()
                                .algorithm(iana::Algorithm::A256KW)
                                .key_id(b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec())
                                .build(),
                        )
                        .ciphertext(hex::decode("711ab0dc2fc4585dce27effa6781c8093eba906f227b6eb0").unwrap())
                        .build(),
                )
                .build(),
            concat!(
                "d861",
                "85",
                "43", "a1010e",
                "a0",
                "54", "546869732069732074686520636f6e74656e742e",
                "48", "36f5afaf0bab5d43",
                "81",
                "83",
                "40",
                "a2",
                "01",
                "24",
                "04",
                "5824", "30313863306165352d346439622d343731622d626664362d656566333134626337303337",
                "5818", "711ab0dc2fc4585dce27effa6781c8093eba906f227b6eb0",
            ),
        ),
        (
            CoseMacBuilder::new()
                .protected(HeaderBuilder::new().algorithm(iana::Algorithm::HMAC_256_256).build())
                .payload(b"This is the content.".to_vec())
                .tag(hex::decode("bf48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e").unwrap())
                .add_recipient(
                    CoseRecipientBuilder::new()
                        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::ECDH_ES_A128KW).build())
                        .unprotected(
                            HeaderBuilder::new()
                                .value(iana::HeaderAlgorithmParameter::EphemeralKey as i64,
                                       CoseKeyBuilder::new_ec2_pub_key_y_sign(iana::EllipticCurve::P_521,
                                                                              hex::decode("0043b12669acac3fd27898ffba0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271a6924b1ac63c02688075b55ef2d613574e7dc242f79c3").unwrap(),
                                                                              true)
                                       .build().to_cbor_value().unwrap())
                                .key_id(b"bilbo.baggins@hobbiton.example".to_vec())
                                .build(),
                        )
                        .ciphertext(hex::decode("339bc4f79984cdc6b3e6ce5f315a4c7d2b0ac466fcea69e8c07dfbca5bb1f661bc5f8e0df9e3eff5").unwrap())
                        .build(),
                )
                .add_recipient(
                    CoseRecipientBuilder::new()
                        .unprotected(
                            HeaderBuilder::new()
                                .algorithm(iana::Algorithm::A256KW)
                                .key_id(b"018c0ae5-4d9b-471b-bfd6-eef314bc7037".to_vec())
                                .build(),
                        )
                        .ciphertext(hex::decode("0b2c7cfce04e98276342d6476a7723c090dfdd15f9a518e7736549e998370695e6d6a83b4ae507bb").unwrap())
                        .build(),
                )
                .build(),
            // Note: contents of maps have been re-ordered from the RFC to canonical ordering.
            concat!(
                "d861",
                "85",
                "43", "a10105",
                "a0",
                "54", "546869732069732074686520636f6e74656e742e",
                "5820", "bf48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e",
                "82",
                "83",
                "44", "a101381c",
                "a2",
                "04",
                "581e", "62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c65",
                "20",
                "a4",
                "01",
                "02",
                "20",
                "03",
                "21",
                "5842", "0043b12669acac3fd27898ffba0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271a6924b1ac63c02688075b55ef2d613574e7dc242f79c3",
                "22",
                "f5",
                "5828", "339bc4f79984cdc6b3e6ce5f315a4c7d2b0ac466fcea69e8c07dfbca5bb1f661bc5f8e0df9e3eff5",
                "83",
                "40",
                "a2",
                "01",
                "24",
                "04",
                "5824", "30313863306165352d346439622d343731622d626664362d656566333134626337303337",
                "5828", "0b2c7cfce04e98276342d6476a7723c090dfdd15f9a518e7736549e998370695e6d6a83b4ae507bb",
            ),
        ),
    ];

    for (i, (mac, mac_data)) in tests.iter().enumerate() {
        let got = mac.clone().to_tagged_vec().unwrap();
        assert_eq!(*mac_data, hex::encode(&got), "case {i}");

        let mut got = CoseMac::from_tagged_slice(&got).unwrap();
        got.protected.original_data = None;
        for recip in &mut got.recipients {
            recip.protected.original_data = None;
        }
        for sig in &mut got.unprotected.counter_signatures {
            sig.protected.original_data = None;
        }
        assert_eq!(*mac, got);
    }
}

#[test]
fn test_cose_mac0_decode() {
    let tests: Vec<(CoseMac0, &'static str)> = vec![
        (
            CoseMac0Builder::new().build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "f6", // null
                "40", // 0-bstr
            ),
        ),
        (
            CoseMac0Builder::new().payload(vec![]).build(),
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "40", // 0-bstr
            ),
        ),
    ];
    for (i, (mac, mac_data)) in tests.iter().enumerate() {
        let got = mac.clone().to_vec().unwrap();
        assert_eq!(*mac_data, hex::encode(&got), "case {i}");

        let mut got = CoseMac0::from_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*mac, got);
    }
}
#[test]
fn test_cose_mac0_decode_fail() {
    let tests = [
        (
            concat!(
                "a2",   // 2-map (should be tuple)
                "40",   // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0",   // 0-map
                "4100", // 0-bstr
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
                "40", // 0-bstr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "40", // 0-bstr (should be map)
                "40", // 0-bstr
                "40", // 0-bstr
            ),
            "expected map",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "60", // 0-tstr (should be bstr)
                "40", // 0-bstr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr (special case for empty protected headers, rather than 41a0)
                "a0", // 0-map
                "40", // 0-bstr
                "60", // 0-tstr
            ),
            "expected bstr",
        ),
    ];
    for (mac_data, err_msg) in tests.iter() {
        let data = hex::decode(mac_data).unwrap();
        let result = CoseMac0::from_slice(&data);
        expect_err(result, err_msg);
    }
}

#[test]
fn test_rfc8152_cose_mac0_decode() {
    // COSE_Mac0 structures from RFC 8152 section C.5.
    let tests: Vec<(CoseMac0, &'static str)> = vec![(
        CoseMac0Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::AES_MAC_256_64)
                    .build(),
            )
            .payload(b"This is the content.".to_vec())
            .tag(hex::decode("726043745027214f").unwrap())
            .build(),
        concat!(
            "d1",
            "84",
            "43",
            "a1010f",
            "a0",
            "54",
            "546869732069732074686520636f6e74656e742e",
            "48",
            "726043745027214f",
        ),
    )];

    for (i, (mac, mac_data)) in tests.iter().enumerate() {
        let got = mac.clone().to_tagged_vec().unwrap();
        assert_eq!(*mac_data, hex::encode(&got), "case {i}");

        let mut got = CoseMac0::from_tagged_slice(&got).unwrap();
        got.protected.original_data = None;
        assert_eq!(*mac, got);
    }
}

struct FakeMac {}
impl FakeMac {
    fn compute(&self, data: &[u8]) -> Vec<u8> {
        let mut val = 0u8;
        for b in data {
            val ^= b;
        }
        vec![val]
    }
    fn verify(&self, tag: &[u8], data: &[u8]) -> Result<(), String> {
        if self.compute(data) == tag {
            Ok(())
        } else {
            Err("mismatch".to_owned())
        }
    }
    fn try_compute(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.compute(data))
    }
    fn fail_compute(&self, _data: &[u8]) -> Result<Vec<u8>, String> {
        Err("failed".to_string())
    }
}

#[test]
fn test_cose_mac_roundtrip() {
    let tagger = FakeMac {};
    let external_aad = b"This is the external aad";
    let mut mac = CoseMacBuilder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        .payload(b"This is the data".to_vec())
        .create_tag(external_aad, |data| tagger.compute(data))
        .build();

    assert!(mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_ok());

    // Changing an unprotected header leaves a correct tag.
    mac.unprotected.content_type = Some(ContentType::Text("text/plain".to_owned()));
    assert!(mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_ok());

    // Providing a different `aad` means the tag won't validate
    assert!(mac
        .verify_tag(b"not aad", |tag, data| tagger.verify(tag, data))
        .is_err());

    // Changing a protected header invalidates the tag.
    mac.protected = ProtectedHeader::default();
    assert!(mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_err());
}

#[test]
fn test_cose_mac_noncanonical() {
    let tagger = FakeMac {};
    let external_aad = b"aad";

    // Build an empty protected header from a non-canonical input of 41a0 rather than 40.
    let protected = ProtectedHeader::from_cbor_bstr(Value::Bytes(vec![0xa0])).unwrap();
    assert_eq!(protected.header, Header::default());
    assert_eq!(protected.original_data, Some(vec![0xa0]));

    let mut mac = CoseMac {
        protected: protected.clone(),
        payload: Some(b"data".to_vec()),
        ..Default::default()
    };
    let tbm = mac.tbm(external_aad);
    mac.tag = tagger.compute(&tbm);

    // Checking the MAC should still succeed, because the `ProtectedHeader`
    // includes the wire data and uses it for building the input.
    assert!(mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_ok());

    // However, if we attempt to build the same decryption inputs by hand (thus not including the
    // non-canonical wire data)...
    let recreated_mac = CoseMacBuilder::new()
        .protected(protected.header)
        .payload(b"data".to_vec())
        .tag(mac.tag)
        .build();

    // ...then the transplanted tag will not verify, because the re-building of the
    // inputs will use the canonical encoding of the protected header, which is not what was
    // originally used for the input.
    assert!(recreated_mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_err());
}

#[test]
fn test_cose_mac_tag_result() {
    let tagger = FakeMac {};
    let external_aad = b"This is the external aad";
    let mut _mac = CoseMacBuilder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        .payload(b"This is the data".to_vec())
        .try_create_tag(external_aad, |data| tagger.try_compute(data))
        .unwrap()
        .build();

    // Cope with MAC creation failure.
    let result = CoseMacBuilder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        .payload(b"This is the data".to_vec())
        .try_create_tag(external_aad, |data| tagger.fail_compute(data));
    expect_err(result, "failed");
}

#[test]
#[should_panic]
fn test_cose_mac_create_tag_no_payload() {
    let tagger = FakeMac {};
    let external_aad = b"This is the external aad";
    let _mac = CoseMacBuilder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        // Creating a tag before a payload has been set will panic.
        .create_tag(external_aad, |data| tagger.compute(data))
        .build();
}

#[test]
#[should_panic]
fn test_cose_mac_verify_tag_no_payload() {
    let tagger = FakeMac {};
    let external_aad = b"This is the external aad";
    let mut mac = CoseMacBuilder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        .payload(b"This is the data".to_vec())
        .create_tag(external_aad, |data| tagger.compute(data))
        .build();

    mac.payload = None;
    // Trying to verify with no payload available panics.
    let _result = mac.verify_tag(external_aad, |tag, data| tagger.verify(tag, data));
}

#[test]
fn test_cose_mac0_roundtrip() {
    let tagger = FakeMac {};
    let external_aad = b"This is the external aad";
    let mut mac = CoseMac0Builder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        .payload(b"This is the data".to_vec())
        .create_tag(external_aad, |data| tagger.compute(data))
        .build();

    assert!(mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_ok());

    // Changing an unprotected header leaves a correct tag.
    mac.unprotected.content_type = Some(ContentType::Text("text/plain".to_owned()));
    assert!(mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_ok());

    // Providing a different `aad` means the tag won't validate
    assert!(mac
        .verify_tag(b"not aad", |tag, data| tagger.verify(tag, data))
        .is_err());

    // Changing a protected header invalidates the tag.
    mac.protected = ProtectedHeader::default();
    assert!(mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_err());
}

#[test]
fn test_cose_mac0_noncanonical() {
    let tagger = FakeMac {};
    let external_aad = b"aad";

    // Build an empty protected header from a non-canonical input of 41a0 rather than 40.
    let protected = ProtectedHeader::from_cbor_bstr(Value::Bytes(vec![0xa0])).unwrap();
    assert_eq!(protected.header, Header::default());
    assert_eq!(protected.original_data, Some(vec![0xa0]));

    let mut mac = CoseMac0 {
        protected: protected.clone(),
        payload: Some(b"data".to_vec()),
        ..Default::default()
    };
    let tbm = mac.tbm(external_aad);
    mac.tag = tagger.compute(&tbm);

    // Checking the MAC should still succeed, because the `ProtectedHeader`
    // includes the wire data and uses it for building the input.
    assert!(mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_ok());

    // However, if we attempt to build the same decryption inputs by hand (thus not including the
    // non-canonical wire data)...
    let recreated_mac = CoseMac0Builder::new()
        .protected(protected.header)
        .payload(b"data".to_vec())
        .tag(mac.tag)
        .build();

    // ...then the transplanted tag will not verify, because the re-building of the
    // inputs will use the canonical encoding of the protected header, which is not what was
    // originally used for the input.
    assert!(recreated_mac
        .verify_tag(external_aad, |tag, data| tagger.verify(tag, data))
        .is_err());
}

#[test]
fn test_cose_mac0_tag_result() {
    let tagger = FakeMac {};
    let external_aad = b"This is the external aad";
    let mut _mac = CoseMac0Builder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        .payload(b"This is the data".to_vec())
        .try_create_tag(external_aad, |data| tagger.try_compute(data))
        .unwrap()
        .build();

    // Cope with MAC creation failure.
    let result = CoseMac0Builder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        .payload(b"This is the data".to_vec())
        .try_create_tag(external_aad, |data| tagger.fail_compute(data));
    expect_err(result, "failed");
}

#[test]
#[should_panic]
fn test_cose_mac0_create_tag_no_payload() {
    let tagger = FakeMac {};
    let external_aad = b"This is the external aad";
    let _mac = CoseMac0Builder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        // Creating a tag before a payload has been set will panic.
        .create_tag(external_aad, |data| tagger.compute(data))
        .build();
}

#[test]
#[should_panic]
fn test_cose_mac0_verify_tag_no_payload() {
    let tagger = FakeMac {};
    let external_aad = b"This is the external aad";
    let mut mac = CoseMac0Builder::new()
        .protected(HeaderBuilder::new().key_id(b"11".to_vec()).build())
        .payload(b"This is the data".to_vec())
        .create_tag(external_aad, |data| tagger.compute(data))
        .build();

    mac.payload = None;
    // Trying to verify with no payload available panics.
    let _result = mac.verify_tag(external_aad, |tag, data| tagger.verify(tag, data));
}
