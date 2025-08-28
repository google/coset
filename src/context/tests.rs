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
use crate::{iana, util::expect_err, CborSerializable, HeaderBuilder};
use alloc::vec;

#[test]
fn test_context_encode() {
    let tests = vec![
        (
            CoseKdfContext::default(),
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .algorithm(iana::Algorithm::A128GCM)
                .build(),
            concat!(
                "84", // 4-tuple
                "01", // int : AES-128-GCM
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .algorithm(iana::Algorithm::A128GCM)
                .party_u_info(PartyInfoBuilder::new().identity(vec![]).build())
                .build(),
            concat!(
                "84", // 4-tuple
                "01", // int : AES-128-GCM
                "83", "40f6f6", // 3-tuple: [0-bstr, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .algorithm(iana::Algorithm::A128GCM)
                .party_u_info(
                    PartyInfoBuilder::new()
                        .identity(vec![3, 6])
                        .nonce(Nonce::Integer(7))
                        .build(),
                )
                .build(),
            concat!(
                "84", // 4-tuple
                "01", // int : AES-128-GCM
                "83", "420306", "07f6", // 3-tuple: [2-bstr, int, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .algorithm(iana::Algorithm::A128GCM)
                .party_u_info(
                    PartyInfoBuilder::new()
                        .identity(vec![3, 6])
                        .nonce(Nonce::Integer(-2))
                        .build(),
                )
                .build(),
            concat!(
                "84", // 4-tuple
                "01", // int : AES-128-GCM
                "83", "420306", "21f6", // 3-tuple: [2-bstr, nint, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .algorithm(iana::Algorithm::A128GCM)
                .party_v_info(
                    PartyInfoBuilder::new()
                        .identity(vec![3, 6])
                        .nonce(Nonce::Bytes(vec![7, 3]))
                        .build(),
                )
                .build(),
            concat!(
                "84", // 4-tuple
                "01", // int : AES-128-GCM
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "420306", "420703", "f6", // 3-tuple: [2-bstr, 2-bstr, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .algorithm(iana::Algorithm::A128GCM)
                .party_v_info(
                    PartyInfoBuilder::new()
                        .identity(vec![3, 6])
                        .other(vec![7, 3])
                        .build(),
                )
                .build(),
            concat!(
                "84", // 4-tuple
                "01", // int : AES-128-GCM
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "420306", "f6", "420703", // 3-tuple: [2-bstr, nil, 2-bstr]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .supp_pub_info(
                    SuppPubInfoBuilder::new()
                        .key_data_length(10)
                        .protected(
                            HeaderBuilder::new()
                                .algorithm(iana::Algorithm::A128GCM)
                                .build(),
                        )
                        .build(),
                )
                .build(),
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0a43", "a10101" // 2-tuple: [10, 3-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .supp_pub_info(
                    SuppPubInfoBuilder::new()
                        .key_data_length(10)
                        .other(vec![1, 3, 5])
                        .build(),
                )
                .build(),
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "0a40", "43010305", // 3-tuple: [10, 0-bstr, 3-bstr]
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .add_supp_priv_info(vec![1, 2, 3])
                .build(),
            concat!(
                "85", // 5-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
                "43", "010203", // 3-bstr
            ),
        ),
        (
            CoseKdfContextBuilder::new()
                .add_supp_priv_info(vec![1, 2, 3])
                .add_supp_priv_info(vec![2, 3])
                .add_supp_priv_info(vec![3])
                .build(),
            concat!(
                "87", // 7-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
                "43", "010203", // 3-bstr
                "42", "0203", // 2-bstr
                "41", "03", // 1-bstr
            ),
        ),
    ];
    for (i, (key, key_data)) in tests.iter().enumerate() {
        let got = key.clone().to_vec().unwrap();
        assert_eq!(*key_data, hex::encode(&got), "case {i}");

        let mut got = CoseKdfContext::from_slice(&got).unwrap();
        got.supp_pub_info.protected.original_data = None;
        assert_eq!(*key, got);
    }
}

#[test]
fn test_context_decode_fail() {
    let tests = vec![
        (
            concat!(
                "a2", // 2-map
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
            "expected array",
        ),
        (
            concat!(
                "83", // 3-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
            ),
            "expected array with at least 4 items",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
            ),
            "decode CBOR failure: Io(EndOfFile",
        ),
        (
            concat!(
                "84", // 4-tuple
                "08", // int : unassigned value
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
            "expected value in IANA or private use range",
        ),
        (
            concat!(
                "84", // 4-tuple
                "40", // 0-bstr : invalid
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
            "expected int/tstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "a1", "f6f6", // 1-map
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
            "expected array",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "84", "f6f6f6f6", // 4-tuple: [nil, nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
            "expected array with 3 items",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f660f6", // 3-tuple: [nil, 0-tstr, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
            "expected bstr / int / nil",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f660", // 3-tuple: [nil, nil, 0-tstr]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
            "expected bstr / nil",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "60f6f6", // 3-tuple: [0-tstr, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
            ),
            "expected bstr / nil",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "a1", "0040", // 1-map: {0: 0-bstr}
            ),
            "expected array",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "81", "00", // 2-tuple: [0]
            ),
            "expected array with 2 or 3 items",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "4040", // 2-tuple: [0-bstr, 0-bstr]
            ),
            "expected int",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0060", // 2-tuple: [0, 0-tstr]
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "004060", // 3-tuple: [0, 0-bstr, 0-tstr]
            ),
            "expected bstr",
        ),
        (
            concat!(
                "85", // 5-tuple
                "00", // int : reserved
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "83", "f6f6f6", // 3-tuple: [nil, nil, nil]
                "82", "0040", // 2-tuple: [0, 0-bstr]
                "60",   // 0-tstr
            ),
            "expected bstr",
        ),
        (
            concat!(
                "84", // 4-tuple
                "01", // int : AES-128-GCM
                "83", // 3-tuple: [0-bstr, out-of-range int, nil]
                "401b8000000000000000f6",
                "83", // 3-tuple: [nil, nil, nil]
                "f6f6f6",
                "82", // 2-tuple: [0, 0-bstr]
                "0040",
            ),
            "out of range integer value",
        ),
    ];
    for (context_data, err_msg) in tests.iter() {
        let data = hex::decode(context_data).unwrap();
        let result = CoseKdfContext::from_slice(&data);
        expect_err(result, err_msg);
    }
}
