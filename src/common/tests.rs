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

#[test]
fn test_label_encode() {
    let tests = vec![
        (Label::Int(2), "02"),
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

// The `serde_cbor` crate doesn't currently support CBOR tagged values, due
// to a mismatch between CBOR and `serde`'s data model.  If this ever changes,
// these tests should start to fail and we can remove the manual workarounds
// in the `TaggedCborSerializable` trait.
#[test]
fn test_cbor_tag_deserialize_support() {
    let hex_data = concat!("d862", "8340a040");
    let data = hex::decode(hex_data).unwrap();
    let value = cbor::from_slice::<cbor::Value>(&data).unwrap();
    if let cbor::Value::Tag(_t, _v) = value {
        panic!("serde_cbor now deserializes tagged values; revisit TaggedCborSerializable default impls");
    }
}

#[test]
fn test_cbor_tag_serialize_support() {
    let value = cbor::Value::Tag(1, Box::new(cbor::Value::Integer(1)));
    let data = cbor::to_vec(&value).unwrap();
    assert_ne!(
        data[0], 0xc1,
        "serde_cbor now serializes tagged values; revisit TaggedCborSerializable default impls"
    );
}

#[test]
fn test_serialize_tag() {
    let tests = vec![
        (0, "c0"),
        (1, "c1"),
        (2, "c2"),
        (23, "d7"),
        (24, "d818"),
        (0xff, "d8ff"),
        (0x100, "d90100"),
        (0xffff, "d9ffff"),
        (0x10000, "da00010000"),
        (0xffffffff, "daffffffff"),
        (0x100000000, "db0000000100000000"),
    ];
    for (tag, prefix_hex) in tests {
        let got = serialize_tag(tag);
        assert_eq!(hex::encode(&got), prefix_hex);
        assert!(tag_prefix_correct(tag, &got));
    }
}

#[test]
#[should_panic]
fn test_invalid_prefix_input() {
    // Feed in an input that violates the assumptions of the helper function -
    // it assumes that the prefix is the correct length.
    tag_prefix_correct(0x1234, &[0xd9]);
}
