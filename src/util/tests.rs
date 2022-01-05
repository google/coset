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
use crate::{cbor::value::Value, util::expect_err};
use alloc::{borrow::ToOwned, boxed::Box, vec};

#[test]
fn test_cbor_type_error() {
    let cases = vec![
        (Value::Null, "nul"),
        (Value::Bool(true), "bool"),
        (Value::Bool(false), "bool"),
        (Value::from(128), "int"),
        (Value::from(-1), "int"),
        (Value::Bytes(vec![1, 2]), "bstr"),
        (Value::Text("string".to_owned()), "tstr"),
        (Value::Array(vec![Value::from(0)]), "array"),
        (Value::Map(vec![]), "map"),
        (Value::Tag(1, Box::new(Value::from(0))), "tag"),
    ];
    for (val, want) in cases {
        let e = cbor_type_error::<()>(&val, "a");
        expect_err(e, want);
    }
}
