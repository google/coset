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
use maplit::btreemap;
use serde::de::value::Error;
use serde_cbor as cbor;

#[test]
fn test_cbor_type_error() {
    let val = cbor::Value::Null;
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "unit value");
    let val = cbor::Value::Bool(true);
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "boolean");
    let val = cbor::Value::Integer(128);
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "integer");
    let val = cbor::Value::Float(64.0);
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "float");
    let val = cbor::Value::Bytes(vec![1, 2]);
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "byte array");
    let val = cbor::Value::Text("string".to_owned());
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "string");
    let val = cbor::Value::Array(vec![cbor::Value::Null]);
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "tuple variant");
    let val = cbor::Value::Map(btreemap! {});
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "struct variant");
    let val = cbor::Value::Tag(1, Box::new(cbor::Value::Null));
    let e = cbor_type_error::<(), _, Error>(&val, &"a");
    expect_err(e, "invalid type");
}
