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

//! Common internal utilities.

use serde_cbor as cbor;

#[cfg(test)]
mod tests;

/// Map a [`cbor::Value`] into a serde type error.
pub(crate) fn cbor_type_error<T, M, E>(v: &cbor::Value, msg: &M) -> Result<T, E>
where
    M: serde::de::Expected,
    E: serde::de::Error,
{
    Err(serde::de::Error::invalid_type(
        match v {
            cbor::Value::Integer(i) => serde::de::Unexpected::Signed(*i as i64),
            cbor::Value::Text(t) => serde::de::Unexpected::Str(&t),
            cbor::Value::Null => serde::de::Unexpected::Unit,
            cbor::Value::Bool(b) => serde::de::Unexpected::Bool(*b),
            cbor::Value::Float(f) => serde::de::Unexpected::Float(*f),
            cbor::Value::Bytes(b) => serde::de::Unexpected::Bytes(b),
            cbor::Value::Array(_) => serde::de::Unexpected::TupleVariant,
            cbor::Value::Map(_) => serde::de::Unexpected::StructVariant,
            _ => serde::de::Unexpected::Other("invalid type"),
        },
        msg,
    ))
}

/// Trait for types that can be converted to/from a [`cbor::Value`]
pub trait AsCborValue: Sized {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E>;
    fn to_cbor_value(&self) -> cbor::Value;
}

/// Check for an expected error.
#[cfg(test)]
pub fn expect_err<T, E: std::fmt::Debug>(result: Result<T, E>, err_msg: &str) {
    assert!(result.is_err(), "expected error containing '{}'", err_msg);
    let err = result.err();
    assert!(
        format!("{:?}", err).contains(err_msg),
        "unexpected error {:?}, doesn't contain '{}'",
        err,
        err_msg
    );
}
