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

/// Map a `serde_cbor::Value` into a serde type error.
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

/// Trait for types that can be converted to/from a `serde_cbor::Value`
pub trait AsCborValue: Sized {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E>;
    fn to_cbor_value(&self) -> cbor::Value;
}

/// Check for an expected error.
#[cfg(test)]
pub fn expect_err<T, E: core::fmt::Debug>(result: Result<T, E>, err_msg: &str) {
    assert!(result.is_err(), "expected error containing '{}'", err_msg);

    // Error messages are only available from serde_cbor if the `std` feature is
    // enabled (and `tags` implies `std`).
    #[cfg(any(feature = "std", feature = "tags"))]
    {
        #[cfg(not(feature = "std"))]
        use alloc::format;

        let err = result.err();
        assert!(
            format!("{:?}", err).contains(err_msg),
            "unexpected error {:?}, doesn't contain '{}'",
            err,
            err_msg
        );
    }
}

/// Macro that emits implementations of `Serialize` and `Deserialize` for
/// types that implement the [`AsCborValue`] trait.
macro_rules! cbor_serialize {
    ( $otype: ty ) => {
        impl ::serde::Serialize for $otype {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.to_cbor_value().serialize(serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $otype {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::from_cbor_value(cbor::Value::deserialize(deserializer)?)
            }
        }
    };
}

// Macros to reduce boilerplate when creating `CoseSomethingBuilder` structures.

/// Add `new()` and `build()` methods to the builder.
macro_rules! builder {
    ( $otype: ty ) => {
        /// Constructor for builder.
        pub fn new() -> Self {
            Self(<$otype>::default())
        }
        /// Build the completed object.
        pub fn build(self) -> $otype {
            self.0
        }
    };
}

/// Add a setter function for a field to the builder.
macro_rules! builder_set {
    ( $name:ident: $ftype:ty ) => {
        /// Set the associated field.
        pub fn $name(mut self, $name: $ftype) -> Self {
            self.0.$name = $name;
            self
        }
    };
}

/// Add a setter function for an optional field to the builder.
macro_rules! builder_set_optional {
    ( $name:ident: $ftype:ty ) => {
        /// Set the associated field.
        pub fn $name(mut self, $name: $ftype) -> Self {
            self.0.$name = Some($name);
            self
        }
    };
}
