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

use crate::{
    cbor::value::Value,
    CoseError,
};

#[cfg(test)]
mod tests;

/// Return an error indicating that an unexpected CBOR type was encountered.
pub(crate) fn cbor_type_error<T>(value: &Value, want: &'static str) -> Result<T, CoseError> {
    let got = match value {
        Value::Integer(_) => "int",
        Value::Bytes(_) => "bstr",
        Value::Float(_) => "float",
        Value::Text(_) => "tstr",
        Value::Bool(_) => "bool",
        Value::Null => "nul",
        Value::Tag(_, _) => "tag",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        _ => "other",
    };
    Err(CoseError::UnexpectedType(got, want))
}

/// Trait for types that can be converted to/from a [`Value`].
pub trait AsCborValue: Sized {
    /// Convert a [`Value`] into an instance of the type.
    fn from_cbor_value(value: Value) -> Result<Self, CoseError>;
    /// Convert the object into a [`Value`], consuming it along the way.
    fn to_cbor_value(self) -> Result<Value, CoseError>;
}

/// Check for an expected error.
#[cfg(test)]
pub fn expect_err<T: core::fmt::Debug, E: core::fmt::Debug>(result: Result<T, E>, err_msg: &str) {
    use alloc::format;
    assert!(
        result.is_err(),
        "expected error containing '{}', got success {:?}",
        err_msg,
        result
    );
    let err = result.err();
    assert!(
        format!("{:?}", err).contains(err_msg),
        "unexpected error {:?}, doesn't contain '{}'",
        err,
        err_msg
    );
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
        #[must_use]
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
        #[must_use]
        pub fn $name(mut self, $name: $ftype) -> Self {
            self.0.$name = Some($name);
            self
        }
    };
}
