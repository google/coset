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
    cbor::value::{Integer, Value},
    common::AsCborValue,
    CoseError, Result,
};
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(test)]
mod tests;

/// Return an error indicating that an unexpected CBOR type was encountered.
pub(crate) fn cbor_type_error<T>(value: &Value, want: &'static str) -> Result<T> {
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
    Err(CoseError::UnexpectedItem(got, want))
}

/// Trait which augments the [`Value`] type with methods for convenient conversions to contained
/// types which throw a [`CoseError`] if the Value is not of the expected type.
pub(crate) trait ValueTryAs
where
    Self: Sized,
{
    /// Extractor for [`Value::Integer`]
    fn try_as_integer(self) -> Result<Integer>;

    /// Extractor for [`Value::Bytes`]
    fn try_as_bytes(self) -> Result<Vec<u8>>;

    /// Extractor for [`Value::Bytes`] which also throws an error if the byte string is zero length
    fn try_as_nonempty_bytes(self) -> Result<Vec<u8>>;

    /// Extractor for [`Value::Array`]
    fn try_as_array(self) -> Result<Vec<Self>>;

    /// Extractor for [`Value::Array`] which applies `f` to each item to build a new [`Vec`]
    fn try_as_array_then_convert<F, T>(self, f: F) -> Result<Vec<T>>
    where
        F: Fn(Value) -> Result<T>;

    /// Extractor for [`Value::Map`]
    fn try_as_map(self) -> Result<Vec<(Self, Self)>>;

    /// Extractor for [`Value::Tag`]
    fn try_as_tag(self) -> Result<(u64, Box<Value>)>;

    /// Extractor for [`Value::Text`]
    fn try_as_string(self) -> Result<String>;
}

impl ValueTryAs for Value {
    fn try_as_integer(self) -> Result<Integer> {
        if let Value::Integer(i) = self {
            Ok(i)
        } else {
            cbor_type_error(&self, "int")
        }
    }

    fn try_as_bytes(self) -> Result<Vec<u8>> {
        if let Value::Bytes(b) = self {
            Ok(b)
        } else {
            cbor_type_error(&self, "bstr")
        }
    }

    fn try_as_nonempty_bytes(self) -> Result<Vec<u8>> {
        let v = self.try_as_bytes()?;
        if v.is_empty() {
            return Err(CoseError::UnexpectedItem("empty bstr", "non-empty bstr"));
        }
        Ok(v)
    }

    fn try_as_array(self) -> Result<Vec<Self>> {
        if let Value::Array(a) = self {
            Ok(a)
        } else {
            cbor_type_error(&self, "array")
        }
    }

    fn try_as_array_then_convert<F, T>(self, f: F) -> Result<Vec<T>>
    where
        F: Fn(Value) -> Result<T>,
    {
        self.try_as_array()?
            .into_iter()
            .map(f)
            .collect::<Result<Vec<_>, _>>()
    }

    fn try_as_map(self) -> Result<Vec<(Self, Self)>> {
        if let Value::Map(a) = self {
            Ok(a)
        } else {
            cbor_type_error(&self, "map")
        }
    }

    fn try_as_tag(self) -> Result<(u64, Box<Value>)> {
        if let Value::Tag(a, v) = self {
            Ok((a, v))
        } else {
            cbor_type_error(&self, "tag")
        }
    }

    fn try_as_string(self) -> Result<String> {
        if let Value::Text(s) = self {
            Ok(s)
        } else {
            cbor_type_error(&self, "tstr")
        }
    }
}

/// Convert each item of an iterator to CBOR, and wrap the lot in
/// a [`Value::Array`]
pub fn to_cbor_array<C>(c: C) -> Result<Value>
where
    C: IntoIterator,
    C::Item: AsCborValue,
{
    Ok(Value::Array(
        c.into_iter()
            .map(|e| e.to_cbor_value())
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

/// Check for an expected error.
#[cfg(test)]
pub fn expect_err<T: core::fmt::Debug, E: core::fmt::Debug + core::fmt::Display>(
    result: Result<T, E>,
    err_msg: &str,
) {
    #[cfg(not(feature = "std"))]
    use alloc::format;
    match result {
        Ok(_) => {
            assert!(
                result.is_err(),
                "expected error containing '{}', got success {:?}",
                err_msg,
                result
            );
        }
        Err(err) => {
            assert!(
                format!("{err:?}").contains(err_msg),
                "unexpected error {:?}, doesn't contain '{}' (Debug impl)",
                err,
                err_msg
            );
            assert!(
                format!("{err}").contains(err_msg),
                "unexpected error {:?}, doesn't contain '{}' (Display impl)",
                err,
                err_msg
            );
        }
    }
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

/// Add a setter function that fills out a `ProtectedHeader` from `Header` contents.
macro_rules! builder_set_protected {
    ( $name:ident ) => {
        /// Set the associated field.
        #[must_use]
        pub fn $name(mut self, hdr: $crate::Header) -> Self {
            self.0.$name = $crate::ProtectedHeader {
                original_data: None,
                header: hdr,
            };
            self
        }
    };
}
