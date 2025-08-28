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

//! Common types.

use crate::{
    cbor,
    cbor::value::Value,
    iana,
    iana::{EnumI64, WithPrivateRange},
    util::{cbor_type_error, ValueTryAs},
};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{cmp::Ordering, convert::TryInto};

#[cfg(test)]
mod tests;

/// Marker structure indicating that the EOF was encountered when reading CBOR data.
#[derive(Debug)]
pub struct EndOfFile;

/// Error type for failures in encoding or decoding COSE types.
pub enum CoseError {
    /// CBOR decoding failure.
    DecodeFailed(cbor::de::Error<EndOfFile>),
    /// Duplicate map key detected.
    DuplicateMapKey,
    /// CBOR encoding failure.
    EncodeFailed,
    /// CBOR input had extra data.
    ExtraneousData,
    /// Integer value on the wire is outside the range of integers representable in this crate.
    /// See <https://crates.io/crates/coset/#integer-ranges>.
    OutOfRangeIntegerValue,
    /// Unexpected CBOR item encountered (got, want).
    UnexpectedItem(&'static str, &'static str),
    /// Unrecognized value in IANA-controlled range (with no private range).
    UnregisteredIanaValue,
    /// Unrecognized value in neither IANA-controlled range nor private range.
    UnregisteredIanaNonPrivateValue,
}

/// Crate-specific Result type
pub type Result<T, E = CoseError> = core::result::Result<T, E>;

impl<T> core::convert::From<cbor::de::Error<T>> for CoseError {
    fn from(e: cbor::de::Error<T>) -> Self {
        // Make sure we use our [`EndOfFile`] marker.
        use cbor::de::Error::{Io, RecursionLimitExceeded, Semantic, Syntax};
        let e = match e {
            Io(_) => Io(EndOfFile),
            Syntax(x) => Syntax(x),
            Semantic(a, b) => Semantic(a, b),
            RecursionLimitExceeded => RecursionLimitExceeded,
        };
        CoseError::DecodeFailed(e)
    }
}

impl<T> core::convert::From<cbor::ser::Error<T>> for CoseError {
    fn from(_e: cbor::ser::Error<T>) -> Self {
        CoseError::EncodeFailed
    }
}

impl core::convert::From<core::num::TryFromIntError> for CoseError {
    fn from(_: core::num::TryFromIntError) -> Self {
        CoseError::OutOfRangeIntegerValue
    }
}

impl core::fmt::Debug for CoseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.fmt_msg(f)
    }
}

impl core::fmt::Display for CoseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.fmt_msg(f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CoseError {}

impl CoseError {
    fn fmt_msg(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoseError::DecodeFailed(e) => write!(f, "decode CBOR failure: {e}"),
            CoseError::DuplicateMapKey => write!(f, "duplicate map key"),
            CoseError::EncodeFailed => write!(f, "encode CBOR failure"),
            CoseError::ExtraneousData => write!(f, "extraneous data in CBOR input"),
            CoseError::OutOfRangeIntegerValue => write!(f, "out of range integer value"),
            CoseError::UnexpectedItem(got, want) => write!(f, "got {got}, expected {want}"),
            CoseError::UnregisteredIanaValue => write!(f, "expected recognized IANA value"),
            CoseError::UnregisteredIanaNonPrivateValue => {
                write!(f, "expected value in IANA or private use range")
            }
        }
    }
}

/// Read a CBOR [`Value`] from a byte slice, failing if any extra data remains after the `Value` has
/// been read.
fn read_to_value(mut slice: &[u8]) -> Result<Value> {
    let value = cbor::de::from_reader(&mut slice)?;
    if slice.is_empty() {
        Ok(value)
    } else {
        Err(CoseError::ExtraneousData)
    }
}

/// Trait for types that can be converted to/from a [`Value`].
pub trait AsCborValue: Sized {
    /// Convert a [`Value`] into an instance of the type.
    fn from_cbor_value(value: Value) -> Result<Self>;
    /// Convert the object into a [`Value`], consuming it along the way.
    fn to_cbor_value(self) -> Result<Value>;
}

/// Extension trait that adds serialization/deserialization methods.
pub trait CborSerializable: AsCborValue {
    /// Create an object instance from serialized CBOR data in a slice.  This method will fail (with
    /// `CoseError::ExtraneousData`) if there is additional CBOR data after the object.
    fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::from_cbor_value(read_to_value(slice)?)
    }

    /// Serialize this object to a vector, consuming it along the way.
    fn to_vec(self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        cbor::ser::into_writer(&self.to_cbor_value()?, &mut data)?;
        Ok(data)
    }
}

/// Extension trait that adds tagged serialization/deserialization methods.
pub trait TaggedCborSerializable: AsCborValue {
    /// The associated tag value.
    const TAG: u64;

    /// Create an object instance from serialized CBOR data in a slice, expecting an initial
    /// tag value.
    fn from_tagged_slice(slice: &[u8]) -> Result<Self> {
        let (t, v) = read_to_value(slice)?.try_as_tag()?;
        if t != Self::TAG {
            return Err(CoseError::UnexpectedItem("tag", "other tag"));
        }
        Self::from_cbor_value(*v)
    }

    /// Serialize this object to a vector, including initial tag, consuming the object along the
    /// way.
    fn to_tagged_vec(self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        cbor::ser::into_writer(
            &Value::Tag(Self::TAG, Box::new(self.to_cbor_value()?)),
            &mut data,
        )?;
        Ok(data)
    }
}

/// Trivial implementation of [`AsCborValue`] for [`Value`].
impl AsCborValue for Value {
    fn from_cbor_value(value: Value) -> Result<Self> {
        Ok(value)
    }
    fn to_cbor_value(self) -> Result<Value> {
        Ok(self)
    }
}

impl CborSerializable for Value {}

/// Algorithm identifier.
pub type Algorithm = crate::RegisteredLabelWithPrivate<iana::Algorithm>;

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Assigned(iana::Algorithm::Reserved)
    }
}

/// A COSE label may be either a signed integer value or a string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Label {
    Int(i64),
    Text(String),
}

impl CborSerializable for Label {}

/// Manual implementation of [`Ord`] to ensure that CBOR canonical ordering is respected.
///
/// Note that this uses the ordering given by RFC 8949 section 4.2.1 (lexicographic ordering of
/// encoded form), which is *different* from the canonical ordering defined in RFC 7049 section 3.9
/// (where the primary sorting criterion is the length of the encoded form)
impl Ord for Label {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Label::Int(i1), Label::Int(i2)) => match (i1.signum(), i2.signum()) {
                (-1, -1) => i2.cmp(i1),
                (-1, 0) => Ordering::Greater,
                (-1, 1) => Ordering::Greater,
                (0, -1) => Ordering::Less,
                (0, 0) => Ordering::Equal,
                (0, 1) => Ordering::Less,
                (1, -1) => Ordering::Less,
                (1, 0) => Ordering::Greater,
                (1, 1) => i1.cmp(i2),
                (_, _) => unreachable!(), // safe: all possibilies covered
            },
            (Label::Int(_i1), Label::Text(_t2)) => Ordering::Less,
            (Label::Text(_t1), Label::Int(_i2)) => Ordering::Greater,
            (Label::Text(t1), Label::Text(t2)) => t1.len().cmp(&t2.len()).then(t1.cmp(t2)),
        }
    }
}

impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Label {
    /// Alternative ordering for `Label`, using the canonical ordering criteria from RFC 7049
    /// section 3.9 (where the primary sorting criterion is the length of the encoded form), rather
    /// than the ordering given by RFC 8949 section 4.2.1 (lexicographic ordering of encoded form).
    ///
    /// # Panics
    ///
    /// Panics if either `Label` fails to serialize.
    pub fn cmp_canonical(&self, other: &Self) -> Ordering {
        let encoded_self = self.clone().to_vec().unwrap(); /* safe: documented */
        let encoded_other = other.clone().to_vec().unwrap(); /* safe: documented */
        if encoded_self.len() != encoded_other.len() {
            // Shorter encoding sorts first.
            encoded_self.len().cmp(&encoded_other.len())
        } else {
            // Both encode to the same length, sort lexicographically on encoded form.
            encoded_self.cmp(&encoded_other)
        }
    }
}

/// Indicate which ordering should be applied to CBOR values.
pub enum CborOrdering {
    /// Order values lexicographically, as per RFC 8949 section 4.2.1 (Core Deterministic Encoding
    /// Requirements)
    Lexicographic,
    /// Order values by encoded length, then by lexicographic ordering of encoded form, as per RFC
    /// 7049 section 3.9 (Canonical CBOR) / RFC 8949 section 4.2.3 (Length-First Map Key Ordering).
    LengthFirstLexicographic,
}

impl AsCborValue for Label {
    fn from_cbor_value(value: Value) -> Result<Self> {
        match value {
            Value::Integer(i) => Ok(Label::Int(i.try_into()?)),
            Value::Text(t) => Ok(Label::Text(t)),
            v => cbor_type_error(&v, "int/tstr"),
        }
    }
    fn to_cbor_value(self) -> Result<Value> {
        Ok(match self {
            Label::Int(i) => Value::from(i),
            Label::Text(t) => Value::Text(t),
        })
    }
}

/// A COSE label which can be either a signed integer value or a string, but
/// where the allowed integer values are governed by IANA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisteredLabel<T: EnumI64> {
    Assigned(T),
    Text(String),
}

impl<T: EnumI64> From<T> for RegisteredLabel<T> {
    fn from(val: T) -> Self {
        Self::Assigned(val)
    }
}

impl<T: EnumI64> CborSerializable for RegisteredLabel<T> {}

/// Manual implementation of [`Ord`] to ensure that CBOR canonical ordering is respected.
impl<T: EnumI64> Ord for RegisteredLabel<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (RegisteredLabel::Assigned(i1), RegisteredLabel::Assigned(i2)) => {
                Label::Int(i1.to_i64()).cmp(&Label::Int(i2.to_i64()))
            }
            (RegisteredLabel::Assigned(_i1), RegisteredLabel::Text(_t2)) => Ordering::Less,
            (RegisteredLabel::Text(_t1), RegisteredLabel::Assigned(_i2)) => Ordering::Greater,
            (RegisteredLabel::Text(t1), RegisteredLabel::Text(t2)) => {
                t1.len().cmp(&t2.len()).then(t1.cmp(t2))
            }
        }
    }
}

impl<T: EnumI64> PartialOrd for RegisteredLabel<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: EnumI64> AsCborValue for RegisteredLabel<T> {
    fn from_cbor_value(value: Value) -> Result<Self> {
        match value {
            Value::Integer(i) => {
                if let Some(a) = T::from_i64(i.try_into()?) {
                    Ok(RegisteredLabel::Assigned(a))
                } else {
                    Err(CoseError::UnregisteredIanaValue)
                }
            }
            Value::Text(t) => Ok(RegisteredLabel::Text(t)),
            v => cbor_type_error(&v, "int/tstr"),
        }
    }

    fn to_cbor_value(self) -> Result<Value> {
        Ok(match self {
            RegisteredLabel::Assigned(e) => Value::from(e.to_i64()),
            RegisteredLabel::Text(t) => Value::Text(t),
        })
    }
}

/// A COSE label which can be either a signed integer value or a string, and
/// where the allowed integer values are governed by IANA but include a private
/// use range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisteredLabelWithPrivate<T: EnumI64 + WithPrivateRange> {
    PrivateUse(i64),
    Assigned(T),
    Text(String),
}

impl<T: EnumI64 + WithPrivateRange> From<T> for RegisteredLabelWithPrivate<T> {
    fn from(val: T) -> Self {
        Self::Assigned(val)
    }
}

impl<T: EnumI64 + WithPrivateRange> CborSerializable for RegisteredLabelWithPrivate<T> {}

/// Manual implementation of [`Ord`] to ensure that CBOR canonical ordering is respected.
impl<T: EnumI64 + WithPrivateRange> Ord for RegisteredLabelWithPrivate<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        use RegisteredLabelWithPrivate::{Assigned, PrivateUse, Text};
        match (self, other) {
            (Assigned(i1), Assigned(i2)) => Label::Int(i1.to_i64()).cmp(&Label::Int(i2.to_i64())),
            (Assigned(i1), PrivateUse(i2)) => Label::Int(i1.to_i64()).cmp(&Label::Int(*i2)),
            (PrivateUse(i1), Assigned(i2)) => Label::Int(*i1).cmp(&Label::Int(i2.to_i64())),
            (PrivateUse(i1), PrivateUse(i2)) => Label::Int(*i1).cmp(&Label::Int(*i2)),
            (Assigned(_i1), Text(_t2)) => Ordering::Less,
            (PrivateUse(_i1), Text(_t2)) => Ordering::Less,
            (Text(_t1), Assigned(_i2)) => Ordering::Greater,
            (Text(_t1), PrivateUse(_i2)) => Ordering::Greater,
            (Text(t1), Text(t2)) => t1.len().cmp(&t2.len()).then(t1.cmp(t2)),
        }
    }
}

impl<T: EnumI64 + WithPrivateRange> PartialOrd for RegisteredLabelWithPrivate<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: EnumI64 + WithPrivateRange> AsCborValue for RegisteredLabelWithPrivate<T> {
    fn from_cbor_value(value: Value) -> Result<Self> {
        match value {
            Value::Integer(i) => {
                let i = i.try_into()?;
                if let Some(a) = T::from_i64(i) {
                    Ok(RegisteredLabelWithPrivate::Assigned(a))
                } else if T::is_private(i) {
                    Ok(RegisteredLabelWithPrivate::PrivateUse(i))
                } else {
                    Err(CoseError::UnregisteredIanaNonPrivateValue)
                }
            }
            Value::Text(t) => Ok(RegisteredLabelWithPrivate::Text(t)),
            v => cbor_type_error(&v, "int/tstr"),
        }
    }
    fn to_cbor_value(self) -> Result<Value> {
        Ok(match self {
            RegisteredLabelWithPrivate::PrivateUse(i) => Value::from(i),
            RegisteredLabelWithPrivate::Assigned(i) => Value::from(i.to_i64()),
            RegisteredLabelWithPrivate::Text(t) => Value::Text(t),
        })
    }
}
