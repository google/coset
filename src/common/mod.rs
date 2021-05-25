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
    iana,
    iana::{EnumI128, WithPrivateRange},
    util::{cbor_type_error, AsCborValue},
};
use alloc::{string::String, vec::Vec};
use core::cmp::Ordering;
use serde::{de::DeserializeOwned, Deserialize, Serialize, Serializer};
use serde_cbor as cbor;

#[cfg(test)]
mod tests;

/// Extension trait that adds serialization/deserialization methods.
pub trait CborSerializable: Serialize + DeserializeOwned {
    /// Create an object instance by reading serialized CBOR data from [`std::io::Read`] instance.
    #[cfg(feature = "std")]
    fn from_reader<R: std::io::Read>(reader: R) -> cbor::Result<Self> {
        cbor::from_reader::<Self, R>(reader)
    }

    /// Create an object instance from serialized CBOR data in a slice.
    fn from_slice(slice: &[u8]) -> cbor::Result<Self> {
        cbor::from_slice::<Self>(slice)
    }

    /// Serialize this object to a vector.
    fn to_vec(&self) -> cbor::Result<Vec<u8>> {
        cbor::to_vec(self)
    }

    /// Serialize this object to a [`std::io::Write`] instance.
    #[cfg(feature = "std")]
    fn to_writer<W: std::io::Write>(&self, writer: W) -> cbor::Result<()> {
        cbor::to_writer(writer, self)
    }
}

/// Extension trait that adds tagged serialization/deserialization methods.
#[cfg(feature = "tags")]
pub trait TaggedCborSerializable: AsCborValue {
    /// The associated tag value.
    const TAG: u64;

    /// Create an object instance by reading serialized CBOR data from [`std::io::Read`] instance,
    /// expecting an initial tag value.
    #[cfg(feature = "std")]
    fn from_tagged_reader<R: std::io::Read>(reader: R) -> cbor::Result<Self> {
        match cbor::from_reader::<cbor::Value, R>(reader)? {
            cbor::Value::Tag(t, v) if t == Self::TAG => Self::from_cbor_value(*v),
            v => cbor_type_error(&v, &"tag"),
        }
    }

    /// Create an object instance from serialized CBOR data in a slice, expecting an initial
    /// tag value.
    fn from_tagged_slice(slice: &[u8]) -> cbor::Result<Self> {
        match cbor::from_slice::<cbor::Value>(slice)? {
            cbor::Value::Tag(t, v) if t == Self::TAG => Self::from_cbor_value(*v),
            v => cbor_type_error(&v, &"tag"),
        }
    }

    /// Serialize this object to a vector, including initial tag.
    fn to_tagged_vec(&self) -> cbor::Result<Vec<u8>> {
        cbor::to_vec(&cbor::Value::Tag(
            Self::TAG,
            alloc::boxed::Box::new(self.to_cbor_value()),
        ))
    }

    /// Serialize this object to a [`std::io::Write`] instance, including initial tag.
    #[cfg(feature = "std")]
    fn to_tagged_writer<W: std::io::Write>(&self, writer: W) -> cbor::Result<()> {
        cbor::to_writer(
            writer,
            &cbor::Value::Tag(Self::TAG, alloc::boxed::Box::new(self.to_cbor_value())),
        )
    }
}

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
    Int(i128),
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
        self.to_cbor_value().cmp(&other.to_cbor_value())
    }
}
impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AsCborValue for Label {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        match value {
            cbor::Value::Integer(i) => Ok(Label::Int(i)),
            cbor::Value::Text(t) => Ok(Label::Text(t)),
            v => cbor_type_error(&v, &"int/tstr"),
        }
    }
    fn to_cbor_value(&self) -> cbor::Value {
        match self {
            Label::Int(i) => cbor::Value::Integer(*i as i128),
            Label::Text(t) => cbor::Value::Text(t.clone()),
        }
    }
}

impl Serialize for Label {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Label::Int(i) => serializer.serialize_i128(*i as i128),
            Label::Text(t) => serializer.serialize_str(t),
        }
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_cbor_value(cbor::Value::deserialize(deserializer)?)
    }
}

/// A COSE label which can be either a signed integer value or a string, but
/// where the allowed integer values are governed by IANA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisteredLabel<T: EnumI128> {
    Assigned(T),
    Text(String),
}

impl<T: EnumI128> CborSerializable for RegisteredLabel<T> {}

/// Manual implementation of [`Ord`] to ensure that CBOR canonical ordering is respected.
///
/// Note that this uses the ordering given by RFC 8949 section 4.2.1 (lexicographic ordering of
/// encoded form), which is *different* from the canonical ordering defined in RFC 7049 section 3.9
/// (where the primary sorting criterion is the length of the encoded form)
impl<T: EnumI128 + Eq> Ord for RegisteredLabel<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_cbor_value().cmp(&other.to_cbor_value())
    }
}
impl<T: EnumI128 + Eq> PartialOrd for RegisteredLabel<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: EnumI128> AsCborValue for RegisteredLabel<T> {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        match value {
            cbor::Value::Integer(i) => {
                if let Some(a) = T::from_i128(i) {
                    Ok(RegisteredLabel::Assigned(a))
                } else {
                    Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Signed(i as i64),
                        &"recognized IANA value",
                    ))
                }
            }
            cbor::Value::Text(t) => Ok(RegisteredLabel::Text(t)),
            v => cbor_type_error(&v, &"int/tstr"),
        }
    }
    fn to_cbor_value(&self) -> cbor::Value {
        match self {
            RegisteredLabel::Assigned(e) => cbor::Value::Integer(e.to_i128()),
            RegisteredLabel::Text(t) => cbor::Value::Text(t.clone()),
        }
    }
}

impl<T: EnumI128> Serialize for RegisteredLabel<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RegisteredLabel::Assigned(i) => serializer.serialize_i128(i.to_i128()),
            RegisteredLabel::Text(t) => serializer.serialize_str(t),
        }
    }
}

impl<'de, T: EnumI128> Deserialize<'de> for RegisteredLabel<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_cbor_value(cbor::Value::deserialize(deserializer)?)
    }
}

/// A COSE label which can be either a signed integer value or a string, and
/// where the allowed integer values are governed by IANA but include a private
/// use range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisteredLabelWithPrivate<T: EnumI128 + WithPrivateRange> {
    PrivateUse(i128),
    Assigned(T),
    Text(String),
}

impl<T: EnumI128 + WithPrivateRange> CborSerializable for RegisteredLabelWithPrivate<T> {}

/// Manual implementation of [`Ord`] to ensure that CBOR canonical ordering is respected.
///
/// Note that this uses the ordering given by RFC 8949 section 4.2.1 (lexicographic ordering of
/// encoded form), which is *different* from the canonical ordering defined in RFC 7049 section 3.9
/// (where the primary sorting criterion is the length of the encoded form)
impl<T: EnumI128 + WithPrivateRange + Eq> Ord for RegisteredLabelWithPrivate<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_cbor_value().cmp(&other.to_cbor_value())
    }
}
impl<T: EnumI128 + WithPrivateRange + Eq> PartialOrd for RegisteredLabelWithPrivate<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: EnumI128 + WithPrivateRange> AsCborValue for RegisteredLabelWithPrivate<T> {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        match value {
            cbor::Value::Integer(i) => {
                if let Some(a) = T::from_i128(i) {
                    Ok(RegisteredLabelWithPrivate::Assigned(a))
                } else if T::is_private(i) {
                    Ok(RegisteredLabelWithPrivate::PrivateUse(i))
                } else {
                    Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Signed(i as i64),
                        &"value in IANA or private use range",
                    ))
                }
            }
            cbor::Value::Text(t) => Ok(RegisteredLabelWithPrivate::Text(t)),
            v => cbor_type_error(&v, &"int/tstr"),
        }
    }
    fn to_cbor_value(&self) -> cbor::Value {
        match self {
            RegisteredLabelWithPrivate::PrivateUse(i) => cbor::Value::Integer(*i),
            RegisteredLabelWithPrivate::Assigned(e) => cbor::Value::Integer(e.to_i128()),
            RegisteredLabelWithPrivate::Text(t) => cbor::Value::Text(t.clone()),
        }
    }
}

impl<T: EnumI128 + WithPrivateRange> Serialize for RegisteredLabelWithPrivate<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RegisteredLabelWithPrivate::PrivateUse(i) => serializer.serialize_i128(*i),
            RegisteredLabelWithPrivate::Assigned(i) => serializer.serialize_i128(i.to_i128()),
            RegisteredLabelWithPrivate::Text(t) => serializer.serialize_str(t),
        }
    }
}

impl<'de, T: EnumI128 + WithPrivateRange> Deserialize<'de> for RegisteredLabelWithPrivate<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_cbor_value(cbor::Value::deserialize(deserializer)?)
    }
}
