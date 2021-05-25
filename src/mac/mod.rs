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

//! COSE_Mac functionality.

use crate::{
    util::{cbor_type_error, AsCborValue},
    CborSerializable, CoseRecipient, Header,
};
use alloc::{borrow::ToOwned, vec, vec::Vec};
use serde::de::Unexpected;
use serde_cbor as cbor;

#[cfg(test)]
mod tests;

/// Structure representing a message with authentication code (MAC).
///
/// ```cddl
///  COSE_Mac = [
///     Headers,
///     payload : bstr / nil,
///     tag : bstr,
///     recipients :[+COSE_recipient]
///  ]
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseMac {
    pub protected: Header,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub tag: Vec<u8>,
    pub recipients: Vec<CoseRecipient>,
}

impl crate::CborSerializable for CoseMac {}

#[cfg(feature = "tags")]
impl crate::TaggedCborSerializable for CoseMac {
    const TAG: u64 = crate::iana::CborTag::CoseMac as u64;
}

impl AsCborValue for CoseMac {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        let mut a = match value {
            cbor::Value::Array(a) => a,
            v => return cbor_type_error(&v, &"array"),
        };
        if a.len() != 5 {
            return Err(serde::de::Error::invalid_value(
                Unexpected::TupleVariant,
                &"array with 5 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        let mut mac = Self::default();

        match a.remove(4) {
            cbor::Value::Array(a) => {
                for val in a {
                    mac.recipients.push(CoseRecipient::from_cbor_value(val)?);
                }
            }
            v => return cbor_type_error(&v, &"array"),
        }
        mac.tag = match a.remove(3) {
            cbor::Value::Bytes(b) => b,
            v => return cbor_type_error(&v, &"bstr"),
        };
        mac.payload = match a.remove(2) {
            cbor::Value::Bytes(b) => Some(b),
            cbor::Value::Null => None,
            v => return cbor_type_error(&v, &"bstr"),
        };
        mac.unprotected = Header::from_cbor_value(a.remove(1))?;
        mac.protected = Header::from_cbor_bstr(a.remove(0))?;

        Ok(mac)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        v.push(self.protected.to_cbor_bstr());
        v.push(self.unprotected.to_cbor_value());
        match &self.payload {
            None => v.push(cbor::Value::Null),
            Some(b) => v.push(cbor::Value::Bytes(b.clone())),
        }
        v.push(cbor::Value::Bytes(self.tag.clone()));
        v.push(cbor::Value::Array(
            self.recipients.iter().map(|r| r.to_cbor_value()).collect(),
        ));
        cbor::Value::Array(v)
    }
}

cbor_serialize!(CoseMac);

impl CoseMac {
    /// Verify the `tag` value using the provided `mac` function, feeding it
    /// the `tag` value and the combined to-be-MACed data (in that order).
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    pub fn verify_tag<F, E>(&self, external_aad: &[u8], verify: F) -> Result<(), E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), E>,
    {
        let tbm = mac_structure_data(
            MacContext::CoseMac,
            &self.protected,
            external_aad,
            self.payload.as_ref().expect("payload missing"), // safe: documented
        );
        verify(&self.tag, &tbm)
    }
}

/// Builder for [`CoseMac`] objects.
#[derive(Default)]
pub struct CoseMacBuilder(CoseMac);

impl CoseMacBuilder {
    builder! {CoseMac}
    builder_set! {protected: Header}
    builder_set! {unprotected: Header}
    builder_set! {tag: Vec<u8>}
    builder_set_optional! {payload: Vec<u8>}

    /// Add a [`CoseRecipient`].
    pub fn add_recipient(mut self, recipient: CoseRecipient) -> Self {
        self.0.recipients.push(recipient);
        self
    }

    /// Calculate the tag value, using `mac`. Any protected header values should be set
    /// before using this method, as should the `payload`.
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    pub fn create_tag<F>(self, external_aad: &[u8], create: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let tbm = mac_structure_data(
            MacContext::CoseMac,
            &self.0.protected,
            external_aad,
            self.0.payload.as_ref().expect("payload missing"), // safe: documented
        );
        self.tag(create(&tbm))
    }
}

/// Structure representing a message with authentication code (MAC)
/// where the relevant key is implicit.
///
/// ```cddl
///  COSE_Mac0 = [
///     Headers,
///     payload : bstr / nil,
///     tag : bstr,
///  ]
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseMac0 {
    pub protected: Header,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub tag: Vec<u8>,
}

impl crate::CborSerializable for CoseMac0 {}

#[cfg(feature = "tags")]
impl crate::TaggedCborSerializable for CoseMac0 {
    const TAG: u64 = crate::iana::CborTag::CoseMac0 as u64;
}

impl AsCborValue for CoseMac0 {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        let mut a = match value {
            cbor::Value::Array(a) => a,
            v => return cbor_type_error(&v, &"array"),
        };
        if a.len() != 4 {
            return Err(serde::de::Error::invalid_value(
                Unexpected::TupleVariant,
                &"array with 4 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        let mut mac = Self::default();

        mac.tag = match a.remove(3) {
            cbor::Value::Bytes(b) => b,
            v => return cbor_type_error(&v, &"bstr"),
        };
        mac.payload = match a.remove(2) {
            cbor::Value::Bytes(b) => Some(b),
            cbor::Value::Null => None,
            v => return cbor_type_error(&v, &"bstr"),
        };
        mac.unprotected = Header::from_cbor_value(a.remove(1))?;
        mac.protected = Header::from_cbor_bstr(a.remove(0))?;

        Ok(mac)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        v.push(self.protected.to_cbor_bstr());
        v.push(self.unprotected.to_cbor_value());
        match &self.payload {
            None => v.push(cbor::Value::Null),
            Some(b) => v.push(cbor::Value::Bytes(b.clone())),
        }
        v.push(cbor::Value::Bytes(self.tag.clone()));
        cbor::Value::Array(v)
    }
}

cbor_serialize!(CoseMac0);

impl CoseMac0 {
    /// Verify the `tag` value using the provided `mac` function, feeding it
    /// the `tag` value and the combined to-be-MACed data (in that order).
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    pub fn verify_tag<F, E>(&self, external_aad: &[u8], verify: F) -> Result<(), E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), E>,
    {
        let tbm = mac_structure_data(
            MacContext::CoseMac0,
            &self.protected,
            external_aad,
            self.payload.as_ref().expect("payload missing"), // safe: documented
        );
        verify(&self.tag, &tbm)
    }
}

/// Builder for [`CoseMac0`] objects.
#[derive(Default)]
pub struct CoseMac0Builder(CoseMac0);

impl CoseMac0Builder {
    builder! {CoseMac0}
    builder_set! {protected: Header}
    builder_set! {unprotected: Header}
    builder_set! {tag: Vec<u8>}
    builder_set_optional! {payload: Vec<u8>}

    /// Calculate the tag value, using `mac`. Any protected header values should be set
    /// before using this method, as should the `payload`.
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    pub fn create_tag<F>(self, external_aad: &[u8], create: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let tbm = mac_structure_data(
            MacContext::CoseMac0,
            &self.0.protected,
            external_aad,
            self.0.payload.as_ref().expect("payload missing"), // safe: documented
        );
        self.tag(create(&tbm))
    }
}

/// Possible MAC contexts.
#[derive(Clone, Copy, Debug)]
pub enum MacContext {
    CoseMac,
    CoseMac0,
}

impl MacContext {
    /// Return the context string as per RFC 8152 section 6.3.
    fn text(&self) -> &'static str {
        match self {
            MacContext::CoseMac => "MAC",
            MacContext::CoseMac0 => "MAC0",
        }
    }
}

/// Create a binary blob that will be signed.
//
/// ```cddl
///  MAC_structure = [
///       context : "MAC" / "MAC0",
///       protected : empty_or_serialized_map,
///       external_aad : bstr,
///       payload : bstr
///  ]
/// ```
pub fn mac_structure_data(
    context: MacContext,
    protected: &Header,
    external_aad: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut arr = Vec::<cbor::Value>::new();
    arr.push(cbor::Value::Text(context.text().to_owned()));
    if protected.is_empty() {
        arr.push(cbor::Value::Bytes(vec![]));
    } else {
        arr.push(cbor::Value::Bytes(
            protected.to_vec().expect("failed to serialize header"), // safe: always serializable
        ));
    }
    arr.push(cbor::Value::Bytes(external_aad.to_vec()));
    arr.push(cbor::Value::Bytes(payload.to_vec()));
    cbor::to_vec(&cbor::Value::Array(arr)).expect("failed to serialize Enc_structure") // safe: always serializable
}
