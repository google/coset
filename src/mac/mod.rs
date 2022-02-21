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
    cbor,
    cbor::value::Value,
    common::AsCborValue,
    iana,
    util::{cbor_type_error, to_cbor_array, ValueTryAs},
    CoseError, CoseRecipient, Header, ProtectedHeader, Result,
};
use alloc::{borrow::ToOwned, vec, vec::Vec};

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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseMac {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub tag: Vec<u8>,
    pub recipients: Vec<CoseRecipient>,
}

impl crate::CborSerializable for CoseMac {}

impl crate::TaggedCborSerializable for CoseMac {
    const TAG: u64 = iana::CborTag::CoseMac as u64;
}

impl AsCborValue for CoseMac {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 5 {
            return Err(CoseError::UnexpectedItem("array", "array with 5 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        let recipients = a
            .remove(4)
            .try_as_array_then_convert(CoseRecipient::from_cbor_value)?;

        Ok(Self {
            recipients,
            tag: a.remove(3).try_as_bytes()?,
            payload: match a.remove(2) {
                Value::Bytes(b) => Some(b),
                Value::Null => None,
                v => return cbor_type_error(&v, "bstr"),
            },
            unprotected: Header::from_cbor_value(a.remove(1))?,
            protected: ProtectedHeader::from_cbor_bstr(a.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> Result<Value> {
        Ok(Value::Array(vec![
            self.protected.cbor_bstr()?,
            self.unprotected.to_cbor_value()?,
            match self.payload {
                None => Value::Null,
                Some(b) => Value::Bytes(b),
            },
            Value::Bytes(self.tag),
            to_cbor_array(self.recipients)?,
        ]))
    }
}

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
        let tbm = self.tbm(external_aad);
        verify(&self.tag, &tbm)
    }

    /// Construct the to-be-MAC-ed data for this object. Any protected header values should be set
    /// before using this method, as should the `payload`.
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    fn tbm(&self, external_aad: &[u8]) -> Vec<u8> {
        mac_structure_data(
            MacContext::CoseMac,
            self.protected.clone(),
            external_aad,
            self.payload.as_ref().expect("payload missing"), // safe: documented
        )
    }
}

/// Builder for [`CoseMac`] objects.
#[derive(Debug, Default)]
pub struct CoseMacBuilder(CoseMac);

impl CoseMacBuilder {
    builder! {CoseMac}
    builder_set_protected! {protected}
    builder_set! {unprotected: Header}
    builder_set! {tag: Vec<u8>}
    builder_set_optional! {payload: Vec<u8>}

    /// Add a [`CoseRecipient`].
    #[must_use]
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
    #[must_use]
    pub fn create_tag<F>(self, external_aad: &[u8], create: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let tbm = self.0.tbm(external_aad);
        self.tag(create(&tbm))
    }

    /// Calculate the tag value, using `mac`. Any protected header values should be set
    /// before using this method, as should the `payload`.
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    pub fn try_create_tag<F, E>(self, external_aad: &[u8], create: F) -> Result<Self, E>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let tbm = self.0.tbm(external_aad);
        Ok(self.tag(create(&tbm)?))
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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseMac0 {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub tag: Vec<u8>,
}

impl crate::CborSerializable for CoseMac0 {}

impl crate::TaggedCborSerializable for CoseMac0 {
    const TAG: u64 = iana::CborTag::CoseMac0 as u64;
}

impl AsCborValue for CoseMac0 {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 4 {
            return Err(CoseError::UnexpectedItem("array", "array with 4 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            tag: a.remove(3).try_as_bytes()?,
            payload: match a.remove(2) {
                Value::Bytes(b) => Some(b),
                Value::Null => None,
                v => return cbor_type_error(&v, "bstr"),
            },
            unprotected: Header::from_cbor_value(a.remove(1))?,
            protected: ProtectedHeader::from_cbor_bstr(a.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> Result<Value> {
        Ok(Value::Array(vec![
            self.protected.cbor_bstr()?,
            self.unprotected.to_cbor_value()?,
            match self.payload {
                None => Value::Null,
                Some(b) => Value::Bytes(b),
            },
            Value::Bytes(self.tag),
        ]))
    }
}

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
        let tbm = self.tbm(external_aad);
        verify(&self.tag, &tbm)
    }

    /// Construct the to-be-MAC-ed data for this object. Any protected header values should be set
    /// before using this method, as should the `payload`.
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    fn tbm(&self, external_aad: &[u8]) -> Vec<u8> {
        mac_structure_data(
            MacContext::CoseMac0,
            self.protected.clone(),
            external_aad,
            self.payload.as_ref().expect("payload missing"), // safe: documented
        )
    }
}

/// Builder for [`CoseMac0`] objects.
#[derive(Debug, Default)]
pub struct CoseMac0Builder(CoseMac0);

impl CoseMac0Builder {
    builder! {CoseMac0}
    builder_set_protected! {protected}
    builder_set! {unprotected: Header}
    builder_set! {tag: Vec<u8>}
    builder_set_optional! {payload: Vec<u8>}

    /// Calculate the tag value, using `mac`. Any protected header values should be set
    /// before using this method, as should the `payload`.
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    #[must_use]
    pub fn create_tag<F>(self, external_aad: &[u8], create: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let tbm = self.0.tbm(external_aad);
        self.tag(create(&tbm))
    }

    /// Calculate the tag value, using `mac`. Any protected header values should be set
    /// before using this method, as should the `payload`.
    ///
    /// # Panics
    ///
    /// This function will panic if the `payload` has not been set.
    pub fn try_create_tag<F, E>(self, external_aad: &[u8], create: F) -> Result<Self, E>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let tbm = self.0.tbm(external_aad);
        Ok(self.tag(create(&tbm)?))
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
    protected: ProtectedHeader,
    external_aad: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let arr = vec![
        Value::Text(context.text().to_owned()),
        protected.cbor_bstr().expect("failed to serialize header"), // safe: always serializable
        Value::Bytes(external_aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ];

    let mut data = Vec::new();
    cbor::ser::into_writer(&Value::Array(arr), &mut data).unwrap(); // safe: always serializable
    data
}
