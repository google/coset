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

//! COSE_Sign* functionality.

use crate::{
    common::CborSerializable,
    iana,
    util::{cbor_type_error, AsCborValue},
    Header,
};
use serde::{de::Unexpected, Deserialize, Serialize, Serializer};
use serde_cbor as cbor;

#[cfg(test)]
mod tests;

/// Structure representing a cryptographic signature.
///
/// ```cddl
///  COSE_Signature =  [
///       Headers,
///       signature : bstr
///  ]
///  ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseSignature {
    pub protected: Header,
    pub unprotected: Header,
    pub signature: Vec<u8>,
}

impl crate::CborSerializable for CoseSignature {}

impl AsCborValue for CoseSignature {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        let mut a = match value {
            cbor::Value::Array(a) => a,
            v => return cbor_type_error(&v, &"array"),
        };
        if a.len() != 3 {
            return Err(serde::de::Error::invalid_value(
                Unexpected::TupleVariant,
                &"array with 3 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        let mut sig = Self::default();
        sig.signature = match a.remove(2) {
            cbor::Value::Bytes(b) => b,
            v => return cbor_type_error(&v, &"bstr"),
        };

        sig.unprotected = Header::from_cbor_value(a.remove(1))?;
        sig.protected = Header::from_cbor_bstr(a.remove(0))?;

        Ok(sig)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        v.push(self.protected.to_cbor_bstr());
        v.push(self.unprotected.to_cbor_value());
        v.push(cbor::Value::Bytes(self.signature.clone()));
        cbor::Value::Array(v)
    }
}

impl Serialize for CoseSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_cbor_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoseSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_cbor_value(cbor::Value::deserialize(deserializer)?)
    }
}

/// Builder for [`CoseSignature`] objects.
#[derive(Default)]
pub struct CoseSignatureBuilder(CoseSignature);

impl CoseSignatureBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the protected header.
    pub fn protected(mut self, header: Header) -> Self {
        self.0.protected = header;
        self
    }

    /// Set the unprotected header.
    pub fn unprotected(mut self, header: Header) -> Self {
        self.0.unprotected = header;
        self
    }

    /// Set the signature.
    pub fn signature(mut self, sig: Vec<u8>) -> Self {
        self.0.signature = sig;
        self
    }

    /// Build the complete [`CoseSignature`] object.
    pub fn build(self) -> CoseSignature {
        self.0
    }
}

/// Signed payload with signatures.
///
/// ```cdl
///   COSE_Sign = [
///       Headers,
///       payload : bstr / nil,
///       signatures : [+ COSE_Signature]
///   ]
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseSign {
    pub protected: Header,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub signatures: Vec<CoseSignature>,
}

impl crate::CborSerializable for CoseSign {}
impl crate::TaggedCborSerializable for CoseSign {
    const TAG: u64 = iana::CborTag::CoseSign as u64;
}

impl AsCborValue for CoseSign {
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
        let mut sign = Self::default();
        match a.remove(3) {
            cbor::Value::Array(sigs) => {
                for sig in sigs.into_iter() {
                    match CoseSignature::from_cbor_value::<E>(sig) {
                        Ok(s) => sign.signatures.push(s),
                        Err(_e) => {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::StructVariant,
                                &"map for COSE_Signature",
                            ));
                        }
                    }
                }
            }
            v => {
                return cbor_type_error(&v, &"array of COSE_Signature");
            }
        };
        sign.payload = match a.remove(2) {
            cbor::Value::Bytes(b) => Some(b),
            cbor::Value::Null => None,
            v => return cbor_type_error(&v, &"bstr or nil"),
        };

        sign.unprotected = Header::from_cbor_value(a.remove(1))?;
        sign.protected = Header::from_cbor_bstr(a.remove(0))?;

        Ok(sign)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        v.push(self.protected.to_cbor_bstr());
        v.push(self.unprotected.to_cbor_value());
        match &self.payload {
            Some(b) => v.push(cbor::Value::Bytes(b.clone())),
            None => v.push(cbor::Value::Null),
        }
        v.push(cbor::Value::Array(
            self.signatures
                .iter()
                .map(|sig| sig.to_cbor_value())
                .collect(),
        ));
        cbor::Value::Array(v)
    }
}

impl Serialize for CoseSign {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_cbor_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoseSign {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_cbor_value(cbor::Value::deserialize(deserializer)?)
    }
}

impl CoseSign {
    /// Verify the indidated signature value, using `verifier` on the signature value and serialized
    /// data (in that order).
    ///
    /// # Panics
    ///
    /// This method will panic if `which` is >= `self.signatures.len()`.
    pub fn verify_signature<F, E>(&self, which: usize, aad: &[u8], verifier: F) -> Result<(), E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), E>,
    {
        let sig = &self.signatures[which];
        let tbs_data = sig_structure_data(
            SignatureContext::CoseSignature,
            &self.protected,
            Some(&sig.protected),
            aad,
            self.payload.as_ref().unwrap_or(&vec![]),
        );
        verifier(&sig.signature, &tbs_data)
    }
}

/// Builder for [`CoseSign`] objects.
#[derive(Default)]
pub struct CoseSignBuilder(CoseSign);

impl CoseSignBuilder {
    /// Constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the protected header.
    pub fn protected(mut self, header: Header) -> Self {
        self.0.protected = header;
        self
    }

    /// Set the unprotected header.
    pub fn unprotected(mut self, header: Header) -> Self {
        self.0.unprotected = header;
        self
    }

    /// Set the payload.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.0.payload = Some(payload);
        self
    }

    /// Add a signature value.
    pub fn add_signature(mut self, sig: CoseSignature) -> Self {
        self.0.signatures.push(sig);
        self
    }

    /// Calculate the signature value, using `signer` to generate the signature bytes that will be
    /// used to complete `sig`.  Any protected header values should be set before using this
    /// method.
    pub fn add_created_signature<F>(self, mut sig: CoseSignature, aad: &[u8], signer: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let tbs_data = sig_structure_data(
            SignatureContext::CoseSignature,
            &self.0.protected,
            Some(&sig.protected),
            aad,
            self.0.payload.as_ref().unwrap_or(&vec![]),
        );
        sig.signature = signer(&tbs_data);
        self.add_signature(sig)
    }

    /// Build the complete [`CoseSign`] object.
    pub fn build(self) -> CoseSign {
        self.0
    }
}

/// Signed payload with a single signature.
///
/// ```cddl
///   COSE_Sign1 = [
///       Headers,
///       payload : bstr / nil,
///       signature : bstr
///   ]
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseSign1 {
    pub protected: Header,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl crate::CborSerializable for CoseSign1 {}
impl crate::TaggedCborSerializable for CoseSign1 {
    const TAG: u64 = iana::CborTag::CoseSign1 as u64;
}

impl AsCborValue for CoseSign1 {
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
        let mut sign = Self::default();
        sign.signature = match a.remove(3) {
            cbor::Value::Bytes(b) => b,
            v => return cbor_type_error(&v, &"bstr"),
        };
        sign.payload = match a.remove(2) {
            cbor::Value::Bytes(b) => Some(b),
            cbor::Value::Null => None,
            v => return cbor_type_error(&v, &"bstr or nil"),
        };

        sign.unprotected = Header::from_cbor_value(a.remove(1))?;
        sign.protected = Header::from_cbor_bstr(a.remove(0))?;

        Ok(sign)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        v.push(self.protected.to_cbor_bstr());
        v.push(self.unprotected.to_cbor_value());
        match &self.payload {
            Some(b) => v.push(cbor::Value::Bytes(b.clone())),
            None => v.push(cbor::Value::Null),
        }
        v.push(cbor::Value::Bytes(self.signature.clone()));
        cbor::Value::Array(v)
    }
}

impl Serialize for CoseSign1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_cbor_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoseSign1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_cbor_value(cbor::Value::deserialize(deserializer)?)
    }
}

impl CoseSign1 {
    /// Verify the signature value, using `verifier` on the signature value and serialized data (in
    /// that order).
    pub fn verify_signature<F, E>(&self, aad: &[u8], verifier: F) -> Result<(), E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), E>,
    {
        let tbs_data = sig_structure_data(
            SignatureContext::CoseSign1,
            &self.protected,
            None,
            aad,
            self.payload.as_ref().unwrap_or(&vec![]),
        );
        verifier(&self.signature, &tbs_data)
    }
}

/// Builder for [`CoseSign1`] objects.
#[derive(Default)]
pub struct CoseSign1Builder(CoseSign1);

impl CoseSign1Builder {
    /// Constructor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the protected header.
    pub fn protected(mut self, header: Header) -> Self {
        self.0.protected = header;
        self
    }

    /// Set the unprotected header.
    pub fn unprotected(mut self, header: Header) -> Self {
        self.0.unprotected = header;
        self
    }

    /// Set the payload.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.0.payload = Some(payload);
        self
    }

    /// Set the signature value directly.
    pub fn signature(mut self, sig: Vec<u8>) -> Self {
        self.0.signature = sig;
        self
    }

    /// Calculate the signature value, using `signer` to generate the signature bytes.  Any
    /// protected header values should be set before using this method.
    pub fn create_signature<F>(self, aad: &[u8], signer: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let tbs_data = sig_structure_data(
            SignatureContext::CoseSign1,
            &self.0.protected,
            None,
            aad,
            self.0.payload.as_ref().unwrap_or(&vec![]),
        );
        let sig_data = signer(&tbs_data);
        self.signature(sig_data)
    }

    /// Build the complete [`CoseSign1`] object.
    pub fn build(self) -> CoseSign1 {
        self.0
    }
}

/// Possible signature contexts.
#[derive(Clone, Copy)]
pub enum SignatureContext {
    CoseSignature,
    CoseSign1,
    CounterSignature,
}

impl SignatureContext {
    /// Return the context string as per RFC 8152 section 4.4.
    fn text(&self) -> &'static str {
        match self {
            SignatureContext::CoseSignature => "Signature",
            SignatureContext::CoseSign1 => "Signature1",
            SignatureContext::CounterSignature => "CounterSignature",
        }
    }
}

/// Create a binary blob that will be signed.
///
/// ```cddl
///   Sig_structure = [
///       context : "Signature" / "Signature1" / "CounterSignature",
///       body_protected : empty_or_serialized_map,
///       ? sign_protected : empty_or_serialized_map,
///       external_aad : bstr,
///       payload : bstr
///   ]
/// ```
pub fn sig_structure_data(
    context: SignatureContext,
    body: &Header,
    sign: Option<&Header>,
    aad: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut arr = Vec::<cbor::Value>::new();
    arr.push(cbor::Value::Text(context.text().to_owned()));
    if body.is_empty() {
        arr.push(cbor::Value::Bytes(vec![]));
    } else {
        arr.push(cbor::Value::Bytes(
            body.to_vec().expect("failed to serialize header"), // safe: always serializable
        ));
    }
    if let Some(sign) = sign {
        if sign.is_empty() {
            arr.push(cbor::Value::Bytes(vec![]));
        } else {
            arr.push(cbor::Value::Bytes(
                sign.to_vec().expect("failed to serialize header"), // safe: always serializable
            ));
        }
    }
    arr.push(cbor::Value::Bytes(aad.to_vec()));
    arr.push(cbor::Value::Bytes(payload.to_vec()));
    cbor::to_vec(&cbor::Value::Array(arr)).expect("failed to serialize Sig_structure") // safe: always serializable
}
