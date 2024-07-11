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
    cbor,
    cbor::value::Value,
    common::AsCborValue,
    iana,
    util::{cbor_type_error, to_cbor_array, ValueTryAs},
    CoseError, Header, ProtectedHeader, Result,
};
use alloc::{borrow::ToOwned, vec, vec::Vec};

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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseSignature {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub signature: Vec<u8>,
}

impl crate::CborSerializable for CoseSignature {}

impl AsCborValue for CoseSignature {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 3 {
            return Err(CoseError::UnexpectedItem("array", "array with 3 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            signature: a.remove(2).try_as_bytes()?,
            unprotected: Header::from_cbor_value(a.remove(1))?,
            protected: ProtectedHeader::from_cbor_bstr(a.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> Result<Value> {
        Ok(Value::Array(vec![
            self.protected.cbor_bstr()?,
            self.unprotected.to_cbor_value()?,
            Value::Bytes(self.signature),
        ]))
    }
}

/// Builder for [`CoseSignature`] objects.
#[derive(Debug, Default)]
pub struct CoseSignatureBuilder(CoseSignature);

impl CoseSignatureBuilder {
    builder! {CoseSignature}
    builder_set_protected! {protected}
    builder_set! {unprotected: Header}
    builder_set! {signature: Vec<u8>}
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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseSign {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub signatures: Vec<CoseSignature>,
}

impl crate::CborSerializable for CoseSign {}
impl crate::TaggedCborSerializable for CoseSign {
    const TAG: u64 = iana::CborTag::CoseSign as u64;
}

impl AsCborValue for CoseSign {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 4 {
            return Err(CoseError::UnexpectedItem("array", "array with 4 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        let signatures = a.remove(3).try_as_array_then_convert(|v| {
            CoseSignature::from_cbor_value(v)
                .map_err(|_e| CoseError::UnexpectedItem("non-signature", "map for COSE_Signature"))
        })?;

        Ok(Self {
            signatures,
            payload: match a.remove(2) {
                Value::Bytes(b) => Some(b),
                Value::Null => None,
                v => return cbor_type_error(&v, "bstr or nil"),
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
                Some(b) => Value::Bytes(b),
                None => Value::Null,
            },
            to_cbor_array(self.signatures)?,
        ]))
    }
}

impl CoseSign {
    /// Verify the indicated signature value, using `verifier` on the signature value and serialized
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
        let tbs_data = self.tbs_data(aad, sig);
        verifier(&sig.signature, &tbs_data)
    }

    /// Verify the indicated signature value for a detached payload, using `verifier` on the
    /// signature value and serialized data (in that order).
    ///
    /// # Panics
    ///
    /// This method will panic if `which` is >= `self.signatures.len()`.
    ///
    /// This method will panic if `self.payload.is_some()`.
    pub fn verify_detached_signature<F, E>(
        &self,
        which: usize,
        payload: &[u8],
        aad: &[u8],
        verifier: F,
    ) -> Result<(), E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), E>,
    {
        let sig = &self.signatures[which];
        let tbs_data = self.tbs_detached_data(payload, aad, sig);
        verifier(&sig.signature, &tbs_data)
    }

    /// Construct the to-be-signed data for this object.
    pub fn tbs_data(&self, aad: &[u8], sig: &CoseSignature) -> Vec<u8> {
        sig_structure_data(
            SignatureContext::CoseSignature,
            self.protected.clone(),
            Some(sig.protected.clone()),
            aad,
            self.payload.as_ref().unwrap_or(&vec![]),
        )
    }

    /// Construct the to-be-signed data for this object, using a detached payload.
    ///
    /// # Panics
    ///
    /// This method will panic if `self.payload.is_some()`.
    pub fn tbs_detached_data(&self, payload: &[u8], aad: &[u8], sig: &CoseSignature) -> Vec<u8> {
        assert!(self.payload.is_none());
        sig_structure_data(
            SignatureContext::CoseSignature,
            self.protected.clone(),
            Some(sig.protected.clone()),
            aad,
            payload,
        )
    }
}

/// Builder for [`CoseSign`] objects.
#[derive(Debug, Default)]
pub struct CoseSignBuilder(CoseSign);

impl CoseSignBuilder {
    builder! {CoseSign}
    builder_set_protected! {protected}
    builder_set! {unprotected: Header}
    builder_set_optional! {payload: Vec<u8>}

    /// Add a signature value.
    #[must_use]
    pub fn add_signature(mut self, sig: CoseSignature) -> Self {
        self.0.signatures.push(sig);
        self
    }

    /// Calculate the signature value, using `signer` to generate the signature bytes that will be
    /// used to complete `sig`.  Any protected header values should be set before using this
    /// method.
    #[must_use]
    pub fn add_created_signature<F>(self, mut sig: CoseSignature, aad: &[u8], signer: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let tbs_data = self.0.tbs_data(aad, &sig);
        sig.signature = signer(&tbs_data);
        self.add_signature(sig)
    }

    /// Calculate the signature value for a detached payload, using `signer` to generate the
    /// signature bytes that will be used to complete `sig`.  Any protected header values should
    /// be set before using this method.
    ///
    /// # Panics
    ///
    /// This method will panic if `self.payload.is_some()`.
    #[must_use]
    pub fn add_detached_signature<F>(
        self,
        mut sig: CoseSignature,
        payload: &[u8],
        aad: &[u8],
        signer: F,
    ) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let tbs_data = self.0.tbs_detached_data(payload, aad, &sig);
        sig.signature = signer(&tbs_data);
        self.add_signature(sig)
    }

    /// Calculate the signature value, using `signer` to generate the signature bytes that will be
    /// used to complete `sig`.  Any protected header values should be set before using this
    /// method.
    pub fn try_add_created_signature<F, E>(
        self,
        mut sig: CoseSignature,
        aad: &[u8],
        signer: F,
    ) -> Result<Self, E>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let tbs_data = self.0.tbs_data(aad, &sig);
        sig.signature = signer(&tbs_data)?;
        Ok(self.add_signature(sig))
    }

    /// Calculate the signature value for a detached payload, using `signer` to generate the
    /// signature bytes that will be used to complete `sig`.  Any protected header values should
    /// be set before using this method.
    ///
    /// # Panics
    ///
    /// This method will panic if `self.payload.is_some()`.
    pub fn try_add_detached_signature<F, E>(
        self,
        mut sig: CoseSignature,
        payload: &[u8],
        aad: &[u8],
        signer: F,
    ) -> Result<Self, E>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let tbs_data = self.0.tbs_detached_data(payload, aad, &sig);
        sig.signature = signer(&tbs_data)?;
        Ok(self.add_signature(sig))
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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseSign1 {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl crate::CborSerializable for CoseSign1 {}
impl crate::TaggedCborSerializable for CoseSign1 {
    const TAG: u64 = iana::CborTag::CoseSign1 as u64;
}

impl AsCborValue for CoseSign1 {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 4 {
            return Err(CoseError::UnexpectedItem("array", "array with 4 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            signature: a.remove(3).try_as_bytes()?,
            payload: match a.remove(2) {
                Value::Bytes(b) => Some(b),
                Value::Null => None,
                v => return cbor_type_error(&v, "bstr or nil"),
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
                Some(b) => Value::Bytes(b),
                None => Value::Null,
            },
            Value::Bytes(self.signature),
        ]))
    }
}

impl CoseSign1 {
    /// Verify the signature value, using `verifier` on the signature value and serialized data (in
    /// that order).
    pub fn verify_signature<F, E>(&self, aad: &[u8], verifier: F) -> Result<(), E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), E>,
    {
        let tbs_data = self.tbs_data(aad);
        verifier(&self.signature, &tbs_data)
    }

    /// Verify the indicated signature value for a detached payload, using `verifier` on the
    /// signature value and serialized data (in that order).
    ///
    /// # Panics
    ///
    /// This method will panic if `self.payload.is_some()`.
    pub fn verify_detached_signature<F, E>(
        &self,
        payload: &[u8],
        aad: &[u8],
        verifier: F,
    ) -> Result<(), E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<(), E>,
    {
        let tbs_data = self.tbs_detached_data(payload, aad);
        verifier(&self.signature, &tbs_data)
    }

    /// Construct the to-be-signed data for this object.
    pub fn tbs_data(&self, aad: &[u8]) -> Vec<u8> {
        sig_structure_data(
            SignatureContext::CoseSign1,
            self.protected.clone(),
            None,
            aad,
            self.payload.as_ref().unwrap_or(&vec![]),
        )
    }

    /// Construct the to-be-signed data for this object, using a detached payload.
    ///
    /// # Panics
    ///
    /// This method will panic if `self.payload.is_some()`.
    pub fn tbs_detached_data(&self, payload: &[u8], aad: &[u8]) -> Vec<u8> {
        assert!(self.payload.is_none());
        sig_structure_data(
            SignatureContext::CoseSign1,
            self.protected.clone(),
            None,
            aad,
            payload,
        )
    }
}

/// Builder for [`CoseSign1`] objects.
#[derive(Debug, Default)]
pub struct CoseSign1Builder(CoseSign1);

impl CoseSign1Builder {
    builder! {CoseSign1}
    builder_set_protected! {protected}
    builder_set! {unprotected: Header}
    builder_set! {signature: Vec<u8>}
    builder_set_optional! {payload: Vec<u8>}

    /// Calculate the signature value, using `signer` to generate the signature bytes.  Any
    /// protected header values should be set before using this method.
    #[must_use]
    pub fn create_signature<F>(self, aad: &[u8], signer: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let sig_data = signer(&self.0.tbs_data(aad));
        self.signature(sig_data)
    }

    /// Calculate the signature value for a detached payload, using `signer` to generate the
    /// signature bytes.  Any protected header values should be set before using this method.
    ///
    /// # Panics
    ///
    /// This method will panic if `self.payload.is_some()`.
    #[must_use]
    pub fn create_detached_signature<F>(self, payload: &[u8], aad: &[u8], signer: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let sig_data = signer(&self.0.tbs_detached_data(payload, aad));
        self.signature(sig_data)
    }

    /// Calculate the signature value, using `signer` to generate the signature bytes.  Any
    /// protected header values should be set before using this method.
    pub fn try_create_signature<F, E>(self, aad: &[u8], signer: F) -> Result<Self, E>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let sig_data = signer(&self.0.tbs_data(aad))?;
        Ok(self.signature(sig_data))
    }

    /// Calculate the signature value for a detached payload, using `signer` to generate the
    /// signature bytes.  Any protected header values should be set before using this method.
    ///
    /// # Panics
    ///
    /// This method will panic if `self.payload.is_some()`.
    pub fn try_create_detached_signature<F, E>(
        self,
        payload: &[u8],
        aad: &[u8],
        signer: F,
    ) -> Result<Self, E>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let sig_data = signer(&self.0.tbs_detached_data(payload, aad))?;
        Ok(self.signature(sig_data))
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
    body: ProtectedHeader,
    sign: Option<ProtectedHeader>,
    aad: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut arr = vec![
        Value::Text(context.text().to_owned()),
        body.cbor_bstr().expect("failed to serialize header"), // safe: always serializable
    ];
    if let Some(sign) = sign {
        arr.push(sign.cbor_bstr().expect("failed to serialize header")); // safe: always
                                                                         // serializable
    }
    arr.push(Value::Bytes(aad.to_vec()));
    arr.push(Value::Bytes(payload.to_vec()));
    let mut data = Vec::new();
    cbor::ser::into_writer(&Value::Array(arr), &mut data).unwrap(); // safe: always serializable
    data
}
