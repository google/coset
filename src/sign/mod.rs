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
    cbor::{SimpleValue, Value},
    iana,
    util::{cbor_type_error, AsCborValue},
    CborSerializable, CoseError, Header,
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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseSignature {
    pub protected: Header,
    pub unprotected: Header,
    pub signature: Vec<u8>,
}

impl crate::CborSerializable for CoseSignature {}

impl AsCborValue for CoseSignature {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let mut a = match value {
            Value::Array(a) => a,
            v => return cbor_type_error(&v, "array"),
        };
        if a.len() != 3 {
            return Err(CoseError::UnexpectedType("array", "array with 3 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            signature: match a.remove(2) {
                Value::ByteString(b) => b,
                v => return cbor_type_error(&v, "bstr"),
            },
            unprotected: Header::from_cbor_value(a.remove(1))?,
            protected: Header::from_cbor_bstr(a.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        Ok(Value::Array(vec![
            self.protected.cbor_bstr()?,
            self.unprotected.to_cbor_value()?,
            Value::ByteString(self.signature),
        ]))
    }
}

/// Builder for [`CoseSignature`] objects.
#[derive(Default)]
pub struct CoseSignatureBuilder(CoseSignature);

impl CoseSignatureBuilder {
    builder! {CoseSignature}
    builder_set! {protected: Header}
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
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let mut a = match value {
            Value::Array(a) => a,
            v => return cbor_type_error(&v, "array"),
        };
        if a.len() != 4 {
            return Err(CoseError::UnexpectedType("array", "array with 4 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        let mut signatures = vec![];
        match a.remove(3) {
            Value::Array(sigs) => {
                for sig in sigs.into_iter() {
                    match CoseSignature::from_cbor_value(sig) {
                        Ok(s) => signatures.push(s),
                        Err(_e) => {
                            return Err(CoseError::UnexpectedType(
                                "non-signature",
                                "map for COSE_Signature",
                            ));
                        }
                    }
                }
            }
            v => {
                return cbor_type_error(&v, "array of COSE_Signature");
            }
        };

        Ok(Self {
            signatures,
            payload: match a.remove(2) {
                Value::ByteString(b) => Some(b),
                Value::Simple(SimpleValue::NullValue) => None,
                v => return cbor_type_error(&v, "bstr or nil"),
            },
            unprotected: Header::from_cbor_value(a.remove(1))?,
            protected: Header::from_cbor_bstr(a.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut v = vec![
            self.protected.cbor_bstr()?,
            self.unprotected.to_cbor_value()?,
            match self.payload {
                Some(b) => Value::ByteString(b),
                None => Value::Simple(SimpleValue::NullValue),
            },
        ];
        let mut arr = Vec::new();
        for sig in self.signatures {
            arr.push(sig.to_cbor_value()?);
        }
        v.push(Value::Array(arr));
        Ok(Value::Array(v))
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
        let tbs_data = self.tbs_data(aad, sig);
        verifier(&sig.signature, &tbs_data)
    }

    /// Construct the to-be-signed data for this object.
    fn tbs_data(&self, aad: &[u8], sig: &CoseSignature) -> Vec<u8> {
        sig_structure_data(
            SignatureContext::CoseSignature,
            self.protected.clone(),
            Some(sig.protected.clone()),
            aad,
            self.payload.as_ref().unwrap_or(&vec![]),
        )
    }
}

/// Builder for [`CoseSign`] objects.
#[derive(Default)]
pub struct CoseSignBuilder(CoseSign);

impl CoseSignBuilder {
    builder! {CoseSign}
    builder_set! {protected: Header}
    builder_set! {unprotected: Header}
    builder_set_optional! {payload: Vec<u8>}

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
        let tbs_data = self.0.tbs_data(aad, &sig);
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
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let mut a = match value {
            Value::Array(a) => a,
            v => return cbor_type_error(&v, "array"),
        };
        if a.len() != 4 {
            return Err(CoseError::UnexpectedType("array", "array with 4 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            signature: match a.remove(3) {
                Value::ByteString(b) => b,
                v => return cbor_type_error(&v, "bstr"),
            },
            payload: match a.remove(2) {
                Value::ByteString(b) => Some(b),
                Value::Simple(SimpleValue::NullValue) => None,
                v => return cbor_type_error(&v, "bstr or nil"),
            },
            unprotected: Header::from_cbor_value(a.remove(1))?,
            protected: Header::from_cbor_bstr(a.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        Ok(Value::Array(vec![
            self.protected.cbor_bstr()?,
            self.unprotected.to_cbor_value()?,
            match self.payload {
                Some(b) => Value::ByteString(b),
                None => Value::Simple(SimpleValue::NullValue),
            },
            Value::ByteString(self.signature),
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

    /// Construct the to-be-signed data for this object.
    fn tbs_data(&self, aad: &[u8]) -> Vec<u8> {
        sig_structure_data(
            SignatureContext::CoseSign1,
            self.protected.clone(),
            None,
            aad,
            self.payload.as_ref().unwrap_or(&vec![]),
        )
    }
}

/// Builder for [`CoseSign1`] objects.
#[derive(Default)]
pub struct CoseSign1Builder(CoseSign1);

impl CoseSign1Builder {
    builder! {CoseSign1}
    builder_set! {protected: Header}
    builder_set! {unprotected: Header}
    builder_set! {signature: Vec<u8>}
    builder_set_optional! {payload: Vec<u8>}

    /// Calculate the signature value, using `signer` to generate the signature bytes.  Any
    /// protected header values should be set before using this method.
    pub fn create_signature<F>(self, aad: &[u8], signer: F) -> Self
    where
        F: FnOnce(&[u8]) -> Vec<u8>,
    {
        let sig_data = signer(&self.0.tbs_data(aad));
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
    body: Header,
    sign: Option<Header>,
    aad: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut arr = vec![
        Value::TextString(context.text().to_owned()),
        if body.is_empty() {
            Value::ByteString(vec![])
        } else {
            Value::ByteString(
                body.to_vec().expect("failed to serialize header"), // safe: always serializable
            )
        },
    ];
    if let Some(sign) = sign {
        if sign.is_empty() {
            arr.push(Value::ByteString(vec![]));
        } else {
            arr.push(Value::ByteString(
                sign.to_vec().expect("failed to serialize header"), // safe: always serializable
            ));
        }
    }
    arr.push(Value::ByteString(aad.to_vec()));
    arr.push(Value::ByteString(payload.to_vec()));
    let mut data = Vec::new();
    cbor::writer::write(Value::Array(arr), &mut data).unwrap(); // safe: always serializable
    data
}
