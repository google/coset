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

//! COSE_Encrypt functionality.

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

/// Structure representing the recipient of encrypted data.
///
/// ```cddl
///  COSE_Recipient = [
///      Headers,
///      ciphertext : bstr / nil,
///      ? recipients : [+COSE_recipient]
///  ]
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseRecipient {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub ciphertext: Option<Vec<u8>>,
    pub recipients: Vec<CoseRecipient>,
}

impl crate::CborSerializable for CoseRecipient {}

impl AsCborValue for CoseRecipient {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 3 && a.len() != 4 {
            return Err(CoseError::UnexpectedItem(
                "array",
                "array with 3 or 4 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        let recipients = if a.len() == 4 {
            a.remove(3)
                .try_as_array_then_convert(CoseRecipient::from_cbor_value)?
        } else {
            Vec::new()
        };

        Ok(Self {
            recipients,
            ciphertext: match a.remove(2) {
                Value::Bytes(b) => Some(b),
                Value::Null => None,
                v => return cbor_type_error(&v, "bstr / null"),
            },
            unprotected: Header::from_cbor_value(a.remove(1))?,
            protected: ProtectedHeader::from_cbor_bstr(a.remove(0))?,
        })
    }

    fn to_cbor_value(self) -> Result<Value> {
        let mut v = vec![
            self.protected.cbor_bstr()?,
            self.unprotected.to_cbor_value()?,
            match self.ciphertext {
                None => Value::Null,
                Some(b) => Value::Bytes(b),
            },
        ];
        if !self.recipients.is_empty() {
            v.push(to_cbor_array(self.recipients)?);
        }
        Ok(Value::Array(v))
    }
}

impl CoseRecipient {
    /// Decrypt the `ciphertext` value with an AEAD, using `cipher` to decrypt the cipher text and
    /// combined AAD as per RFC 8152 section 5.3.
    ///
    /// # Panics
    ///
    /// This function will panic if no `ciphertext` is available. It will also panic
    /// if the `context` parameter does not refer to a recipient context.
    pub fn decrypt<F, E>(
        &self,
        context: EncryptionContext,
        external_aad: &[u8],
        cipher: F,
    ) -> Result<Vec<u8>, E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, E>,
    {
        let ct = self.ciphertext.as_ref().unwrap(/* safe: documented */);
        match context {
            EncryptionContext::EncRecipient
            | EncryptionContext::MacRecipient
            | EncryptionContext::RecRecipient => {}
            _ => panic!("unsupported encryption context {:?}", context), // safe: documented
        }
        let aad = enc_structure_data(context, self.protected.clone(), external_aad);
        cipher(ct, &aad)
    }
}

/// Builder for [`CoseRecipient`] objects.
#[derive(Debug, Default)]
pub struct CoseRecipientBuilder(CoseRecipient);

impl CoseRecipientBuilder {
    builder! {CoseRecipient}
    builder_set_protected! {protected}
    builder_set! {unprotected: Header}
    builder_set_optional! {ciphertext: Vec<u8>}

    /// Add a [`CoseRecipient`].
    #[must_use]
    pub fn add_recipient(mut self, recipient: CoseRecipient) -> Self {
        self.0.recipients.push(recipient);
        self
    }

    /// Calculate the ciphertext value with an AEAD, using `cipher` to generate the encrypted bytes
    /// from the plaintext and combined AAD (in that order) as per RFC 8152 section 5.3.  Any
    /// protected header values should be set before using this method.
    ///
    /// # Panics
    ///
    /// This function will panic if the `context` parameter does not refer to a recipient context.
    #[must_use]
    pub fn create_ciphertext<F>(
        self,
        context: EncryptionContext,
        plaintext: &[u8],
        external_aad: &[u8],
        cipher: F,
    ) -> Self
    where
        F: FnOnce(&[u8], &[u8]) -> Vec<u8>,
    {
        let aad = self.aad(context, external_aad);
        self.ciphertext(cipher(plaintext, &aad))
    }

    /// Calculate the ciphertext value with an AEAD, using `cipher` to generate the encrypted bytes
    /// from the plaintext and combined AAD (in that order) as per RFC 8152 section 5.3.  Any
    /// protected header values should be set before using this method.
    ///
    /// # Panics
    ///
    /// This function will panic if the `context` parameter does not refer to a recipient context.
    pub fn try_create_ciphertext<F, E>(
        self,
        context: EncryptionContext,
        plaintext: &[u8],
        external_aad: &[u8],
        cipher: F,
    ) -> Result<Self, E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, E>,
    {
        let aad = self.aad(context, external_aad);
        Ok(self.ciphertext(cipher(plaintext, &aad)?))
    }

    /// Construct the combined AAD data needed for encryption with an AEAD. Any protected header
    /// values should be set before using this method.
    ///
    /// # Panics
    ///
    /// This function will panic if the `context` parameter does not refer to a recipient context.
    #[must_use]
    fn aad(&self, context: EncryptionContext, external_aad: &[u8]) -> Vec<u8> {
        match context {
            EncryptionContext::EncRecipient
            | EncryptionContext::MacRecipient
            | EncryptionContext::RecRecipient => {}
            _ => panic!("unsupported encryption context {:?}", context), // safe: documented
        }
        enc_structure_data(context, self.0.protected.clone(), external_aad)
    }
}

/// Structure representing an encrypted object.
///
/// ```cddl
///  COSE_Encrypt = [
///      Headers,
///      ciphertext : bstr / nil,
///      recipients : [+COSE_recipient]
///  ]
///  ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseEncrypt {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub ciphertext: Option<Vec<u8>>,
    pub recipients: Vec<CoseRecipient>,
}

impl crate::CborSerializable for CoseEncrypt {}

impl crate::TaggedCborSerializable for CoseEncrypt {
    const TAG: u64 = iana::CborTag::CoseEncrypt as u64;
}

impl AsCborValue for CoseEncrypt {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 4 {
            return Err(CoseError::UnexpectedItem("array", "array with 4 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        let recipients = a
            .remove(3)
            .try_as_array_then_convert(CoseRecipient::from_cbor_value)?;
        Ok(Self {
            recipients,
            ciphertext: match a.remove(2) {
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
            match self.ciphertext {
                None => Value::Null,
                Some(b) => Value::Bytes(b),
            },
            to_cbor_array(self.recipients)?,
        ]))
    }
}

impl CoseEncrypt {
    /// Decrypt the `ciphertext` value with an AEAD, using `cipher` to decrypt the cipher text and
    /// combined AAD.
    ///
    /// # Panics
    ///
    /// This function will panic if no `ciphertext` is available.
    pub fn decrypt<F, E>(&self, external_aad: &[u8], cipher: F) -> Result<Vec<u8>, E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, E>,
    {
        let ct = self.ciphertext.as_ref().unwrap(/* safe: documented */);
        let aad = enc_structure_data(
            EncryptionContext::CoseEncrypt,
            self.protected.clone(),
            external_aad,
        );
        cipher(ct, &aad)
    }
}

/// Builder for [`CoseEncrypt`] objects.
#[derive(Debug, Default)]
pub struct CoseEncryptBuilder(CoseEncrypt);

impl CoseEncryptBuilder {
    builder! {CoseEncrypt}
    builder_set_protected! {protected}
    builder_set! {unprotected: Header}
    builder_set_optional! {ciphertext: Vec<u8>}

    /// Calculate the ciphertext value with an AEAD, using `cipher` to generate the encrypted bytes
    /// from the plaintext and combined AAD (in that order) as per RFC 8152 section 5.3.  Any
    /// protected header values should be set before using this method.
    #[must_use]
    pub fn create_ciphertext<F>(self, plaintext: &[u8], external_aad: &[u8], cipher: F) -> Self
    where
        F: FnOnce(&[u8], &[u8]) -> Vec<u8>,
    {
        let aad = enc_structure_data(
            EncryptionContext::CoseEncrypt,
            self.0.protected.clone(),
            external_aad,
        );
        self.ciphertext(cipher(plaintext, &aad))
    }

    /// Calculate the ciphertext value with an AEAD, using `cipher` to generate the encrypted bytes
    /// from the plaintext and combined AAD (in that order) as per RFC 8152 section 5.3.  Any
    /// protected header values should be set before using this method.
    pub fn try_create_ciphertext<F, E>(
        self,
        plaintext: &[u8],
        external_aad: &[u8],
        cipher: F,
    ) -> Result<Self, E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, E>,
    {
        let aad = enc_structure_data(
            EncryptionContext::CoseEncrypt,
            self.0.protected.clone(),
            external_aad,
        );
        Ok(self.ciphertext(cipher(plaintext, &aad)?))
    }

    /// Add a [`CoseRecipient`].
    #[must_use]
    pub fn add_recipient(mut self, recipient: CoseRecipient) -> Self {
        self.0.recipients.push(recipient);
        self
    }
}

/// Structure representing an encrypted object.
///
/// ```cddl
///  COSE_Encrypt0 = [
///      Headers,
///      ciphertext : bstr / nil,
///  ]
///  ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseEncrypt0 {
    pub protected: ProtectedHeader,
    pub unprotected: Header,
    pub ciphertext: Option<Vec<u8>>,
}

impl crate::CborSerializable for CoseEncrypt0 {}

impl crate::TaggedCborSerializable for CoseEncrypt0 {
    const TAG: u64 = iana::CborTag::CoseEncrypt0 as u64;
}

impl AsCborValue for CoseEncrypt0 {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 3 {
            return Err(CoseError::UnexpectedItem("array", "array with 3 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            ciphertext: match a.remove(2) {
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
            match self.ciphertext {
                None => Value::Null,
                Some(b) => Value::Bytes(b),
            },
        ]))
    }
}

impl CoseEncrypt0 {
    /// Decrypt the `ciphertext` value with an AEAD, using `cipher` to decrypt the cipher text and
    /// combined AAD.
    ///
    /// # Panics
    ///
    /// This function will panic if no `ciphertext` is available.
    pub fn decrypt<F, E>(&self, external_aad: &[u8], cipher: F) -> Result<Vec<u8>, E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, E>,
    {
        let ct = self.ciphertext.as_ref().unwrap(/* safe: documented */);
        let aad = enc_structure_data(
            EncryptionContext::CoseEncrypt0,
            self.protected.clone(),
            external_aad,
        );
        cipher(ct, &aad)
    }
}

/// Builder for [`CoseEncrypt0`] objects.
#[derive(Debug, Default)]
pub struct CoseEncrypt0Builder(CoseEncrypt0);

impl CoseEncrypt0Builder {
    builder! {CoseEncrypt0}
    builder_set_protected! {protected}
    builder_set! {unprotected: Header}
    builder_set_optional! {ciphertext: Vec<u8>}

    /// Calculate the ciphertext value with an AEAD, using `cipher` to generate the encrypted bytes
    /// from the plaintext and combined AAD (in that order) as per RFC 8152 section 5.3.  Any
    /// protected header values should be set before using this method.
    #[must_use]
    pub fn create_ciphertext<F>(self, plaintext: &[u8], external_aad: &[u8], cipher: F) -> Self
    where
        F: FnOnce(&[u8], &[u8]) -> Vec<u8>,
    {
        let aad = enc_structure_data(
            EncryptionContext::CoseEncrypt0,
            self.0.protected.clone(),
            external_aad,
        );
        self.ciphertext(cipher(plaintext, &aad))
    }

    /// Calculate the ciphertext value with an AEAD, using `cipher` to generate the encrypted bytes
    /// from the plaintext and combined AAD (in that order) as per RFC 8152 section 5.3.  Any
    /// protected header values should be set before using this method.
    pub fn try_create_ciphertext<F, E>(
        self,
        plaintext: &[u8],
        external_aad: &[u8],
        cipher: F,
    ) -> Result<Self, E>
    where
        F: FnOnce(&[u8], &[u8]) -> Result<Vec<u8>, E>,
    {
        let aad = enc_structure_data(
            EncryptionContext::CoseEncrypt0,
            self.0.protected.clone(),
            external_aad,
        );
        Ok(self.ciphertext(cipher(plaintext, &aad)?))
    }
}

/// Possible encryption contexts.
#[derive(Clone, Copy, Debug)]
pub enum EncryptionContext {
    CoseEncrypt,
    CoseEncrypt0,
    EncRecipient,
    MacRecipient,
    RecRecipient,
}

impl EncryptionContext {
    /// Return the context string as per RFC 8152 section 5.3.
    fn text(&self) -> &'static str {
        match self {
            EncryptionContext::CoseEncrypt => "Encrypt",
            EncryptionContext::CoseEncrypt0 => "Encrypt0",
            EncryptionContext::EncRecipient => "Enc_Recipient",
            EncryptionContext::MacRecipient => "Mac_Recipient",
            EncryptionContext::RecRecipient => "Rec_Recipient",
        }
    }
}

/// Create a binary blob that will be signed.
//
/// ```cddl
///  Enc_structure = [
///      context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
///          "Mac_Recipient" / "Rec_Recipient",
///      protected : empty_or_serialized_map,
///      external_aad : bstr
///  ]
/// ```
pub fn enc_structure_data(
    context: EncryptionContext,
    protected: ProtectedHeader,
    external_aad: &[u8],
) -> Vec<u8> {
    let arr = vec![
        Value::Text(context.text().to_owned()),
        protected.cbor_bstr().expect("failed to serialize header"), // safe: always serializable
        Value::Bytes(external_aad.to_vec()),
    ];

    let mut data = Vec::new();
    cbor::ser::into_writer(&Value::Array(arr), &mut data).unwrap(); // safe: always serializable
    data
}
