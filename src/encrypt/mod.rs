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
    common::CborSerializable,
    iana,
    util::{cbor_type_error, AsCborValue},
    Header,
};
use serde::de::Unexpected;
use serde_cbor as cbor;

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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseRecipient {
    pub protected: Header,
    pub unprotected: Header,
    pub ciphertext: Option<Vec<u8>>,
    pub recipients: Vec<CoseRecipient>,
}

impl crate::CborSerializable for CoseRecipient {}

impl AsCborValue for CoseRecipient {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        let mut a = match value {
            cbor::Value::Array(a) => a,
            v => return cbor_type_error(&v, &"array"),
        };
        if a.len() != 3 && a.len() != 4 {
            return Err(serde::de::Error::invalid_value(
                Unexpected::TupleVariant,
                &"array with 3 or 4 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        let mut recipient = Self::default();
        if a.len() == 4 {
            match a.remove(3) {
                cbor::Value::Array(a) => {
                    for val in a {
                        recipient
                            .recipients
                            .push(CoseRecipient::from_cbor_value(val)?);
                    }
                }
                v => return cbor_type_error(&v, &"array"),
            }
        }

        recipient.ciphertext = match a.remove(2) {
            cbor::Value::Bytes(b) => Some(b),
            cbor::Value::Null => None,
            v => return cbor_type_error(&v, &"bstr / null"),
        };

        recipient.unprotected = Header::from_cbor_value(a.remove(1))?;
        recipient.protected = Header::from_cbor_bstr(a.remove(0))?;

        Ok(recipient)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        v.push(self.protected.to_cbor_bstr());
        v.push(self.unprotected.to_cbor_value());
        match &self.ciphertext {
            None => v.push(cbor::Value::Null),
            Some(b) => v.push(cbor::Value::Bytes(b.clone())),
        }
        if !self.recipients.is_empty() {
            v.push(cbor::Value::Array(
                self.recipients.iter().map(|r| r.to_cbor_value()).collect(),
            ));
        }
        cbor::Value::Array(v)
    }
}

cbor_serialize!(CoseRecipient);

impl CoseRecipient {
    /// Decrypt the `ciphertext` value, using `cipher` to decrypt the cipher text and
    /// combined AAD.
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
        let aad = enc_structure_data(context, &self.protected, external_aad);
        cipher(ct, &aad)
    }
}

/// Builder for `CoseRecipient` objects.
#[derive(Default)]
pub struct CoseRecipientBuilder(CoseRecipient);

impl CoseRecipientBuilder {
    builder! {CoseRecipient}
    builder_set! {protected: Header}
    builder_set! {unprotected: Header}

    /// Set the ciphertext.
    pub fn ciphertext(mut self, ciphertext: Vec<u8>) -> Self {
        self.0.ciphertext = Some(ciphertext);
        self
    }

    /// Add a [`CoseRecipient`].
    pub fn add_recipient(mut self, recipient: CoseRecipient) -> Self {
        self.0.recipients.push(recipient);
        self
    }

    /// Calculate the ciphertext value, using `cipher` to generate the encrypted bytes from the
    /// plaintext and combined AAD (in that order).  Any protected header values should be set
    /// before using this method.
    ///
    /// # Panics
    ///
    /// This function will panic if the `context` parameter does not refer to a recipient context.
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
        match context {
            EncryptionContext::EncRecipient
            | EncryptionContext::MacRecipient
            | EncryptionContext::RecRecipient => {}
            _ => panic!("unsupported encryption context {:?}", context), // safe: documented
        }
        let aad = enc_structure_data(context, &self.0.protected, external_aad);
        self.ciphertext(cipher(plaintext, &aad))
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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseEncrypt {
    pub protected: Header,
    pub unprotected: Header,
    pub ciphertext: Option<Vec<u8>>,
    pub recipients: Vec<CoseRecipient>,
}

impl crate::CborSerializable for CoseEncrypt {}

impl crate::TaggedCborSerializable for CoseEncrypt {
    const TAG: u64 = iana::CborTag::CoseEncrypt as u64;
}

impl AsCborValue for CoseEncrypt {
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
        let mut encrypted = Self::default();
        match a.remove(3) {
            cbor::Value::Array(a) => {
                for val in a {
                    encrypted
                        .recipients
                        .push(CoseRecipient::from_cbor_value(val)?);
                }
            }
            v => return cbor_type_error(&v, &"array"),
        }

        encrypted.ciphertext = match a.remove(2) {
            cbor::Value::Bytes(b) => Some(b),
            cbor::Value::Null => None,
            v => return cbor_type_error(&v, &"bstr"),
        };

        encrypted.unprotected = Header::from_cbor_value(a.remove(1))?;
        encrypted.protected = Header::from_cbor_bstr(a.remove(0))?;

        Ok(encrypted)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        v.push(self.protected.to_cbor_bstr());
        v.push(self.unprotected.to_cbor_value());
        match &self.ciphertext {
            None => v.push(cbor::Value::Null),
            Some(b) => v.push(cbor::Value::Bytes(b.clone())),
        }
        v.push(cbor::Value::Array(
            self.recipients.iter().map(|r| r.to_cbor_value()).collect(),
        ));
        cbor::Value::Array(v)
    }
}

cbor_serialize!(CoseEncrypt);

impl CoseEncrypt {
    /// Decrypt the `ciphertext` value, using `cipher` to decrypt the cipher text and
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
            &self.protected,
            external_aad,
        );
        cipher(ct, &aad)
    }
}

/// Builder for `CoseEncrypt` objects.
#[derive(Default)]
pub struct CoseEncryptBuilder(CoseEncrypt);

impl CoseEncryptBuilder {
    builder! {CoseEncrypt}
    builder_set! {protected: Header}
    builder_set! {unprotected: Header}

    /// Set the ciphertext.
    pub fn ciphertext(mut self, ciphertext: Vec<u8>) -> Self {
        self.0.ciphertext = Some(ciphertext);
        self
    }

    /// Calculate the ciphertext value, using `cipher` to generate the encrypted bytes from the
    /// plaintext and combined AAD (in that order).  Any protected header values should be set
    /// before using this method.
    pub fn create_ciphertext<F>(self, plaintext: &[u8], external_aad: &[u8], cipher: F) -> Self
    where
        F: FnOnce(&[u8], &[u8]) -> Vec<u8>,
    {
        let aad = enc_structure_data(
            EncryptionContext::CoseEncrypt,
            &self.0.protected,
            external_aad,
        );
        self.ciphertext(cipher(plaintext, &aad))
    }

    /// Add a [`CoseRecipient`].
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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseEncrypt0 {
    pub protected: Header,
    pub unprotected: Header,
    pub ciphertext: Option<Vec<u8>>,
}

impl crate::CborSerializable for CoseEncrypt0 {}

impl crate::TaggedCborSerializable for CoseEncrypt0 {
    const TAG: u64 = iana::CborTag::CoseEncrypt0 as u64;
}

impl AsCborValue for CoseEncrypt0 {
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
        let mut encrypted = Self::default();
        encrypted.ciphertext = match a.remove(2) {
            cbor::Value::Bytes(b) => Some(b),
            cbor::Value::Null => None,
            v => return cbor_type_error(&v, &"bstr"),
        };

        encrypted.unprotected = Header::from_cbor_value(a.remove(1))?;
        encrypted.protected = Header::from_cbor_bstr(a.remove(0))?;

        Ok(encrypted)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        v.push(self.protected.to_cbor_bstr());
        v.push(self.unprotected.to_cbor_value());
        match &self.ciphertext {
            None => v.push(cbor::Value::Null),
            Some(b) => v.push(cbor::Value::Bytes(b.clone())),
        }
        cbor::Value::Array(v)
    }
}

cbor_serialize!(CoseEncrypt0);

impl CoseEncrypt0 {
    /// Decrypt the `ciphertext` value, using `cipher` to decrypt the cipher text and
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
            &self.protected,
            external_aad,
        );
        cipher(ct, &aad)
    }
}

/// Builder for `CoseEncrypt0` objects.
#[derive(Default)]
pub struct CoseEncrypt0Builder(CoseEncrypt0);

impl CoseEncrypt0Builder {
    builder! {CoseEncrypt0}
    builder_set! {protected: Header}
    builder_set! {unprotected: Header}

    /// Set the ciphertext.
    pub fn ciphertext(mut self, ciphertext: Vec<u8>) -> Self {
        self.0.ciphertext = Some(ciphertext);
        self
    }

    /// Calculate the ciphertext value, using `cipher` to generate the encrypted bytes from the
    /// plaintext and combined AAD (in that order).  Any protected header values should be set
    /// before using this method.
    pub fn create_ciphertext<F>(self, plaintext: &[u8], external_aad: &[u8], cipher: F) -> Self
    where
        F: FnOnce(&[u8], &[u8]) -> Vec<u8>,
    {
        let aad = enc_structure_data(
            EncryptionContext::CoseEncrypt0,
            &self.0.protected,
            external_aad,
        );
        self.ciphertext(cipher(plaintext, &aad))
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
    protected: &Header,
    external_aad: &[u8],
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
    cbor::to_vec(&cbor::Value::Array(arr)).expect("failed to serialize Enc_structure") // safe: always serializable
}
