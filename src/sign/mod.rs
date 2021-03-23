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

//! COSE_Key functionality.

use crate::{
    common::CborSerializable,
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

        let prot_data = match a.remove(0) {
            cbor::Value::Bytes(b) => b,
            v => return cbor_type_error(&v, &"bstr encoded map"),
        };
        if !prot_data.is_empty() {
            sig.protected = match Header::from_slice(&prot_data) {
                Ok(h) => h,
                Err(_e) => {
                    return Err(serde::de::Error::invalid_value(
                        Unexpected::StructVariant,
                        &"header struct",
                    ));
                }
            };
        }

        Ok(sig)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = Vec::<cbor::Value>::new();
        let protected_data = if self.protected.is_empty() {
            vec![]
        } else {
            self.protected
                .to_vec()
                .expect("failed to serialize protected headers") // safe: Header always serializable
        };
        v.push(cbor::Value::Bytes(protected_data));
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
