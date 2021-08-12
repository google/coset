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

//! COSE Headers functionality.

use crate::{
    iana,
    iana::EnumI128,
    util::{cbor_type_error, AsCborValue},
    Algorithm, CborSerializable, CoseSignature, Label, RegisteredLabel,
};
use serde::de::Unexpected;
use serde_cbor as cbor;
use std::collections::{btree_map::Entry, BTreeMap};

#[cfg(test)]
mod tests;

/// Content type.
pub type ContentType = crate::RegisteredLabel<iana::CoapContentFormat>;

/// Structure representing a common COSE header map.
///
/// ```cddl
///   header_map = {
///       Generic_Headers,
///       * label => values
///   }
///
///   Generic_Headers = (
///       ? 1 => int / tstr,  ; algorithm identifier
///       ? 2 => [+label],    ; criticality
///       ? 3 => tstr / int,  ; content type
///       ? 4 => bstr,        ; key identifier
///       ? 5 => bstr,        ; IV
///       ? 6 => bstr,        ; Partial IV
///       ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
///   )
///  ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Header {
    /// Cryptographic algorithm to use
    pub alg: Option<Algorithm>,
    /// Critical headers to be understood
    pub crit: Vec<RegisteredLabel<iana::HeaderParameter>>,
    /// Content type of the payload
    pub content_type: Option<ContentType>,
    /// Key identifier.
    pub key_id: Vec<u8>,
    /// Full initialization vector
    pub iv: Vec<u8>,
    /// Partial initialization vector
    pub partial_iv: Vec<u8>,
    /// Counter signature
    pub counter_signatures: Vec<CoseSignature>,
    /// Any additional header values.
    pub rest: BTreeMap<Label, cbor::Value>,
}

impl Header {
    /// Constructor from a [`cbor::Value`] that holds a `bstr` encoded header.
    #[inline]
    pub fn from_cbor_bstr<E: serde::de::Error>(val: cbor::Value) -> Result<Self, E> {
        let data = match val {
            cbor::Value::Bytes(b) => b,
            v => return cbor_type_error(&v, &"bstr encoded map"),
        };
        if data.is_empty() {
            return Ok(Self::default());
        }
        Header::from_slice(&data).map_err(|_e| {
            serde::de::Error::invalid_value(Unexpected::StructVariant, &"header struct")
        })
    }

    /// Convert this header to a `bstr` encoded map, as a [`cbor::Value`].
    #[inline]
    pub fn to_cbor_bstr(&self) -> cbor::Value {
        cbor::Value::Bytes(if self.is_empty() {
            vec![]
        } else {
            self.to_vec().expect("failed to serialize header") // safe: Header always serializable
        })
    }

    /// Indicate whether the `Header` is empty.
    pub fn is_empty(&self) -> bool {
        self.alg.is_none()
            && self.crit.is_empty()
            && self.content_type.is_none()
            && self.key_id.is_empty()
            && self.iv.is_empty()
            && self.partial_iv.is_empty()
            && self.counter_signatures.is_empty()
            && self.rest.is_empty()
    }
}

impl crate::CborSerializable for Header {}

const ALG: cbor::Value = cbor::Value::Integer(iana::HeaderParameter::Alg as i128);
const CRIT: cbor::Value = cbor::Value::Integer(iana::HeaderParameter::Crit as i128);
const CONTENT_TYPE: cbor::Value = cbor::Value::Integer(iana::HeaderParameter::ContentType as i128);
const KID: cbor::Value = cbor::Value::Integer(iana::HeaderParameter::Kid as i128);
const IV: cbor::Value = cbor::Value::Integer(iana::HeaderParameter::Iv as i128);
const PARTIAL_IV: cbor::Value = cbor::Value::Integer(iana::HeaderParameter::PartialIv as i128);
const COUNTER_SIG: cbor::Value =
    cbor::Value::Integer(iana::HeaderParameter::CounterSignature as i128);

impl AsCborValue for Header {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        let m = match value {
            cbor::Value::Map(m) => m,
            v => return cbor_type_error(&v, &"map"),
        };

        let mut headers = Self::default();
        for (label, value) in m.into_iter() {
            match label {
                x if x == ALG => headers.alg = Some(Algorithm::from_cbor_value(value)?),

                x if x == CRIT => match value {
                    cbor::Value::Array(a) => {
                        if a.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::TupleVariant,
                                &"non-empty array",
                            ));
                        }
                        for v in a {
                            headers.crit.push(
                                RegisteredLabel::<iana::HeaderParameter>::from_cbor_value(v)?,
                            );
                        }
                    }
                    v => return cbor_type_error(&v, &"array value"),
                },

                x if x == CONTENT_TYPE => {
                    headers.content_type = Some(ContentType::from_cbor_value(value)?);
                    if let Some(ContentType::Text(text)) = &headers.content_type {
                        if text.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::Str(text),
                                &"non-empty string",
                            ));
                        }
                        if text.trim() != text {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::Str(text),
                                &"no leading/trailing whitespace",
                            ));
                        }
                        // Basic check that the content type is of form type/subtype.
                        // We don't check the precise definition though (RFC 6838 s4.2)
                        if text.matches('/').count() != 1 {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::Str(text),
                                &"text of form type/subtype",
                            ));
                        }
                    }
                }

                x if x == KID => match value {
                    cbor::Value::Bytes(v) => {
                        if v.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::Bytes(&v),
                                &"non-empty bstr",
                            ));
                        }
                        headers.key_id = v;
                    }
                    v => return cbor_type_error(&v, &"bstr value"),
                },

                x if x == IV => match value {
                    cbor::Value::Bytes(v) => {
                        if v.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::Bytes(&v),
                                &"non-empty bstr",
                            ));
                        }
                        headers.iv = v;
                    }
                    v => return cbor_type_error(&v, &"bstr value"),
                },

                x if x == PARTIAL_IV => match value {
                    cbor::Value::Bytes(v) => {
                        if v.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::Bytes(&v),
                                &"non-empty bstr",
                            ));
                        }
                        headers.partial_iv = v;
                    }
                    v => return cbor_type_error(&v, &"bstr value"),
                },
                x if x == COUNTER_SIG => match value {
                    cbor::Value::Array(sig_or_sigs) => {
                        if sig_or_sigs.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::TupleVariant,
                                &"non-empty array",
                            ));
                        }
                        // The encoding of counter signature[s] is pesky:
                        // - a single counter signature is encoded as `COSE_Signature` (a 3-tuple)
                        // - multiple counter signatures are encoded as `[+ COSE_Signature]`
                        //
                        // Determine which is which by looking at the first entry of the array:
                        // - If it's a bstr, sig_or_sigs is a single signature.
                        // - If it's an array, sig_or_sigs is an array of signatures
                        match &sig_or_sigs[0] {
                            cbor::Value::Bytes(_) => {
                                headers
                                    .counter_signatures
                                    .push(CoseSignature::from_cbor_value(cbor::Value::Array(
                                        sig_or_sigs,
                                    ))?)
                            }
                            cbor::Value::Array(_) => {
                                for sig in sig_or_sigs.into_iter() {
                                    headers
                                        .counter_signatures
                                        .push(CoseSignature::from_cbor_value(sig)?);
                                }
                            }
                            v => return cbor_type_error(v, &"array or bstr value"),
                        }
                    }
                    v => return cbor_type_error(&v, &"array value"),
                },

                l => {
                    let label = Label::from_cbor_value(l)?;
                    match headers.rest.entry(label) {
                        Entry::Occupied(_) => {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::StructVariant,
                                &"unique map label",
                            ));
                        }
                        Entry::Vacant(ve) => {
                            ve.insert(value);
                        }
                    }
                }
            }
            // RFC 8152 section 3.1: "The 'Initialization Vector' and 'Partial Initialization
            // Vector' parameters MUST NOT both be present in the same security layer."
            if !headers.iv.is_empty() && !headers.partial_iv.is_empty() {
                return Err(serde::de::Error::invalid_value(
                    Unexpected::StructVariant,
                    &"only one of IV and partial IV",
                ));
            }
        }
        Ok(headers)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut map = BTreeMap::<cbor::Value, cbor::Value>::new();
        if let Some(alg) = &self.alg {
            map.insert(ALG, alg.to_cbor_value());
        }
        if !self.crit.is_empty() {
            map.insert(
                CRIT,
                cbor::Value::Array(self.crit.iter().map(|c| c.to_cbor_value()).collect()),
            );
        }
        if let Some(content_type) = &self.content_type {
            map.insert(CONTENT_TYPE, content_type.to_cbor_value());
        }
        if !self.key_id.is_empty() {
            map.insert(KID, cbor::Value::Bytes(self.key_id.to_vec()));
        }
        if !self.iv.is_empty() {
            map.insert(IV, cbor::Value::Bytes(self.iv.to_vec()));
        }
        if !self.partial_iv.is_empty() {
            map.insert(PARTIAL_IV, cbor::Value::Bytes(self.partial_iv.to_vec()));
        }
        if !self.counter_signatures.is_empty() {
            if self.counter_signatures.len() == 1 {
                // A single counter signature is encoded differently.
                map.insert(COUNTER_SIG, self.counter_signatures[0].to_cbor_value());
            } else {
                map.insert(
                    COUNTER_SIG,
                    cbor::Value::Array(
                        self.counter_signatures
                            .iter()
                            .map(|s| s.to_cbor_value())
                            .collect(),
                    ),
                );
            }
        }
        for (label, value) in &self.rest {
            map.insert(label.to_cbor_value(), value.clone());
        }
        cbor::Value::Map(map)
    }
}

cbor_serialize!(Header);

/// Builder for [`Header`] objects.
#[derive(Default)]
pub struct HeaderBuilder(Header);

impl HeaderBuilder {
    builder! {Header}
    builder_set! {key_id: Vec<u8>}

    /// Set the algorithm.
    pub fn algorithm(mut self, alg: iana::Algorithm) -> Self {
        self.0.alg = Some(Algorithm::Assigned(alg));
        self
    }

    /// Add a critical header.
    pub fn add_critical(mut self, param: iana::HeaderParameter) -> Self {
        self.0.crit.push(RegisteredLabel::Assigned(param));
        self
    }

    /// Add a critical header.
    pub fn add_critical_label(mut self, label: RegisteredLabel<iana::HeaderParameter>) -> Self {
        self.0.crit.push(label);
        self
    }

    /// Set the content type to a numeric value.
    pub fn content_format(mut self, content_type: iana::CoapContentFormat) -> Self {
        self.0.content_type = Some(ContentType::Assigned(content_type));
        self
    }

    /// Set the content type to a text value.
    pub fn content_type(mut self, content_type: String) -> Self {
        self.0.content_type = Some(ContentType::Text(content_type));
        self
    }

    /// Set the IV, and clear any partial IV already set.
    pub fn iv(mut self, iv: Vec<u8>) -> Self {
        self.0.iv = iv;
        self.0.partial_iv.clear();
        self
    }

    /// Set the partial IV, and clear any IV already set.
    pub fn partial_iv(mut self, iv: Vec<u8>) -> Self {
        self.0.partial_iv = iv;
        self.0.iv.clear();
        self
    }

    /// Add a counter signature.
    pub fn add_counter_signature(mut self, sig: CoseSignature) -> Self {
        self.0.counter_signatures.push(sig);
        self
    }

    /// Set a header label:value pair.
    ///
    /// # Panics
    ///
    /// This function will panic if it used to set a header label from the range [1, 6].
    pub fn value(mut self, label: i128, value: cbor::Value) -> Self {
        if label >= iana::HeaderParameter::Alg.to_i128()
            && label <= iana::HeaderParameter::CounterSignature.to_i128()
        {
            panic!("value() method used to set core header parameter"); // safe: invalid input
        }
        self.0.rest.insert(Label::Int(label), value);
        self
    }

    /// Set a header label:value pair where the `label` is text.
    pub fn text_value(mut self, label: String, value: cbor::Value) -> Self {
        self.0.rest.insert(Label::Text(label), value);
        self
    }
}
