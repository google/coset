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
    cbor::value::Value,
    common::AsCborValue,
    iana,
    iana::EnumI64,
    util::{cbor_type_error, to_cbor_array, ValueTryAs},
    Algorithm, CborSerializable, CoseError, CoseSignature, Label, RegisteredLabelWithPrivate,
    Result,
};
use alloc::{collections::BTreeSet, string::String, vec, vec::Vec};

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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Header {
    /// Cryptographic algorithm to use
    pub alg: Option<Algorithm>,
    /// Critical headers to be understood
    pub crit: Vec<RegisteredLabelWithPrivate<iana::HeaderParameter>>,
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
    /// Any additional header (label,value) pairs.  If duplicate labels are present, CBOR-encoding
    /// will fail.
    pub rest: Vec<(Label, Value)>,
}

impl Header {
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

const ALG: Label = Label::Int(iana::HeaderParameter::Alg as i64);
const CRIT: Label = Label::Int(iana::HeaderParameter::Crit as i64);
const CONTENT_TYPE: Label = Label::Int(iana::HeaderParameter::ContentType as i64);
const KID: Label = Label::Int(iana::HeaderParameter::Kid as i64);
const IV: Label = Label::Int(iana::HeaderParameter::Iv as i64);
const PARTIAL_IV: Label = Label::Int(iana::HeaderParameter::PartialIv as i64);
const COUNTER_SIG: Label = Label::Int(iana::HeaderParameter::CounterSignature as i64);

impl AsCborValue for Header {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let m = value.try_as_map()?;
        let mut headers = Self::default();
        let mut seen = BTreeSet::new();
        for (l, value) in m.into_iter() {
            // The `ciborium` CBOR library does not police duplicate map keys.
            // RFC 8152 section 14 requires that COSE does police duplicates, so do it here.
            let label = Label::from_cbor_value(l)?;
            if seen.contains(&label) {
                return Err(CoseError::DuplicateMapKey);
            }
            seen.insert(label.clone());
            match label {
                ALG => headers.alg = Some(Algorithm::from_cbor_value(value)?),

                CRIT => match value {
                    Value::Array(a) => {
                        if a.is_empty() {
                            return Err(CoseError::UnexpectedItem(
                                "empty array",
                                "non-empty array",
                            ));
                        }
                        for v in a {
                            headers.crit.push(
                                RegisteredLabelWithPrivate::<iana::HeaderParameter>::from_cbor_value(v)?,
                            );
                        }
                    }
                    v => return cbor_type_error(&v, "array value"),
                },

                CONTENT_TYPE => {
                    headers.content_type = Some(ContentType::from_cbor_value(value)?);
                    if let Some(ContentType::Text(text)) = &headers.content_type {
                        if text.is_empty() {
                            return Err(CoseError::UnexpectedItem("empty tstr", "non-empty tstr"));
                        }
                        if text.trim() != text {
                            return Err(CoseError::UnexpectedItem(
                                "leading/trailing whitespace",
                                "no leading/trailing whitespace",
                            ));
                        }
                        // Basic check that the content type is of form type/subtype.
                        // We don't check the precise definition though (RFC 6838 s4.2)
                        if text.matches('/').count() != 1 {
                            return Err(CoseError::UnexpectedItem(
                                "arbitrary text",
                                "text of form type/subtype",
                            ));
                        }
                    }
                }

                KID => {
                    headers.key_id = value.try_as_nonempty_bytes()?;
                }

                IV => {
                    headers.iv = value.try_as_nonempty_bytes()?;
                }

                PARTIAL_IV => {
                    headers.partial_iv = value.try_as_nonempty_bytes()?;
                }
                COUNTER_SIG => {
                    let sig_or_sigs = value.try_as_array()?;
                    if sig_or_sigs.is_empty() {
                        return Err(CoseError::UnexpectedItem(
                            "empty sig array",
                            "non-empty sig array",
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
                        Value::Bytes(_) => headers
                            .counter_signatures
                            .push(CoseSignature::from_cbor_value(Value::Array(sig_or_sigs))?),
                        Value::Array(_) => {
                            for sig in sig_or_sigs.into_iter() {
                                headers
                                    .counter_signatures
                                    .push(CoseSignature::from_cbor_value(sig)?);
                            }
                        }
                        v => return cbor_type_error(v, "array or bstr value"),
                    }
                }

                label => headers.rest.push((label, value)),
            }
            // RFC 8152 section 3.1: "The 'Initialization Vector' and 'Partial Initialization
            // Vector' parameters MUST NOT both be present in the same security layer."
            if !headers.iv.is_empty() && !headers.partial_iv.is_empty() {
                return Err(CoseError::UnexpectedItem(
                    "IV and partial-IV specified",
                    "only one of IV and partial IV",
                ));
            }
        }
        Ok(headers)
    }

    fn to_cbor_value(mut self) -> Result<Value> {
        let mut map = Vec::<(Value, Value)>::new();
        if let Some(alg) = self.alg {
            map.push((ALG.to_cbor_value()?, alg.to_cbor_value()?));
        }
        if !self.crit.is_empty() {
            map.push((CRIT.to_cbor_value()?, to_cbor_array(self.crit)?));
        }
        if let Some(content_type) = self.content_type {
            map.push((CONTENT_TYPE.to_cbor_value()?, content_type.to_cbor_value()?));
        }
        if !self.key_id.is_empty() {
            map.push((KID.to_cbor_value()?, Value::Bytes(self.key_id)));
        }
        if !self.iv.is_empty() {
            map.push((IV.to_cbor_value()?, Value::Bytes(self.iv)));
        }
        if !self.partial_iv.is_empty() {
            map.push((PARTIAL_IV.to_cbor_value()?, Value::Bytes(self.partial_iv)));
        }
        if !self.counter_signatures.is_empty() {
            if self.counter_signatures.len() == 1 {
                // A single counter signature is encoded differently.
                map.push((
                    COUNTER_SIG.to_cbor_value()?,
                    self.counter_signatures.remove(0).to_cbor_value()?,
                ));
            } else {
                map.push((
                    COUNTER_SIG.to_cbor_value()?,
                    to_cbor_array(self.counter_signatures)?,
                ));
            }
        }
        let mut seen = BTreeSet::new();
        for (label, value) in self.rest.into_iter() {
            if seen.contains(&label) {
                return Err(CoseError::DuplicateMapKey);
            }
            seen.insert(label.clone());
            map.push((label.to_cbor_value()?, value));
        }
        Ok(Value::Map(map))
    }
}

/// Builder for [`Header`] objects.
#[derive(Debug, Default)]
pub struct HeaderBuilder(Header);

impl HeaderBuilder {
    builder! {Header}
    builder_set! {key_id: Vec<u8>}

    /// Set the algorithm.
    #[must_use]
    pub fn algorithm(self, alg: iana::Algorithm) -> Self {
        self.algorithm_label(alg.into())
    }

    /// Set the algorithm.
    #[must_use]
    pub fn algorithm_label(mut self, label: RegisteredLabelWithPrivate<iana::Algorithm>) -> Self {
        self.0.alg = Some(label);
        self
    }

    /// Add a critical header.
    #[must_use]
    pub fn add_critical(self, param: iana::HeaderParameter) -> Self {
        self.add_critical_label(param.into())
    }

    /// Add a critical header.
    #[must_use]
    pub fn add_critical_label(
        mut self,
        label: RegisteredLabelWithPrivate<iana::HeaderParameter>,
    ) -> Self {
        self.0.crit.push(label);
        self
    }

    /// Set the content type to a numeric value.
    #[must_use]
    pub fn content_format(mut self, content_type: iana::CoapContentFormat) -> Self {
        self.0.content_type = Some(ContentType::Assigned(content_type));
        self
    }

    /// Set the content type to a text value.
    #[must_use]
    pub fn content_type(mut self, content_type: String) -> Self {
        self.0.content_type = Some(ContentType::Text(content_type));
        self
    }

    /// Set the IV, and clear any partial IV already set.
    #[must_use]
    pub fn iv(mut self, iv: Vec<u8>) -> Self {
        self.0.iv = iv;
        self.0.partial_iv.clear();
        self
    }

    /// Set the partial IV, and clear any IV already set.
    #[must_use]
    pub fn partial_iv(mut self, iv: Vec<u8>) -> Self {
        self.0.partial_iv = iv;
        self.0.iv.clear();
        self
    }

    /// Add a counter signature.
    #[must_use]
    pub fn add_counter_signature(mut self, sig: CoseSignature) -> Self {
        self.0.counter_signatures.push(sig);
        self
    }

    /// Set a header label:value pair. If duplicate labels are added to a [`Header`],
    /// subsequent attempts to CBOR-encode the header will fail.
    ///
    /// # Panics
    ///
    /// This function will panic if it used to set a header label from the range [1, 6].
    #[must_use]
    pub fn value(mut self, label: i64, value: Value) -> Self {
        if label >= iana::HeaderParameter::Alg.to_i64()
            && label <= iana::HeaderParameter::CounterSignature.to_i64()
        {
            panic!("value() method used to set core header parameter"); // safe: invalid input
        }
        self.0.rest.push((Label::Int(label), value));
        self
    }

    /// Set a header label:value pair where the `label` is text.
    #[must_use]
    pub fn text_value(mut self, label: String, value: Value) -> Self {
        self.0.rest.push((Label::Text(label), value));
        self
    }
}

/// Structure representing a protected COSE header map.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProtectedHeader {
    /// If this structure was created by parsing serialized data, this field
    /// holds the entire contents of the original `bstr` data.
    pub original_data: Option<Vec<u8>>,
    /// Parsed header information.
    pub header: Header,
}

impl ProtectedHeader {
    /// Constructor from a [`Value`] that holds a `bstr` encoded header.
    #[inline]
    pub fn from_cbor_bstr(val: Value) -> Result<Self> {
        let data = val.try_as_bytes()?;
        let header = if data.is_empty() {
            // An empty bstr is used as a short cut for an empty header map.
            Header::default()
        } else {
            Header::from_slice(&data)?
        };
        Ok(ProtectedHeader {
            original_data: Some(data),
            header,
        })
    }

    /// Convert this header to a `bstr` encoded map, as a [`Value`], consuming the object along the
    /// way.
    #[inline]
    pub fn cbor_bstr(self) -> Result<Value> {
        Ok(Value::Bytes(
            if let Some(original_data) = self.original_data {
                original_data
            } else if self.is_empty() {
                vec![]
            } else {
                self.to_vec()?
            },
        ))
    }

    /// Indicate whether the `ProtectedHeader` is empty.
    pub fn is_empty(&self) -> bool {
        self.header.is_empty()
    }
}

impl crate::CborSerializable for ProtectedHeader {}

impl AsCborValue for ProtectedHeader {
    fn from_cbor_value(value: Value) -> Result<Self> {
        Ok(ProtectedHeader {
            original_data: None,
            header: Header::from_cbor_value(value)?,
        })
    }

    fn to_cbor_value(self) -> Result<Value> {
        self.header.to_cbor_value()
    }
}
