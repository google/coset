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
    cbor::values::Value,
    iana,
    iana::EnumI128,
    util::{cbor_type_error, AsCborValue},
    Algorithm, CborSerializable, CoseError, CoseSignature, Label, RegisteredLabel,
};
use alloc::{string::String, vec, vec::Vec};

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
    /// Any additional header (label,value) pairs.  If duplicate labels are present, CBOR-encoding
    /// will fail.
    pub rest: Vec<(Label, Value)>,
}

impl Header {
    /// Constructor from a [`Value`] that holds a `bstr` encoded header.
    #[inline]
    pub fn from_cbor_bstr(val: Value) -> Result<Self, CoseError> {
        let data = match val {
            Value::ByteString(b) => b,
            v => return cbor_type_error(&v, "bstr encoded map"),
        };
        if data.is_empty() {
            return Ok(Self::default());
        }
        Header::from_slice(&data)
    }

    /// Convert this header to a `bstr` encoded map, as a [`Value`], consuming the object along the
    /// way.
    #[inline]
    pub fn cbor_bstr(self) -> Result<Value, CoseError> {
        Ok(Value::ByteString(if self.is_empty() {
            vec![]
        } else {
            self.to_vec()?
        }))
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

const ALG: Value = Value::Unsigned(iana::HeaderParameter::Alg as u64);
const CRIT: Value = Value::Unsigned(iana::HeaderParameter::Crit as u64);
const CONTENT_TYPE: Value = Value::Unsigned(iana::HeaderParameter::ContentType as u64);
const KID: Value = Value::Unsigned(iana::HeaderParameter::Kid as u64);
const IV: Value = Value::Unsigned(iana::HeaderParameter::Iv as u64);
const PARTIAL_IV: Value = Value::Unsigned(iana::HeaderParameter::PartialIv as u64);
const COUNTER_SIG: Value = Value::Unsigned(iana::HeaderParameter::CounterSignature as u64);

impl AsCborValue for Header {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let m = match value {
            Value::Map(m) => m,
            v => return cbor_type_error(&v, "map"),
        };

        let mut headers = Self::default();
        for (label, value) in m.into_iter() {
            match label {
                x if x == ALG => headers.alg = Some(Algorithm::from_cbor_value(value)?),

                x if x == CRIT => match value {
                    Value::Array(a) => {
                        if a.is_empty() {
                            return Err(CoseError::UnexpectedType(
                                "empty array",
                                "non-empty array",
                            ));
                        }
                        for v in a {
                            headers.crit.push(
                                RegisteredLabel::<iana::HeaderParameter>::from_cbor_value(v)?,
                            );
                        }
                    }
                    v => return cbor_type_error(&v, "array value"),
                },

                x if x == CONTENT_TYPE => {
                    headers.content_type = Some(ContentType::from_cbor_value(value)?);
                    if let Some(ContentType::Text(text)) = &headers.content_type {
                        if text.is_empty() {
                            return Err(CoseError::UnexpectedType("empty tstr", "non-empty tstr"));
                        }
                        if text.trim() != text {
                            return Err(CoseError::UnexpectedType(
                                "leading/trailing whitespace",
                                "no leading/trailing whitespace",
                            ));
                        }
                        // Basic check that the content type is of form type/subtype.
                        // We don't check the precise definition though (RFC 6838 s4.2)
                        if text.matches('/').count() != 1 {
                            return Err(CoseError::UnexpectedType(
                                "arbitrary text",
                                "text of form type/subtype",
                            ));
                        }
                    }
                }

                x if x == KID => match value {
                    Value::ByteString(v) => {
                        if v.is_empty() {
                            return Err(CoseError::UnexpectedType("empty bstr", "non-empty bstr"));
                        }
                        headers.key_id = v;
                    }
                    v => return cbor_type_error(&v, "bstr value"),
                },

                x if x == IV => match value {
                    Value::ByteString(v) => {
                        if v.is_empty() {
                            return Err(CoseError::UnexpectedType("empty bstr", "non-empty bstr"));
                        }
                        headers.iv = v;
                    }
                    v => return cbor_type_error(&v, "bstr value"),
                },

                x if x == PARTIAL_IV => match value {
                    Value::ByteString(v) => {
                        if v.is_empty() {
                            return Err(CoseError::UnexpectedType("empty bstr", "non-empty bstr"));
                        }
                        headers.partial_iv = v;
                    }
                    v => return cbor_type_error(&v, "bstr value"),
                },
                x if x == COUNTER_SIG => match value {
                    Value::Array(sig_or_sigs) => {
                        if sig_or_sigs.is_empty() {
                            return Err(CoseError::UnexpectedType(
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
                            Value::ByteString(_) => headers
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
                    v => return cbor_type_error(&v, "array value"),
                },

                l => {
                    let label = Label::from_cbor_value(l)?;
                    headers.rest.push((label, value));
                }
            }
            // RFC 8152 section 3.1: "The 'Initialization Vector' and 'Partial Initialization
            // Vector' parameters MUST NOT both be present in the same security layer."
            if !headers.iv.is_empty() && !headers.partial_iv.is_empty() {
                return Err(CoseError::UnexpectedType(
                    "IV and partial-IV specified",
                    "only one of IV and partial IV",
                ));
            }
        }
        Ok(headers)
    }

    fn to_cbor_value(mut self) -> Result<Value, CoseError> {
        let mut map = Vec::<(Value, Value)>::new();
        if let Some(alg) = self.alg {
            map.push((ALG, alg.to_cbor_value()?));
        }
        if !self.crit.is_empty() {
            let mut arr = Vec::new();
            for c in self.crit {
                arr.push(c.to_cbor_value()?);
            }
            map.push((CRIT, Value::Array(arr)));
        }
        if let Some(content_type) = self.content_type {
            map.push((CONTENT_TYPE, content_type.to_cbor_value()?));
        }
        if !self.key_id.is_empty() {
            map.push((KID, Value::ByteString(self.key_id)));
        }
        if !self.iv.is_empty() {
            map.push((IV, Value::ByteString(self.iv)));
        }
        if !self.partial_iv.is_empty() {
            map.push((PARTIAL_IV, Value::ByteString(self.partial_iv)));
        }
        if !self.counter_signatures.is_empty() {
            if self.counter_signatures.len() == 1 {
                // A single counter signature is encoded differently.
                map.push((
                    COUNTER_SIG,
                    self.counter_signatures.remove(0).to_cbor_value()?,
                ));
            } else {
                let mut arr = Vec::new();
                for cs in self.counter_signatures {
                    arr.push(cs.to_cbor_value()?);
                }
                map.push((COUNTER_SIG, Value::Array(arr)));
            }
        }
        for (label, value) in self.rest.into_iter() {
            map.push((label.to_cbor_value()?, value));
        }
        Ok(Value::Map(map))
    }
}

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

    /// Set a header label:value pair. If duplicate labels are added to a [`Header`],
    /// subsequent attempts to CBOR-encode the header will fail.
    ///
    /// # Panics
    ///
    /// This function will panic if it used to set a header label from the range [1, 6].
    pub fn value(mut self, label: i128, value: Value) -> Self {
        if label >= iana::HeaderParameter::Alg.to_i128()
            && label <= iana::HeaderParameter::CounterSignature.to_i128()
        {
            panic!("value() method used to set core header parameter"); // safe: invalid input
        }
        self.0.rest.push((Label::Int(label), value));
        self
    }

    /// Set a header label:value pair where the `label` is text.
    pub fn text_value(mut self, label: String, value: Value) -> Self {
        self.0.rest.push((Label::Text(label), value));
        self
    }
}
