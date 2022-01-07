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
    cbor::value::Value,
    iana,
    iana::EnumI64,
    util::{cbor_type_error, AsCborValue},
    Algorithm, CoseError, Label,
};
use alloc::{collections::BTreeSet, vec, vec::Vec};

#[cfg(test)]
mod tests;

/// Key type.
pub type KeyType = crate::RegisteredLabel<iana::KeyType>;

impl Default for KeyType {
    fn default() -> Self {
        KeyType::Assigned(iana::KeyType::Reserved)
    }
}

/// Key operation.
pub type KeyOperation = crate::RegisteredLabel<iana::KeyOperation>;

/// A collection of [`CoseKey`] objects.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseKeySet(pub Vec<CoseKey>);

impl crate::CborSerializable for CoseKeySet {}

impl AsCborValue for CoseKeySet {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let a = match value {
            Value::Array(a) => a,
            v => return cbor_type_error(&v, "array"),
        };
        let mut keys = Vec::new();
        for v in a {
            keys.push(CoseKey::from_cbor_value(v)?);
        }
        Ok(Self(keys))
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut arr = Vec::new();
        for k in self.0 {
            arr.push(k.to_cbor_value()?);
        }
        Ok(Value::Array(arr))
    }
}

/// Structure representing a cryptographic key.
///
/// ```cddl
///  COSE_Key = {
///      1 => tstr / int,          ; kty
///      ? 2 => bstr,              ; kid
///      ? 3 => tstr / int,        ; alg
///      ? 4 => [+ (tstr / int) ], ; key_ops
///      ? 5 => bstr,              ; Base IV
///      * label => values
///  }
///  ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseKey {
    /// Key type identification.
    pub kty: KeyType,
    /// Key identification.
    pub key_id: Vec<u8>,
    /// Key use restriction to this algorithm.
    pub alg: Option<Algorithm>,
    /// Restrict set of possible operations.
    pub key_ops: BTreeSet<KeyOperation>,
    /// Base IV to be xor-ed with partial IVs.
    pub base_iv: Vec<u8>,
    /// Any additional parameter (label,value) pairs.  If duplicate labels are present,
    /// CBOR-encoding will fail.
    pub params: Vec<(Label, Value)>,
}

impl crate::CborSerializable for CoseKey {}

fn kty_value() -> Value {
    Value::from(iana::KeyParameter::Kty.to_i64())
}
fn kid_value() -> Value {
    Value::from(iana::KeyParameter::Kid.to_i64())
}
fn alg_value() -> Value {
    Value::from(iana::KeyParameter::Alg.to_i64())
}
fn key_ops_value() -> Value {
    Value::from(iana::KeyParameter::KeyOps.to_i64())
}
fn base_iv_value() -> Value {
    Value::from(iana::KeyParameter::BaseIv.to_i64())
}

impl AsCborValue for CoseKey {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let m = match value {
            Value::Map(m) => m,
            v => return cbor_type_error(&v, "map"),
        };

        let mut key = Self::default();
        let mut seen = BTreeSet::new();
        for (l, value) in m.into_iter() {
            // The `ciborium` CBOR library does not police duplicate map keys.
            // RFC 8152 section 14 requires that COSE does police duplicates, so do it here.
            let label = Label::from_cbor_value(l.clone())?;
            if seen.contains(&label) {
                return Err(CoseError::DuplicateMapKey);
            }
            seen.insert(label.clone());
            match l {
                x if x == kty_value() => key.kty = KeyType::from_cbor_value(value)?,

                x if x == kid_value() => match value {
                    Value::Bytes(v) => {
                        if v.is_empty() {
                            return Err(CoseError::UnexpectedType("empty bstr", "non-empty bstr"));
                        }
                        key.key_id = v;
                    }
                    v => return cbor_type_error(&v, "bstr value"),
                },

                x if x == alg_value() => key.alg = Some(Algorithm::from_cbor_value(value)?),

                x if x == key_ops_value() => match value {
                    Value::Array(key_ops) => {
                        for key_op in key_ops.into_iter() {
                            if !key.key_ops.insert(KeyOperation::from_cbor_value(key_op)?) {
                                return Err(CoseError::UnexpectedType(
                                    "repeated array entry",
                                    "unique array label",
                                ));
                            }
                        }
                        if key.key_ops.is_empty() {
                            return Err(CoseError::UnexpectedType(
                                "empty array",
                                "non-empty array",
                            ));
                        }
                    }
                    v => return cbor_type_error(&v, "array value"),
                },

                x if x == base_iv_value() => match value {
                    Value::Bytes(v) => {
                        if v.is_empty() {
                            return Err(CoseError::UnexpectedType("empty bstr", "non-empty bstr"));
                        }
                        key.base_iv = v;
                    }
                    v => return cbor_type_error(&v, "bstr value"),
                },

                _l => key.params.push((label, value)),
            }
        }
        // Check that key type has been set.
        if key.kty == KeyType::Assigned(iana::KeyType::Reserved) {
            return Err(CoseError::UnexpectedType(
                "no kty label",
                "mandatory kty label",
            ));
        }

        Ok(key)
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut map: Vec<(Value, Value)> = vec![(kty_value(), self.kty.to_cbor_value()?)];
        if !self.key_id.is_empty() {
            map.push((kid_value(), Value::Bytes(self.key_id)));
        }
        if let Some(alg) = self.alg {
            map.push((alg_value(), alg.to_cbor_value()?));
        }
        if !self.key_ops.is_empty() {
            let mut arr = Vec::new();
            for op in self.key_ops {
                arr.push(op.to_cbor_value()?);
            }
            map.push((key_ops_value(), Value::Array(arr)));
        }
        if !self.base_iv.is_empty() {
            map.push((base_iv_value(), Value::Bytes(self.base_iv)));
        }
        let mut seen = BTreeSet::new();
        for (label, value) in self.params {
            if seen.contains(&label) {
                return Err(CoseError::DuplicateMapKey);
            }
            seen.insert(label.clone());
            map.push((label.to_cbor_value()?, value));
        }
        Ok(Value::Map(map))
    }
}

/// Builder for [`CoseKey`] objects.
#[derive(Debug, Default)]
pub struct CoseKeyBuilder(CoseKey);

impl CoseKeyBuilder {
    builder! {CoseKey}
    builder_set! {key_id: Vec<u8>}
    builder_set! {base_iv: Vec<u8>}

    /// Constructor for an elliptic curve public key specified by `x` and `y` coordinates.
    pub fn new_ec2_pub_key(curve: iana::EllipticCurve, x: Vec<u8>, y: Vec<u8>) -> Self {
        Self(CoseKey {
            kty: KeyType::Assigned(iana::KeyType::EC2),
            params: vec![
                (
                    Label::Int(iana::Ec2KeyParameter::Crv as i64),
                    Value::from(curve as u64),
                ),
                (Label::Int(iana::Ec2KeyParameter::X as i64), Value::Bytes(x)),
                (Label::Int(iana::Ec2KeyParameter::Y as i64), Value::Bytes(y)),
            ],
            ..Default::default()
        })
    }

    /// Constructor for an elliptic curve public key specified by `x` coordinate plus sign of `y`
    /// coordinate.
    pub fn new_ec2_pub_key_y_sign(curve: iana::EllipticCurve, x: Vec<u8>, y_sign: bool) -> Self {
        Self(CoseKey {
            kty: KeyType::Assigned(iana::KeyType::EC2),
            params: vec![
                (
                    Label::Int(iana::Ec2KeyParameter::Crv as i64),
                    Value::from(curve as u64),
                ),
                (Label::Int(iana::Ec2KeyParameter::X as i64), Value::Bytes(x)),
                (
                    Label::Int(iana::Ec2KeyParameter::Y as i64),
                    Value::Bool(y_sign),
                ),
            ],
            ..Default::default()
        })
    }

    /// Constructor for an elliptic curve private key specified by `d`, together with public `x` and
    /// `y` coordinates.
    pub fn new_ec2_priv_key(
        curve: iana::EllipticCurve,
        x: Vec<u8>,
        y: Vec<u8>,
        d: Vec<u8>,
    ) -> Self {
        let mut builder = Self::new_ec2_pub_key(curve, x, y);
        builder
            .0
            .params
            .push((Label::Int(iana::Ec2KeyParameter::D as i64), Value::Bytes(d)));
        builder
    }

    /// Constructor for a symmetric key specified by `k`.
    pub fn new_symmetric_key(k: Vec<u8>) -> Self {
        Self(CoseKey {
            kty: KeyType::Assigned(iana::KeyType::Symmetric),
            params: vec![(
                Label::Int(iana::SymmetricKeyParameter::K as i64),
                Value::Bytes(k),
            )],
            ..Default::default()
        })
    }

    /// Set the algorithm.
    #[must_use]
    pub fn algorithm(mut self, alg: iana::Algorithm) -> Self {
        self.0.alg = Some(Algorithm::Assigned(alg));
        self
    }

    /// Add a key operation.
    #[must_use]
    pub fn add_key_op(mut self, op: iana::KeyOperation) -> Self {
        self.0.key_ops.insert(KeyOperation::Assigned(op));
        self
    }

    /// Set a parameter value.
    ///
    /// # Panics
    ///
    /// This function will panic if it used to set a parameter label from the [`iana::KeyParameter`]
    /// range.
    #[must_use]
    pub fn param(mut self, label: i64, value: Value) -> Self {
        if iana::KeyParameter::from_i64(label).is_some() {
            panic!("param() method used to set KeyParameter"); // safe: invalid input
        }
        self.0.params.push((Label::Int(label), value));
        self
    }
}
