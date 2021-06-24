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
    iana,
    iana::EnumI128,
    util::{cbor_type_error, AsCborValue},
    Algorithm, Label,
};
use maplit::btreemap;
use serde::de::Unexpected;
use serde_cbor as cbor;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

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
#[derive(Clone, Debug, Default, Eq, PartialEq)]
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
    /// Any additional parameter values.
    pub params: BTreeMap<Label, cbor::Value>,
}

/// A collection of [`CoseKey`] objects.
pub type CoseKeySet = Vec<CoseKey>;

impl crate::CborSerializable for CoseKey {}

const KTY: cbor::Value = cbor::Value::Integer(iana::KeyParameter::Kty as i128);
const KID: cbor::Value = cbor::Value::Integer(iana::KeyParameter::Kid as i128);
const ALG: cbor::Value = cbor::Value::Integer(iana::KeyParameter::Alg as i128);
const KEY_OPS: cbor::Value = cbor::Value::Integer(iana::KeyParameter::KeyOps as i128);
const BASE_IV: cbor::Value = cbor::Value::Integer(iana::KeyParameter::BaseIv as i128);

impl AsCborValue for CoseKey {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        let m = match value {
            cbor::Value::Map(m) => m,
            v => return cbor_type_error(&v, &"map"),
        };

        let mut key = Self::default();
        for (label, value) in m.into_iter() {
            match label {
                x if x == KTY => key.kty = KeyType::from_cbor_value(value)?,

                x if x == KID => match value {
                    cbor::Value::Bytes(v) => {
                        if v.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::Bytes(&v),
                                &"non-empty bstr",
                            ));
                        }
                        key.key_id = v;
                    }
                    v => return cbor_type_error(&v, &"bstr value"),
                },

                x if x == ALG => key.alg = Some(Algorithm::from_cbor_value(value)?),

                x if x == KEY_OPS => match value {
                    cbor::Value::Array(key_ops) => {
                        for key_op in key_ops.into_iter() {
                            if !key.key_ops.insert(KeyOperation::from_cbor_value(key_op)?) {
                                return Err(serde::de::Error::invalid_value(
                                    Unexpected::TupleVariant,
                                    &"unique array label",
                                ));
                            }
                        }
                        if key.key_ops.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::TupleVariant,
                                &"non-empty array",
                            ));
                        }
                    }
                    v => return cbor_type_error(&v, &"array value"),
                },

                x if x == BASE_IV => match value {
                    cbor::Value::Bytes(v) => {
                        if v.is_empty() {
                            return Err(serde::de::Error::invalid_value(
                                Unexpected::Bytes(&v),
                                &"non-empty bstr",
                            ));
                        }
                        key.base_iv = v;
                    }
                    v => return cbor_type_error(&v, &"bstr value"),
                },

                l => {
                    let label = Label::from_cbor_value(l)?;
                    match key.params.entry(label) {
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
        }
        // Check that key type has been set.
        if key.kty == KeyType::Assigned(iana::KeyType::Reserved) {
            return Err(serde::de::Error::invalid_value(
                Unexpected::StructVariant,
                &"mandatory kty label",
            ));
        }

        Ok(key)
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut map = BTreeMap::<cbor::Value, cbor::Value>::new();
        map.insert(KTY, self.kty.to_cbor_value());
        if !self.key_id.is_empty() {
            map.insert(KID, cbor::Value::Bytes(self.key_id.to_vec()));
        }
        if let Some(alg) = &self.alg {
            map.insert(ALG, alg.to_cbor_value());
        }
        if !self.key_ops.is_empty() {
            map.insert(
                KEY_OPS,
                cbor::Value::Array(
                    self.key_ops
                        .iter()
                        .map(|op| match op {
                            KeyOperation::Assigned(i) => cbor::Value::Integer(*i as i128),
                            KeyOperation::Text(t) => cbor::Value::Text(t.to_owned()),
                        })
                        .collect(),
                ),
            );
        }
        if !self.base_iv.is_empty() {
            map.insert(BASE_IV, cbor::Value::Bytes(self.base_iv.to_vec()));
        }
        for (label, value) in &self.params {
            map.insert(label.to_cbor_value(), value.clone());
        }
        cbor::Value::Map(map)
    }
}

cbor_serialize!(CoseKey);

/// Builder for [`CoseKey`] objects.
#[derive(Default)]
pub struct CoseKeyBuilder(CoseKey);

impl CoseKeyBuilder {
    builder! {CoseKey}
    builder_set! {key_id: Vec<u8>}
    builder_set! {base_iv: Vec<u8>}

    /// Constructor for an elliptic curve public key specified by `x` and `y` coordinates.
    pub fn new_ec2_pub_key(curve: iana::EllipticCurve, x: Vec<u8>, y: Vec<u8>) -> Self {
        Self(CoseKey {
            kty: KeyType::Assigned(iana::KeyType::EC2),
            params: btreemap! {
                Label::Int(iana::Ec2KeyParameter::Crv as i128) => cbor::Value::Integer(curve as i128),
                Label::Int(iana::Ec2KeyParameter::X as i128) => cbor::Value::Bytes(x),
                Label::Int(iana::Ec2KeyParameter::Y as i128) => cbor::Value::Bytes(y),
            },
            ..Default::default()
        })
    }

    /// Constructor for an elliptic curve public key specified by `x` coordinate plus sign of `y`
    /// coordinate.
    pub fn new_ec2_pub_key_y_sign(curve: iana::EllipticCurve, x: Vec<u8>, y_sign: bool) -> Self {
        Self(CoseKey {
            kty: KeyType::Assigned(iana::KeyType::EC2),
            params: btreemap! {
                Label::Int(iana::Ec2KeyParameter::Crv as i128) => cbor::Value::Integer(curve as i128),
                Label::Int(iana::Ec2KeyParameter::X as i128) => cbor::Value::Bytes(x),
                Label::Int(iana::Ec2KeyParameter::Y as i128) => cbor::Value::Bool(y_sign),
            },
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
        builder.0.params.insert(
            Label::Int(iana::Ec2KeyParameter::D as i128),
            cbor::Value::Bytes(d),
        );
        builder
    }

    /// Constructor for a symmetric key specified by `k`.
    pub fn new_symmetric_key(k: Vec<u8>) -> Self {
        Self(CoseKey {
            kty: KeyType::Assigned(iana::KeyType::Symmetric),
            params: btreemap! {
                Label::Int(iana::SymmetricKeyParameter::K as i128) => cbor::Value::Bytes(k),
            },
            ..Default::default()
        })
    }

    /// Set the algorithm.
    pub fn algorithm(mut self, alg: iana::Algorithm) -> Self {
        self.0.alg = Some(Algorithm::Assigned(alg));
        self
    }

    /// Add a key operation.
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
    pub fn param(mut self, label: i128, value: cbor::Value) -> Self {
        if iana::KeyParameter::from_i128(label).is_some() {
            panic!("param() method used to set KeyParameter"); // safe: invalid input
        }
        self.0.params.insert(Label::Int(label), value);
        self
    }
}
