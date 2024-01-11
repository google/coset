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
    common::{AsCborValue, CborOrdering},
    iana,
    iana::EnumI64,
    util::{to_cbor_array, ValueTryAs},
    Algorithm, CoseError, Label, Result,
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
    fn from_cbor_value(value: Value) -> Result<Self> {
        Ok(Self(
            value.try_as_array_then_convert(CoseKey::from_cbor_value)?,
        ))
    }

    fn to_cbor_value(self) -> Result<Value> {
        to_cbor_array(self.0)
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

impl CoseKey {
    /// Re-order the contents of the key so that the contents will be emitted in one of the standard
    /// CBOR sorted orders.
    pub fn canonicalize(&mut self, ordering: CborOrdering) {
        // The keys that are represented as named fields CBOR-encode as single bytes 0x01 - 0x05,
        // which sort before any other CBOR values (other than 0x00) in either sorting scheme:
        // - In length-first sorting, a single byte sorts before anything multi-byte and 1-5 sorts
        //   before any other value.
        // - In encoded-lexicographic sorting, there are no valid CBOR-encoded single values that
        //   start with a byte in the range 0x01 - 0x05 other than the values 1-5.
        // So we only need to sort the `params`.
        match ordering {
            CborOrdering::Lexicographic => self.params.sort_by(|l, r| l.0.cmp(&r.0)),
            CborOrdering::LengthFirstLexicographic => {
                self.params.sort_by(|l, r| l.0.cmp_canonical(&r.0))
            }
        }
    }
}

impl crate::CborSerializable for CoseKey {}

const KTY: Label = Label::Int(iana::KeyParameter::Kty as i64);
const KID: Label = Label::Int(iana::KeyParameter::Kid as i64);
const ALG: Label = Label::Int(iana::KeyParameter::Alg as i64);
const KEY_OPS: Label = Label::Int(iana::KeyParameter::KeyOps as i64);
const BASE_IV: Label = Label::Int(iana::KeyParameter::BaseIv as i64);

impl AsCborValue for CoseKey {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let m = value.try_as_map()?;
        let mut key = Self::default();
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
                KTY => key.kty = KeyType::from_cbor_value(value)?,

                KID => {
                    key.key_id = value.try_as_nonempty_bytes()?;
                }

                ALG => key.alg = Some(Algorithm::from_cbor_value(value)?),

                KEY_OPS => {
                    let key_ops = value.try_as_array()?;
                    for key_op in key_ops.into_iter() {
                        if !key.key_ops.insert(KeyOperation::from_cbor_value(key_op)?) {
                            return Err(CoseError::UnexpectedItem(
                                "repeated array entry",
                                "unique array label",
                            ));
                        }
                    }
                    if key.key_ops.is_empty() {
                        return Err(CoseError::UnexpectedItem("empty array", "non-empty array"));
                    }
                }

                BASE_IV => {
                    key.base_iv = value.try_as_nonempty_bytes()?;
                }

                label => key.params.push((label, value)),
            }
        }
        // Check that key type has been set.
        if key.kty == KeyType::Assigned(iana::KeyType::Reserved) {
            return Err(CoseError::UnexpectedItem(
                "no kty label",
                "mandatory kty label",
            ));
        }

        Ok(key)
    }

    fn to_cbor_value(self) -> Result<Value> {
        let mut map: Vec<(Value, Value)> = vec![(KTY.to_cbor_value()?, self.kty.to_cbor_value()?)];
        if !self.key_id.is_empty() {
            map.push((KID.to_cbor_value()?, Value::Bytes(self.key_id)));
        }
        if let Some(alg) = self.alg {
            map.push((ALG.to_cbor_value()?, alg.to_cbor_value()?));
        }
        if !self.key_ops.is_empty() {
            map.push((KEY_OPS.to_cbor_value()?, to_cbor_array(self.key_ops)?));
        }
        if !self.base_iv.is_empty() {
            map.push((BASE_IV.to_cbor_value()?, Value::Bytes(self.base_iv)));
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
    builder_set! {kty: KeyType}
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

    /// Constructor for a octet keypair key.
    pub fn new_okp_key() -> Self {
        Self(CoseKey {
            kty: KeyType::Assigned(iana::KeyType::OKP),
            ..Default::default()
        })
    }

    /// Set the key type.
    #[must_use]
    pub fn key_type(mut self, key_type: iana::KeyType) -> Self {
        self.0.kty = KeyType::Assigned(key_type);
        self
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
