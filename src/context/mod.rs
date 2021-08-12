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

//! COSE_KDF_Context functionality.

use crate::{
    iana,
    util::{cbor_type_error, AsCborValue},
    Algorithm, Header,
};
use serde::de::Unexpected;
use serde_cbor as cbor;

#[cfg(test)]
mod tests;

/// A nonce value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Nonce {
    Bytes(Vec<u8>),
    Integer(i128),
}

/// Structure representing a party involved in key derivation.
///
/// ```cddl
///  PartyInfo = (
///      identity : bstr / nil,
///      nonce : bstr / int / nil,
///      other : bstr / nil
///  )
///  ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PartyInfo {
    pub identity: Option<Vec<u8>>,
    pub nonce: Option<Nonce>,
    pub other: Option<Vec<u8>>,
}

impl crate::CborSerializable for PartyInfo {}

impl AsCborValue for PartyInfo {
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
        Ok(Self {
            other: match a.remove(2) {
                cbor::Value::Null => None,
                cbor::Value::Bytes(b) => Some(b),
                v => return cbor_type_error(&v, &"bstr / nil"),
            },
            nonce: match a.remove(1) {
                cbor::Value::Null => None,
                cbor::Value::Bytes(b) => Some(Nonce::Bytes(b)),
                cbor::Value::Integer(i) => Some(Nonce::Integer(i)),
                v => return cbor_type_error(&v, &"bstr / int / nil"),
            },
            identity: match a.remove(0) {
                cbor::Value::Null => None,
                cbor::Value::Bytes(b) => Some(b),
                v => return cbor_type_error(&v, &"bstr / nil"),
            },
        })
    }

    fn to_cbor_value(&self) -> cbor::Value {
        cbor::Value::Array(vec![
            match &self.identity {
                None => cbor::Value::Null,
                Some(b) => cbor::Value::Bytes(b.clone()),
            },
            match &self.nonce {
                None => cbor::Value::Null,
                Some(Nonce::Bytes(b)) => cbor::Value::Bytes(b.clone()),
                Some(Nonce::Integer(i)) => cbor::Value::Integer(*i),
            },
            match &self.other {
                None => cbor::Value::Null,
                Some(b) => cbor::Value::Bytes(b.clone()),
            },
        ])
    }
}

cbor_serialize!(PartyInfo);

/// Builder for [`PartyInfo`] objects.
#[derive(Default)]
pub struct PartyInfoBuilder(PartyInfo);

impl PartyInfoBuilder {
    builder! {PartyInfo}
    builder_set_optional! {identity: Vec<u8>}
    builder_set_optional! {nonce: Nonce}
    builder_set_optional! {other: Vec<u8>}
}

/// Structure representing supplemental public information.
///
/// ```cddl
///  SuppPubInfo : [
///      keyDataLength : uint,
///      protected : empty_or_serialized_map,
///      ? other : bstr
///  ],
///  ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SuppPubInfo {
    pub key_data_length: u64,
    pub protected: Header,
    pub other: Option<Vec<u8>>,
}

impl crate::CborSerializable for SuppPubInfo {}

impl AsCborValue for SuppPubInfo {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        let mut a = match value {
            cbor::Value::Array(a) => a,
            v => return cbor_type_error(&v, &"array"),
        };
        if a.len() != 2 && a.len() != 3 {
            return Err(serde::de::Error::invalid_value(
                Unexpected::TupleVariant,
                &"array with 2 or 3 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            other: {
                if a.len() == 3 {
                    match a.remove(2) {
                        cbor::Value::Bytes(b) => Some(b),
                        v => return cbor_type_error(&v, &"bstr"),
                    }
                } else {
                    None
                }
            },
            protected: Header::from_cbor_bstr(a.remove(1))?,
            key_data_length: match a.remove(0) {
                cbor::Value::Integer(i) if i >= 0 && i <= u64::MAX.into() => i as u64,
                v => return cbor_type_error(&v, &"uint"),
            },
        })
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = vec![
            cbor::Value::Integer(self.key_data_length as i128),
            self.protected.to_cbor_bstr(),
        ];
        if let Some(other) = &self.other {
            v.push(cbor::Value::Bytes(other.clone()));
        }
        cbor::Value::Array(v)
    }
}

cbor_serialize!(SuppPubInfo);

/// Builder for [`SuppPubInfo`] objects.
#[derive(Default)]
pub struct SuppPubInfoBuilder(SuppPubInfo);

impl SuppPubInfoBuilder {
    builder! {SuppPubInfo}
    builder_set! {key_data_length: u64}
    builder_set! {protected: Header}
    builder_set_optional! {other: Vec<u8>}
}

/// Structure representing a a key derivation context.
/// ```cdl
///  COSE_KDF_Context = [
///      AlgorithmID : int / tstr,
///      PartyUInfo : [ PartyInfo ],
///      PartyVInfo : [ PartyInfo ],
///      SuppPubInfo : [
///          keyDataLength : uint,
///          protected : empty_or_serialized_map,
///          ? other : bstr
///      ],
///      ? SuppPrivInfo : bstr
///  ]
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoseKdfContext {
    algorithm_id: Algorithm,
    party_u_info: PartyInfo,
    party_v_info: PartyInfo,
    supp_pub_info: SuppPubInfo,
    supp_priv_info: Vec<Vec<u8>>,
}

impl crate::CborSerializable for CoseKdfContext {}

impl AsCborValue for CoseKdfContext {
    fn from_cbor_value<E: serde::de::Error>(value: cbor::Value) -> Result<Self, E> {
        let mut a = match value {
            cbor::Value::Array(a) => a,
            v => return cbor_type_error(&v, &"array"),
        };
        if a.len() < 4 {
            return Err(serde::de::Error::invalid_value(
                Unexpected::TupleVariant,
                &"array with at least 4 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        let mut supp_priv_info = Vec::with_capacity(a.len() - 4);
        for i in (4..a.len()).rev() {
            let b = match a.remove(i) {
                cbor::Value::Bytes(b) => b,
                v => return cbor_type_error(&v, &"bstr"),
            };
            supp_priv_info.push(b);
        }
        supp_priv_info.reverse();

        Ok(Self {
            supp_priv_info,
            supp_pub_info: SuppPubInfo::from_cbor_value(a.remove(3))?,
            party_v_info: PartyInfo::from_cbor_value(a.remove(2))?,
            party_u_info: PartyInfo::from_cbor_value(a.remove(1))?,
            algorithm_id: Algorithm::from_cbor_value(a.remove(0))?,
        })
    }

    fn to_cbor_value(&self) -> cbor::Value {
        let mut v = vec![
            self.algorithm_id.to_cbor_value(),
            self.party_u_info.to_cbor_value(),
            self.party_v_info.to_cbor_value(),
            self.supp_pub_info.to_cbor_value(),
        ];
        for supp_priv_info in &self.supp_priv_info {
            v.push(cbor::Value::Bytes(supp_priv_info.clone()));
        }
        cbor::Value::Array(v)
    }
}

cbor_serialize!(CoseKdfContext);

/// Builder for [`CoseKdfContext`] objects.
#[derive(Default)]
pub struct CoseKdfContextBuilder(CoseKdfContext);

impl CoseKdfContextBuilder {
    builder! {CoseKdfContext}
    builder_set! {party_u_info: PartyInfo}
    builder_set! {party_v_info: PartyInfo}
    builder_set! {supp_pub_info: SuppPubInfo}

    /// Set the algorithm.
    pub fn algorithm(mut self, alg: iana::Algorithm) -> Self {
        self.0.algorithm_id = Algorithm::Assigned(alg);
        self
    }

    /// Add supplemental private info.
    pub fn add_supp_priv_info(mut self, supp_priv_info: Vec<u8>) -> Self {
        self.0.supp_priv_info.push(supp_priv_info);
        self
    }
}
