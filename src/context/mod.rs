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
    cbor::value::Value,
    common::AsCborValue,
    iana,
    util::{cbor_type_error, ValueTryAs},
    Algorithm, CoseError, ProtectedHeader, Result,
};
use alloc::{vec, vec::Vec};
use core::convert::TryInto;

#[cfg(test)]
mod tests;

/// A nonce value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Nonce {
    Bytes(Vec<u8>),
    Integer(i64),
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
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 3 {
            return Err(CoseError::UnexpectedItem("array", "array with 3 items"));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            other: match a.remove(2) {
                Value::Null => None,
                Value::Bytes(b) => Some(b),
                v => return cbor_type_error(&v, "bstr / nil"),
            },
            nonce: match a.remove(1) {
                Value::Null => None,
                Value::Bytes(b) => Some(Nonce::Bytes(b)),
                Value::Integer(u) => Some(Nonce::Integer(u.try_into()?)),
                v => return cbor_type_error(&v, "bstr / int / nil"),
            },
            identity: match a.remove(0) {
                Value::Null => None,
                Value::Bytes(b) => Some(b),
                v => return cbor_type_error(&v, "bstr / nil"),
            },
        })
    }

    fn to_cbor_value(self) -> Result<Value> {
        Ok(Value::Array(vec![
            match self.identity {
                None => Value::Null,
                Some(b) => Value::Bytes(b),
            },
            match self.nonce {
                None => Value::Null,
                Some(Nonce::Bytes(b)) => Value::Bytes(b),
                Some(Nonce::Integer(i)) => Value::from(i),
            },
            match self.other {
                None => Value::Null,
                Some(b) => Value::Bytes(b),
            },
        ]))
    }
}

/// Builder for [`PartyInfo`] objects.
#[derive(Debug, Default)]
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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SuppPubInfo {
    pub key_data_length: u64,
    pub protected: ProtectedHeader,
    pub other: Option<Vec<u8>>,
}

impl crate::CborSerializable for SuppPubInfo {}

impl AsCborValue for SuppPubInfo {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() != 2 && a.len() != 3 {
            return Err(CoseError::UnexpectedItem(
                "array",
                "array with 2 or 3 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        Ok(Self {
            other: {
                if a.len() == 3 {
                    Some(a.remove(2).try_as_bytes()?)
                } else {
                    None
                }
            },
            protected: ProtectedHeader::from_cbor_bstr(a.remove(1))?,
            key_data_length: a.remove(0).try_as_integer()?.try_into()?,
        })
    }

    fn to_cbor_value(self) -> Result<Value> {
        let mut v = vec![
            Value::from(self.key_data_length),
            self.protected.cbor_bstr()?,
        ];
        if let Some(other) = self.other {
            v.push(Value::Bytes(other));
        }
        Ok(Value::Array(v))
    }
}

/// Builder for [`SuppPubInfo`] objects.
#[derive(Debug, Default)]
pub struct SuppPubInfoBuilder(SuppPubInfo);

impl SuppPubInfoBuilder {
    builder! {SuppPubInfo}
    builder_set! {key_data_length: u64}
    builder_set_protected! {protected}
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
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseKdfContext {
    algorithm_id: Algorithm,
    party_u_info: PartyInfo,
    party_v_info: PartyInfo,
    supp_pub_info: SuppPubInfo,
    supp_priv_info: Vec<Vec<u8>>,
}

impl crate::CborSerializable for CoseKdfContext {}

impl AsCborValue for CoseKdfContext {
    fn from_cbor_value(value: Value) -> Result<Self> {
        let mut a = value.try_as_array()?;
        if a.len() < 4 {
            return Err(CoseError::UnexpectedItem(
                "array",
                "array with at least 4 items",
            ));
        }

        // Remove array elements in reverse order to avoid shifts.
        let mut supp_priv_info = Vec::with_capacity(a.len() - 4);
        for i in (4..a.len()).rev() {
            supp_priv_info.push(a.remove(i).try_as_bytes()?);
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

    fn to_cbor_value(self) -> Result<Value> {
        let mut v = vec![
            self.algorithm_id.to_cbor_value()?,
            self.party_u_info.to_cbor_value()?,
            self.party_v_info.to_cbor_value()?,
            self.supp_pub_info.to_cbor_value()?,
        ];
        for supp_priv_info in self.supp_priv_info {
            v.push(Value::Bytes(supp_priv_info));
        }
        Ok(Value::Array(v))
    }
}

/// Builder for [`CoseKdfContext`] objects.
#[derive(Debug, Default)]
pub struct CoseKdfContextBuilder(CoseKdfContext);

impl CoseKdfContextBuilder {
    builder! {CoseKdfContext}
    builder_set! {party_u_info: PartyInfo}
    builder_set! {party_v_info: PartyInfo}
    builder_set! {supp_pub_info: SuppPubInfo}

    /// Set the algorithm.
    #[must_use]
    pub fn algorithm(mut self, alg: iana::Algorithm) -> Self {
        self.0.algorithm_id = Algorithm::Assigned(alg);
        self
    }

    /// Add supplemental private info.
    #[must_use]
    pub fn add_supp_priv_info(mut self, supp_priv_info: Vec<u8>) -> Self {
        self.0.supp_priv_info.push(supp_priv_info);
        self
    }
}
