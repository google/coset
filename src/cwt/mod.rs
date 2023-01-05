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

//! CBOR Web Token functionality.

use crate::{
    cbor::value::Value,
    common::AsCborValue,
    iana,
    iana::{EnumI64, WithPrivateRange},
    util::{cbor_type_error, ValueTryAs},
    CoseError,
};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use core::convert::TryInto;

#[cfg(test)]
mod tests;

/// Number of seconds since UNIX epoch.
#[derive(Clone, Debug, PartialEq)]
pub enum Timestamp {
    WholeSeconds(i64),
    FractionalSeconds(f64),
}

impl AsCborValue for Timestamp {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        match value {
            Value::Integer(i) => Ok(Timestamp::WholeSeconds(i.try_into()?)),
            Value::Float(f) => Ok(Timestamp::FractionalSeconds(f)),
            _ => cbor_type_error(&value, "int/float"),
        }
    }
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        Ok(match self {
            Timestamp::WholeSeconds(t) => Value::Integer(t.into()),
            Timestamp::FractionalSeconds(f) => Value::Float(f),
        })
    }
}

/// Claim name.
pub type ClaimName = crate::RegisteredLabelWithPrivate<iana::CwtClaimName>;

/// Structure representing a CWT Claims Set.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClaimsSet {
    /// Issuer
    pub issuer: Option<String>,
    /// Subject
    pub subject: Option<String>,
    /// Audience
    pub audience: Option<String>,
    /// Expiration Time
    pub expiration_time: Option<Timestamp>,
    /// Not Before
    pub not_before: Option<Timestamp>,
    /// Issued At
    pub issued_at: Option<Timestamp>,
    /// CWT ID
    pub cwt_id: Option<Vec<u8>>,
    /// Any additional claims.
    pub rest: Vec<(ClaimName, Value)>,
}

impl crate::CborSerializable for ClaimsSet {}

const ISS: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Iss);
const SUB: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Sub);
const AUD: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Aud);
const EXP: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Exp);
const NBF: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Nbf);
const IAT: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Iat);
const CTI: ClaimName = ClaimName::Assigned(iana::CwtClaimName::Cti);

impl AsCborValue for ClaimsSet {
    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let m = match value {
            Value::Map(m) => m,
            v => return cbor_type_error(&v, "map"),
        };

        let mut claims = Self::default();
        let mut seen = BTreeSet::new();
        for (n, value) in m.into_iter() {
            // The `ciborium` CBOR library does not police duplicate map keys, so do it here.
            let name = ClaimName::from_cbor_value(n)?;
            if seen.contains(&name) {
                return Err(CoseError::DuplicateMapKey);
            }
            seen.insert(name.clone());
            match name {
                x if x == ISS => claims.issuer = Some(value.try_as_string()?),
                x if x == SUB => claims.subject = Some(value.try_as_string()?),
                x if x == AUD => claims.audience = Some(value.try_as_string()?),
                x if x == EXP => claims.expiration_time = Some(Timestamp::from_cbor_value(value)?),
                x if x == NBF => claims.not_before = Some(Timestamp::from_cbor_value(value)?),
                x if x == IAT => claims.issued_at = Some(Timestamp::from_cbor_value(value)?),
                x if x == CTI => claims.cwt_id = Some(value.try_as_bytes()?),
                name => claims.rest.push((name, value)),
            }
        }
        Ok(claims)
    }

    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut map = Vec::new();
        if let Some(iss) = self.issuer {
            map.push((ISS.to_cbor_value()?, Value::Text(iss)));
        }
        if let Some(sub) = self.subject {
            map.push((SUB.to_cbor_value()?, Value::Text(sub)));
        }
        if let Some(aud) = self.audience {
            map.push((AUD.to_cbor_value()?, Value::Text(aud)));
        }
        if let Some(exp) = self.expiration_time {
            map.push((EXP.to_cbor_value()?, exp.to_cbor_value()?));
        }
        if let Some(nbf) = self.not_before {
            map.push((NBF.to_cbor_value()?, nbf.to_cbor_value()?));
        }
        if let Some(iat) = self.issued_at {
            map.push((IAT.to_cbor_value()?, iat.to_cbor_value()?));
        }
        if let Some(cti) = self.cwt_id {
            map.push((CTI.to_cbor_value()?, Value::Bytes(cti)));
        }
        for (label, value) in self.rest {
            map.push((label.to_cbor_value()?, value));
        }
        Ok(Value::Map(map))
    }
}

/// Builder for [`ClaimsSet`] objects.
#[derive(Default)]
pub struct ClaimsSetBuilder(ClaimsSet);

impl ClaimsSetBuilder {
    builder! {ClaimsSet}
    builder_set_optional! {issuer: String}
    builder_set_optional! {subject: String}
    builder_set_optional! {audience: String}
    builder_set_optional! {expiration_time: Timestamp}
    builder_set_optional! {not_before: Timestamp}
    builder_set_optional! {issued_at: Timestamp}
    builder_set_optional! {cwt_id: Vec<u8>}

    /// Set a claim name:value pair.
    ///
    /// # Panics
    ///
    /// This function will panic if it used to set a claim with name from the range [1, 7].
    #[must_use]
    pub fn claim(mut self, name: iana::CwtClaimName, value: Value) -> Self {
        if name.to_i64() >= iana::CwtClaimName::Iss.to_i64()
            && name.to_i64() <= iana::CwtClaimName::Cti.to_i64()
        {
            panic!("claim() method used to set core claim"); // safe: invalid input
        }
        self.0.rest.push((ClaimName::Assigned(name), value));
        self
    }

    /// Set a claim name:value pair where the `name` is text.
    #[must_use]
    pub fn text_claim(mut self, name: String, value: Value) -> Self {
        self.0.rest.push((ClaimName::Text(name), value));
        self
    }

    /// Set a claim  where the claim key is a numeric value from the private use range.
    ///
    /// # Panics
    ///
    /// This function will panic if it is used to set a claim with a key value outside of the
    /// private use range.
    #[must_use]
    pub fn private_claim(mut self, id: i64, value: Value) -> Self {
        assert!(iana::CwtClaimName::is_private(id));
        self.0.rest.push((ClaimName::PrivateUse(id), value));
        self
    }
}
