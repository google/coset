//! Types for the ACE OSCORE profile (RFC 9203)

use crate::{
    cbor::value::Value,
    common::AsCborValue,
    iana,
    util::ValueTryAs,
    Algorithm, CoseError, Label, Result,
};
use alloc::{collections::BTreeSet, vec::Vec};

/// OSCORE_Input_Material, suitable to produce OSCORE keys when applying the ACE OSCORE profile
/// (RFC 9203)
///
/// This is typically transported in a token response as a variant of the cnf.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct OscoreInputMaterial {
    /// OSCORE Input Material Identifier
    pub id: Option<Vec<u8>>,
    /// OSCORE Version
    pub version: Option<ciborium::value::Integer>,
    /// OSCORE Master Secret value
    pub ms: Option<Vec<u8>>,
    /// OSCORE HKDF value
    pub hkdf: Option<Algorithm>,
    /// OSCORE AEAD Algorithm value
    pub alg: Option<Algorithm>,
    /// an input to OSCORE Master Salt value
    pub salt: Option<Vec<u8>>,
    /// OSCORE ID Context value
    pub context_id: Option<Vec<u8>>,
}

const ID: Label = Label::Int(iana::OscoreSecurityContextParameter::Id as i64);
const VERSION: Label = Label::Int(iana::OscoreSecurityContextParameter::Version as i64);
const MS: Label = Label::Int(iana::OscoreSecurityContextParameter::Ms as i64);
const HKDF: Label = Label::Int(iana::OscoreSecurityContextParameter::Hkdf as i64);
const ALG: Label = Label::Int(iana::OscoreSecurityContextParameter::Alg as i64);
const SALT: Label = Label::Int(iana::OscoreSecurityContextParameter::Salt as i64);
const CONTEXTID: Label = Label::Int(iana::OscoreSecurityContextParameter::ContextId as i64);

impl AsCborValue for OscoreInputMaterial {
    fn from_cbor_value(value: Value) -> Result<Self> {

        let m = value.try_as_map()?;
        let mut material = Self::default();
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
                ID => material.id = Some(value.try_as_bytes()?),
                VERSION => material.version = Some(value.try_as_integer()?),
                MS => material.ms = Some(value.try_as_bytes()?),
                HKDF => material.hkdf = Some(Algorithm::from_cbor_value(value)?),
                ALG => material.alg = Some(Algorithm::from_cbor_value(value)?),
                SALT => material.salt = Some(value.try_as_bytes()?),
                CONTEXTID => material.context_id = Some(value.try_as_bytes()?),
                _label => {
                    return Err(CoseError::UnregisteredIanaValue);
                },
            }
        }
        // No checks for required properties: All parameters are (at least formally, not
        // practically) optional

        Ok(material)
    }

    fn to_cbor_value(self) -> Result<Value> {
        todo!()
    }
}
