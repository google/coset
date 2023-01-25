// Copyright 2022 Google LLC
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

//! Example program demonstrating signed CWT processing.
use coset::{cbor::value::Value, cwt, iana, CborSerializable, CoseError};

#[derive(Copy, Clone)]
struct FakeSigner {}

// Use a fake signer/verifier (to avoid pulling in lots of dependencies).
impl FakeSigner {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn verify(&self, sig: &[u8], data: &[u8]) -> Result<(), String> {
        if sig != self.sign(data) {
            Err("failed to verify".to_owned())
        } else {
            Ok(())
        }
    }
}

fn main() -> Result<(), CoseError> {
    // Build a fake signer/verifier (to avoid pulling in lots of dependencies).
    let signer = FakeSigner {};
    let verifier = signer;

    // Build a CWT ClaimsSet (cf. RFC 8392 A.3).
    let claims = cwt::ClaimsSetBuilder::new()
        .issuer("coap://as.example.com".to_string())
        .subject("erikw".to_string())
        .audience("coap://light.example.com".to_string())
        .expiration_time(cwt::Timestamp::WholeSeconds(1444064944))
        .not_before(cwt::Timestamp::WholeSeconds(1443944944))
        .issued_at(cwt::Timestamp::WholeSeconds(1443944944))
        .cwt_id(vec![0x0b, 0x71])
        // Add additional standard claim.
        .claim(
            iana::CwtClaimName::Scope,
            Value::Text("email phone".to_string()),
        )
        // Add additional private-use claim.
        .private_claim(-70_000, Value::Integer(42.into()))
        .build();
    let aad = b"";

    // Build a `CoseSign1` object.
    let protected = coset::HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();
    let unprotected = coset::HeaderBuilder::new()
        .key_id(b"AsymmetricECDSA256".to_vec())
        .build();
    let sign1 = coset::CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(claims.clone().to_vec()?)
        .create_signature(aad, |pt| signer.sign(pt))
        .build();

    // Serialize to bytes.
    let sign1_data = sign1.to_vec()?;

    // At the receiving end, deserialize the bytes back to a `CoseSign1` object.
    let sign1 = coset::CoseSign1::from_slice(&sign1_data)?;

    // Real code would:
    // - Use the key ID to identify the relevant local key.
    // - Check that the key is of the same type as `sign1.protected.algorithm`.

    // Check the signature.
    let result = sign1.verify_signature(aad, |sig, data| verifier.verify(sig, data));
    println!("Signature verified: {:?}.", result);
    assert!(result.is_ok());

    // Now it's safe to parse the payload.
    let recovered_claims = cwt::ClaimsSet::from_slice(&sign1.payload.unwrap())?;

    assert_eq!(recovered_claims, claims);
    Ok(())
}
