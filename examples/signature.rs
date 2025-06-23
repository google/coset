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

//! Example program demonstrating signature creation.
use coset::{iana, CborSerializable, CoseError};

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

    // Inputs.
    let pt = b"This is the content";
    let aad = b"this is additional data";

    // Build a `CoseSign1` object.
    let protected = coset::HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256.into())
        .key_id(b"11".to_vec())
        .build();
    let sign1 = coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(pt.to_vec())
        .create_signature(aad, |pt| signer.sign(pt))
        .build();

    // Serialize to bytes.
    let sign1_data = sign1.to_vec()?;
    println!(
        "'{}' + '{}' => {}",
        String::from_utf8_lossy(pt),
        String::from_utf8_lossy(aad),
        hex::encode(&sign1_data)
    );

    // At the receiving end, deserialize the bytes back to a `CoseSign1` object.
    let mut sign1 = coset::CoseSign1::from_slice(&sign1_data)?;

    // Check the signature, which needs to have the same `aad` provided.
    let result = sign1.verify_signature(aad, |sig, data| verifier.verify(sig, data));
    println!("Signature verified: {:?}.", result);
    assert!(result.is_ok());

    // Changing an unprotected header leaves the signature valid.
    sign1.unprotected.content_type = Some(coset::ContentType::Text("text/plain".to_owned()));
    assert!(sign1
        .verify_signature(aad, |sig, data| verifier.verify(sig, data))
        .is_ok());

    // Providing a different `aad` means the signature won't validate.
    assert!(sign1
        .verify_signature(b"not aad", |sig, data| verifier.verify(sig, data))
        .is_err());

    // Changing a protected header invalidates the signature.
    sign1.protected.header.content_type = Some(coset::ContentType::Text("text/plain".to_owned()));
    sign1.protected.original_data = None;
    assert!(sign1
        .verify_signature(aad, |sig, data| verifier.verify(sig, data))
        .is_err());
    Ok(())
}
