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

//! Set of types for supporting [CBOR Object Signing and Encryption (COSE)][COSE].
//!
//! Builds on the [`ciborium`](https://docs.rs/ciborium) crate for underlying [CBOR][CBOR] support.
//!
//! ## Usage
//!
//! ```
//! # #[derive(Copy, Clone)]
//! # struct FakeSigner {}
//! # impl FakeSigner {
//! #     fn sign(&self, data: &[u8]) -> Vec<u8> {
//! #         data.to_vec()
//! #     }
//! #     fn verify(&self, sig: &[u8], data: &[u8]) -> Result<(), String> {
//! #         if sig != self.sign(data) {
//! #             Err("failed to verify".to_owned())
//! #         } else {
//! #             Ok(())
//! #         }
//! #     }
//! # }
//! # let signer = FakeSigner {};
//! # let verifier = signer;
//! use coset::{iana, CborSerializable};
//!
//! // Inputs.
//! let pt = b"This is the content";
//! let aad = b"this is additional data";
//!
//! // Build a `CoseSign1` object.
//! let protected = coset::HeaderBuilder::new()
//!     .algorithm(iana::Algorithm::ES256)
//!     .key_id(b"11".to_vec())
//!     .build();
//! let sign1 = coset::CoseSign1Builder::new()
//!     .protected(protected)
//!     .payload(pt.to_vec())
//!     .create_signature(aad, |pt| signer.sign(pt)) // closure to do sign operation
//!     .build();
//!
//! // Serialize to bytes.
//! let sign1_data = sign1.to_vec().unwrap();
//! println!(
//!     "'{}' + '{}' => {}",
//!     String::from_utf8_lossy(pt),
//!     String::from_utf8_lossy(aad),
//!     hex::encode(&sign1_data)
//! );
//!
//! // At the receiving end, deserialize the bytes back to a `CoseSign1` object.
//! let mut sign1 = coset::CoseSign1::from_slice(&sign1_data).unwrap();
//!
//! // At this point, real code would validate the protected headers.
//!
//! // Check the signature, which needs to have the same `aad` provided, by
//! // providing a closure that can do the verify operation.
//! let result = sign1.verify_signature(aad, |sig, data| verifier.verify(sig, data));
//! println!("Signature verified: {:?}.", result);
//! assert!(result.is_ok());
//!
//! // Changing an unprotected header leaves the signature valid.
//! sign1.unprotected.content_type = Some(coset::ContentType::Text("text/plain".to_owned()));
//! assert!(sign1
//!     .verify_signature(aad, |sig, data| verifier.verify(sig, data))
//!     .is_ok());
//!
//! // Providing a different `aad` means the signature won't validate.
//! assert!(sign1
//!     .verify_signature(b"not aad", |sig, data| verifier.verify(sig, data))
//!     .is_err());
//!
//! // Changing a protected header invalidates the signature.
//! sign1.protected.original_data = None;
//! sign1.protected.header.content_type = Some(coset::ContentType::Text("text/plain".to_owned()));
//! assert!(sign1
//!     .verify_signature(aad, |sig, data| verifier.verify(sig, data))
//!     .is_err());
//! ```
//!
//! [COSE]: https://tools.ietf.org/html/rfc8152
//! [CBOR]: https://tools.ietf.org/html/rfc7049

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(rustdoc::broken_intra_doc_links)]
extern crate alloc;

/// Re-export of the `ciborium` crate used for underlying CBOR encoding.
pub use ciborium as cbor;

#[macro_use]
pub(crate) mod util;

pub mod cwt;
#[macro_use]
pub mod iana;

mod common;
pub use common::*;
mod context;
pub use context::*;
mod encrypt;
pub use encrypt::*;
mod header;
pub use header::*;
mod key;
pub use key::*;
mod mac;
pub use mac::*;
mod sign;
pub use sign::*;
