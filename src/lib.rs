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

//! Set of types for supporting CBOR Object Signing and Encryption (COSE).

#![deny(broken_intra_doc_links)]

#[macro_use]
pub(crate) mod util;

pub mod iana;

mod common;
pub use common::*;
mod header;
pub use header::*;
mod key;
pub use key::*;
mod sign;
pub use sign::*;
