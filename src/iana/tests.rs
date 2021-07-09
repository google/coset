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

use super::*;

#[test]
fn test_algorithm_conversion() {
    assert_eq!(Some(Algorithm::ES256), Algorithm::from_i64(-7));
    assert_eq!(Some(Algorithm::A128GCM), Algorithm::from_i64(1));
    assert_eq!(Algorithm::A128GCM as i64, 1);
    assert_eq!(None, Algorithm::from_i64(8));
    assert_eq!(None, Algorithm::from_i64(-65538));
}

#[test]
fn test_header_param_private_range() {
    assert!(!HeaderParameter::is_private(1));
    assert!(HeaderParameter::is_private(-70_000));
}

#[test]
fn test_elliptic_curve_private_range() {
    assert!(!EllipticCurve::is_private(1));
    assert!(EllipticCurve::is_private(-70_000));
}
