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

//! Enumerations for IANA-managed values.
//!
//! Sources:
//! - <https://www.iana.org/assignments/cose/cose.xhtml>
//! - <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
//! - <https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats>
//! - <https://www.iana.org/assignments/cwt/cwt.xhtml>

#[cfg(test)]
mod tests;

/// Trait indicating an enum that can be constructed from `i64` values.
pub trait EnumI64: Sized + Eq {
    fn from_i64(i: i64) -> Option<Self>;
    fn to_i64(&self) -> i64;
}

/// Trait indicating an enum with a range of private values.
pub trait WithPrivateRange {
    fn is_private(i: i64) -> bool;
}

/// Generate an enum with associated values, plus a `from_i64` method.
macro_rules! iana_registry {
    ( $(#[$attr:meta])* $enum_name:ident {$($(#[$fattr:meta])* $name:ident: $val:expr,)* } ) => {
        #[allow(non_camel_case_types)]
        $(#[$attr])*
        #[non_exhaustive]
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub enum $enum_name {
            $($(#[$fattr])* $name = $val,)*
        }
        impl EnumI64 for $enum_name {
            fn from_i64(i: i64) -> Option<Self> {
                match i {
                    $(x if x == Self::$name as i64 => Some(Self::$name),)*
                    _ => None,
                }
            }
            #[inline]
            fn to_i64(&self) -> i64 {
                *self as i64
            }
        }
    }
}

iana_registry! {
    /// IANA-registered COSE header parameters.
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#header-parameters>
    /// as of 2023-07-12.
    HeaderParameter {
        /// Reserved
        Reserved: 0,
        /// Cryptographic algorithm to use
        ///
        /// Associated value of type int / tstr
        Alg: 1,
        /// Critical headers to be understood
        ///
        /// Associated value of type [+ label]
        Crit: 2,
        /// Content type of the payload
        ///
        /// Associated value of type tstr / uint
        ContentType: 3,
        /// Key identifier
        ///
        /// Associated value of type bstr
        Kid: 4,
        /// Full Initialization Vector
        ///
        /// Associated value of type bstr
        Iv: 5,
        /// Partial Initialization Vector
        ///
        /// Associated value of type bstr
        PartialIv: 6,
        /// CBOR-encoded signature structure
        ///
        /// Associated value of type COSE_Signature / [+ COSE_Signature ]
        CounterSignature: 7,
        /// Counter signature with implied signer and headers
        ///
        /// Associated value of type bstr
        CounterSignature0: 9,
        /// Identifies the context for the key identifier
        ///
        /// Associated value of type bstr
        KidContext: 10,
        /// Counter signature v2
        ///
        /// Associated value of type COSE_Countersignature / [+ COSE_Countersignature]
        CounterSignatureV2: 11,
        /// Abbreviated counter signature v2.
        ///
        /// Associated value of type COSE_Countersignature0
        CounterSignature0V2:12,
        /// An unordered bag of X.509 certificates
        ///
        /// Associated value of type COSE_X509
        X5Bag: 32,
        /// An ordered chain of X.509 certificates
        ///
        /// Associated value of type COSE_X509
        X5Chain: 33,
        /// Hash of an X.509 certificate
        ///
        /// Associated value of type COSE_CertHash
        X5T: 34,
        /// URI pointing to an X.509 certificate
        ///
        /// Associated value of type uri
        X5U: 35,
        /// Challenge Nonce
        ///
        /// Associated value of type bstr
        CuphNonce: 256,
        /// Public Key
        ///
        /// Associated value of type array
        CuphOwnerPubKey: 257,
    }
}

/// Integer values for COSE header parameters below this value are reserved for private use.
pub const HEADER_PARAMETER_PRIVATE_USE_MAX: i64 = -65536;

impl WithPrivateRange for HeaderParameter {
    fn is_private(i: i64) -> bool {
        i < HEADER_PARAMETER_PRIVATE_USE_MAX
    }
}

iana_registry! {
    /// IANA-registered COSE header algorithm parameters.
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#header-algorithm-parameters>
    /// as of 2023-07-12.
    HeaderAlgorithmParameter {
        /// Static key X.509 certificate chain
        ///
        /// Associated value of type COSE_X509
        X5ChainSender: -29,
        /// URI for the sender's X.509 certificate
        ///
        /// Associated value of type uri
        X5USender: -28,
        /// Thumbprint for the sender's X.509 certificate
        ///
        /// Associated value of type COSE_CertHash
        X5TSender: -27,
        /// Party V other provided information
        ///
        /// Associated value of type bstr
        PartyVOther: -26,
        /// Party V provided nonce
        ///
        /// Associated value of type bstr / int
        PartyVNonce: -25,
        /// Party V identity information
        ///
        /// Associated value of type bstr
        PartyVIdentity: -24,
        /// Party U other provided information
        ///
        /// Associated value of type bstr
        PartyUOther: -23,
        /// Party U provided nonce
        ///
        /// Associated value of type bstr / int
        PartyUNonce: -22,
        /// Party U identity information
        ///
        /// Associated value of type bstr
        PartyUIdentity: -21,
        /// Random salt
        ///
        /// Associated value of type bstr
        Salt: -20,
        /// Static public key identifier for the sender
        ///
        /// Associated value of type bstr
        StaticKeyId: -3,
        /// Static public key for the sender
        ///
        /// Associated value of type COSE_Key
        StaticKey: -2,
        /// Ephemeral public key for the sender
        ///
        /// Associated value of type COSE_Key
        EphemeralKey: -1,
    }
}

iana_registry! {
    /// IANA-registered COSE algorithms.
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
    /// as of 2023-07-12.
    Algorithm {
        /// RSASSA-PKCS1-v1_5 using SHA-1
        RS1: -65535,
        /// WalnutDSA signature
        WalnutDSA: -260,
        /// RSASSA-PKCS1-v1_5 using SHA-512
        RS512: -259,
        /// RSASSA-PKCS1-v1_5 using SHA-384
        RS384: -258,
        /// RSASSA-PKCS1-v1_5 using SHA-256
        RS256: -257,
        /// ECDSA using secp256k1 curve and SHA-256
        ES256K: -47,
        /// HSS/LMS hash-based digital signature
        HSS_LMS: -46,
        /// SHAKE-256 512-bit Hash Value
        SHAKE256: -45,
        /// SHA-2 512-bit Hash
        SHA_512: -44,
        /// SHA-2 384-bit Hash
        SHA_384: -43,
        /// RSAES-OAEP w/ SHA-512
        RSAES_OAEP_SHA_512: -42,
        /// RSAES-OAEP w/ SHA-256
        RSAES_OAEP_SHA_256: -41,
        /// RSAES-OAEP w/ SHA-1
        RSAES_OAEP_RFC_8017_default: -40,
        /// RSASSA-PSS w/ SHA-512
        PS512: -39,
        /// RSASSA-PSS_SHA-384
        PS384: -38,
        /// RSASSA-PSS w/ SHA-256
        PS256: -37,
        /// ECDSA w/ SHA-512
        ES512: -36,
        /// ECDSA w/ SHA-384
        ES384: -35,
        /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
        ECDH_SS_A256KW: -34,
        /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
        ECDH_SS_A192KW: -33,
        /// ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
        ECDH_SS_A128KW: -32,
        /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
        ECDH_ES_A256KW: -31,
        /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
        ECDH_ES_A192KW: -30,
        /// ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
        ECDH_ES_A128KW: -29,
        /// ECDH SS w/ HKDF - generate key directly
        ECDH_SS_HKDF_512: -28,
        /// ECDH SS w/ HKDF - generate key directly
        ECDH_SS_HKDF_256: -27,
        /// ECDH ES w/ HKDF - generate key directly
        ECDH_ES_HKDF_512: -26,
        /// ECDH ES w/ HKDF - generate key directly
        ECDH_ES_HKDF_256: -25,
        /// SHAKE-128 256-bit Hash Value
        SHAKE128: -18,
        /// SHA-2 512-bit Hash truncated to 256-bits
        SHA_512_256: -17,
        /// SHA-2 256-bit Hash
        SHA_256: -16,
        /// SHA-2 256-bit Hash truncated to 64-bits
        SHA_256_64: -15,
        /// SHA-1 Hash
        SHA_1: -14,
        /// Shared secret w/ AES-MAC 256-bit key
        Direct_HKDF_AES_256: -13,
        /// Shared secret w/ AES-MAC 128-bit key
        Direct_HKDF_AES_128: -12,
        /// Shared secret w/ HKDF and SHA-512
        Direct_HKDF_SHA_512: -11,
        /// Shared secret w/ HKDF and SHA-256
        Direct_HKDF_SHA_256: -10,
        /// EdDSA
        EdDSA: -8,
        /// ECDSA w/ SHA-256
        ES256: -7,
        /// Direct use of CEK
        Direct: -6,
        /// AES Key Wrap w/ 256-bit key
        A256KW: -5,
        /// AES Key Wrap w/ 192-bit key
        A192KW: -4,
        /// AES Key Wrap w/ 128-bit key
        A128KW: -3,
        /// Reserved
        Reserved: 0,
        /// AES-GCM mode w/ 128-bit key, 128-bit tag
        A128GCM: 1,
        /// AES-GCM mode w/ 192-bit key, 128-bit tag
        A192GCM: 2,
        /// AES-GCM mode w/ 256-bit key, 128-bit tag
        A256GCM: 3,
        /// HMAC w/ SHA-256 truncated to 64 bits
        HMAC_256_64: 4,
        /// HMAC w/ SHA-256
        HMAC_256_256: 5,
        /// HMAC w/ SHA-384
        HMAC_384_384: 6,
        /// HMAC w/ SHA-512
        HMAC_512_512: 7,
        /// AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
        AES_CCM_16_64_128: 10,
        /// AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
        AES_CCM_16_64_256: 11,
        /// AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
        AES_CCM_64_64_128: 12,
        /// AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
        AES_CCM_64_64_256: 13,
        /// AES-MAC 128-bit key, 64-bit tag
        AES_MAC_128_64: 14,
        /// AES-MAC 256-bit key, 64-bit tag
        AES_MAC_256_64: 15,
        /// ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
        ChaCha20Poly1305: 24,
        /// AES-MAC 128-bit key, 128-bit tag
        AES_MAC_128_128: 25,
        /// AES-MAC 256-bit key, 128-bit tag
        AES_MAC_256_128: 26,
        /// AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
        AES_CCM_16_128_128: 30,
        /// AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
        AES_CCM_16_128_256: 31,
        /// AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
        AES_CCM_64_128_128: 32,
        /// AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
        AES_CCM_64_128_256: 33,
        /// For doing IV generation for symmetric algorithms.
        IV_GENERATION: 34,
    }
}

/// Integer values for COSE algorithms below this value are reserved for private use.
pub const ALGORITHM_PRIVATE_USE_MAX: i64 = -65536;

impl WithPrivateRange for Algorithm {
    fn is_private(i: i64) -> bool {
        i < ALGORITHM_PRIVATE_USE_MAX
    }
}

iana_registry! {
    /// IANA-registered COSE common key parameters.
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters>
    /// as of 2023-07-12.
    KeyParameter {
        /// Reserved value.
        Reserved: 0,
        /// Identification of the key type
        ///
        /// Associated value of type tstr / int
        Kty: 1,
        /// Key identification value - match to kid in message
        ///
        /// Associated value of type bstr
        Kid: 2,
        /// Key usage restriction to this algorithm
        ///
        /// Associated value of type tstr / int
        Alg: 3,
        /// Restrict set of permissible operations
        ///
        /// Associated value of type [+ (tstr / int)]
        KeyOps: 4,
        /// Base IV to be XORed with Partial IVs
        ///
        /// Associated value of type bstr
        BaseIv: 5,
    }
}

iana_registry! {
    /// IANA-registered COSE key parameters for keys of type [`KeyType::OKP`].
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
    /// as of 2023-07-12.
    OkpKeyParameter {
        /// EC identifier - Taken from the "COSE Elliptic Curves" registry
        ///
        /// Associated value of type tstr / int
        Crv: -1,
        /// x-coordinate
        ///
        /// Associated value of type bstr
        X: -2,
        /// Private key
        ///
        /// Associated value of type bstr
        D: -4,
    }
}

iana_registry! {
    /// IANA-registered COSE key parameters for keys of type [`KeyType::EC2`].
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
    /// as of 2023-07-12.
    Ec2KeyParameter {
        /// EC identifier - Taken from the "COSE Elliptic Curves" registry
        ///
        /// Associated value of type tstr / int
        Crv: -1,
        /// Public Key
        ///
        /// Associated value of type bstr
        X: -2,
        /// y-coordinate
        ///
        /// Associated value of type bstr / bool
        Y: -3,
        /// Private key
        ///
        /// Associated value of type bstr
        D: -4,
    }
}

iana_registry! {
    /// IANA-registered COSE key parameters for keys of type [`KeyType::RSA`].
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
    /// as of 2023-07-12.
    RsaKeyParameter {
        /// The RSA modulus n
        ///
        /// Associated value of type bstr
        N: -1,
        /// The RSA public exponent e
        ///
        /// Associated value of type bstr
        E: -2,
        /// The RSA private exponent d
        ///
        /// Associated value of type bstr
        D: -3,
        /// The prime factor p of n
        ///
        /// Associated value of type bstr
        P: -4,
        /// The prime factor q of n
        ///
        /// Associated value of type bstr
        Q: -5,
        /// dP is d mod (p - 1)
        ///
        /// Associated value of type bstr
        DP: -6,
        /// dQ is d mod (q - 1)
        ///
        /// Associated value of type bstr
        DQ: -7,
        /// qInv is the CRT coefficient q^(-1) mod p
        ///
        /// Associated value of type bstr
        QInv: -8,
        /// Other prime infos, an array
        ///
        /// Associated value of type array
        Other: -9,
        /// a prime factor r_i of n, where i >= 3
        ///
        /// Associated value of type bstr
        RI: -10,
        /// d_i = d mod (r_i - 1)
        ///
        /// Associated value of type bstr
        DI: -11,
        /// The CRT coefficient t_i = (r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i
        ///
        /// Associated value of type bstr
        TI: -12,
    }
}

iana_registry! {
    /// IANA-registered COSE key parameters for keys of type [`KeyType::Symmetric`].
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
    /// as of 2023-07-12.
    SymmetricKeyParameter {
        /// Key Value
        ///
        /// Associated value of type bstr
        K: -1,
    }
}

iana_registry! {
    /// IANA-registered COSE key parameters for keys of type [`KeyType::HSS_LMS`].
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
    /// as of 2023-07-12.
    HssLmsKeyParameter {
        /// Public key for HSS/LMS hash-based digital signature
        ///
        /// Associated value of type bstr
        Pub: -1,
    }
}

iana_registry! {
    /// IANA-registered COSE key parameters for keys of type [`KeyType::WalnutDSA`].
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
    /// as of 2023-07-12.
    WalnutDsaKeyParameter {
        /// Group and Matrix (NxN) size
        ///
        /// Associated value of type uint
        N: -1,
        /// Finite field F_q
        ///
        /// Associated value of type uint
        Q: -2,
        /// List of T-values, enties in F_q
        ///
        /// Associated value of type array of uint
        TValues: -3,
        /// NxN Matrix of enties in F_q in column-major form
        ///
        /// Associated value of type array of array of uint
        Matrix1: -4,
        /// Permutation associated with matrix 1
        ///
        /// Associated value of type array of uint
        Permutation1: -5,
        /// NxN Matrix of enties in F_q in column-major form
        ///
        /// Associated value of type array of array of uint
        Matrix2: -6,
    }
}

iana_registry! {
    /// IANA-registered COSE key types.
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type>
    /// as of 2023-07-12.
    KeyType {
        /// This value is reserved
        Reserved: 0,
        /// Octet Key Pair
        OKP: 1,
        /// Elliptic Curve Keys w/ x- and y-coordinate pair
        EC2: 2,
        /// RSA Key
        RSA: 3,
        /// Symmetric Keys
        Symmetric: 4,
        /// Public key for HSS/LMS hash-based digital signature
        HSS_LMS: 5,
        /// WalnutDSA public key
        WalnutDSA: 6,
    }
}

iana_registry! {
    /// IANA-registered COSE elliptic curves.
    ///
    /// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves>
    /// as of 2023-07-12.
    EllipticCurve {
        Reserved: 0,
        /// EC2: NIST P-256 also known as secp256r1
        P_256: 1,
        /// EC2: NIST P-384 also known as secp384r1
        P_384: 2,
        /// EC2: NIST P-521 also known as secp521r1
        P_521: 3,
        /// OKP: X25519 for use w/ ECDH only
        X25519: 4,
        /// OKP: X448 for use w/ ECDH only
        X448: 5,
        /// OKP: Ed25519 for use w/ EdDSA only
        Ed25519: 6,
        /// OKP: Ed448 for use w/ EdDSA only
        Ed448: 7,
        /// EC2: SECG secp256k1 curve
        Secp256k1: 8,
    }
}

/// Integer values for COSE elliptic curves below this value are reserved for private use.
pub const ELLIPTIC_CURVE_PRIVATE_USE_MAX: i64 = -65536;

impl WithPrivateRange for EllipticCurve {
    fn is_private(i: i64) -> bool {
        i < ELLIPTIC_CURVE_PRIVATE_USE_MAX
    }
}

iana_registry! {
    /// Key operation values.
    ///
    /// See RFC 8152 section 7.1 table 4.
    KeyOperation {
        /// Key is used to create signatures. Requires private key fields.
        Sign: 1,
        /// Key is used for verification of signatures.
        Verify: 2,
        /// Key is used for key transport encryption.
        Encrypt: 3,
        /// Key is used for key transport decryption. Requires private key fields.
        Decrypt: 4,
        /// Key is used for key wrap encryption.
        WrapKey: 5,
        /// Key is used for key wrap decryption.  Requires private key fields.
        UnwrapKey: 6,
        /// Key is used for deriving keys.  Requires private key fields.
        DeriveKey: 7,
        /// Key is used for deriving bits not to be used as a key.  Requires private key fields.
        DeriveBits: 8,
        /// Key is used for creating MACs.
        MacCreate: 9,
        /// Key is used for validating MACs.
        MacVerify: 10,
    }
}

iana_registry! {
    /// CBOR tag values for COSE structures.
    ///
    /// From IANA registry <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
    /// as of 2023-07-12.
    CborTag {
        /// COSE Single Recipient Encrypted Data Object
        CoseEncrypt0: 16,
        /// COSE Mac w/o Recipients Object
        CoseMac0: 17,
        /// COSE Single Signer Data Object
        CoseSign1: 18,
        /// CBOR Web Token (CWT)
        Cwt: 61,
        /// COSE Encrypted Data Object
        CoseEncrypt: 96,
        /// COSE MACed Data Object
        CoseMac: 97,
        /// COSE Signed Data Object
        CoseSign: 98,
    }
}

iana_registry! {
    /// CoAP Content Formats
    ///
    /// From IANA registry <https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats>
    /// as of 2023-07-12.
    CoapContentFormat {
        /// text/plain; charset=utf-8
        TextPlainUtf8: 0,
        /// application/cose; cose-type="cose-encrypt0"
        CoseEncrypt0: 16,
        /// application/cose; cose-type="cose-mac0"
        CoseMac0: 17,
        /// application/cose; cose-type="cose-sign1"
        CoseSign1: 18,
        /// application/ace+cbor
        AceCbor: 19,
        /// image/gif
        ImageGif: 21,
        /// image/jpeg
        ImageJpeg: 22,
        /// image/png
        ImagePng: 23,
        /// application/link-format
        LinkFormat: 40,
        /// application/xml
        Xml: 41,
        /// application/octet-stream
        OctetStream: 42,
        /// application/exi
        Exi: 47,
        /// application/json
        Json: 50,
        /// application/json-patch+json
        JsonPatchJson: 51,
        /// application/merge-patch+json
        MergePatchJson: 52,
        /// application/cbor
        Cbor: 60,
        /// application/cwt
        Cwt: 61,
        /// application/multipart-core
        MultipartCore: 62,
        /// application/cbor-seq
        CborSeq: 63,
        /// application/cose; cose-type="cose-encrypt"
        CoseEncrypt: 96,
        /// application/cose; cose-type="cose-mac"
        CoseMac: 97,
        /// application/cose; cose-type="cose-sign"
        CoseSign: 98,
        /// application/cose-key
        CoseKey: 101,
        /// application/cose-key-set
        CoseKeySet: 102,
        /// application/senml+json
        SenmlJson: 110,
        /// application/sensml+json
        SensmlJson: 111,
        /// application/senml+cbor
        SenmlCbor: 112,
        /// application/sensml+cbor
        SensmlCbor: 113,
        /// application/senml-exi
        SenmlExi: 114,
        /// application/sensml-exi
        SensmlExi: 115,
        /// application/yang-data+cbor
        YangData: 140,
        /// application/coap-group+json
        CoapGroupJson: 256,

        /// application/concise-problem-details+cbor
        ConciseProblemDetailsCbor: 257,
        /// application/swid+cbor
        SwidCbor:258,
        /// application/pkixcmp
        PkixCmp: 259,
        /// application/dots+cbor
        DotsCbor: 271,
        /// application/missing-blocks+cbor-seq
        MissingBlocksCborSeq: 272,
        /// application/pkcs7-mime; smime-type=server-generated-key
        Pkcs7MimeSmimeTypeServerGeneratedKey: 280,
        /// application/pkcs7-mime; smime-type=certs-only
        Pkcs7MimeSmimeTypeCertsOnly: 281,
        /// application/pkcs7-mime; smime-type=CMC-Request
        Pkcs7MimeSmimeTypeCmcRequest: 282,
        /// application/pkcs7-mime; smime-type=CMC-Response
        Pkcs7MimeSmimeTypeCmcResponse: 283,
        /// application/pkcs8
        Pkcs8: 284,
        /// application/csrattrs
        Csrattrs: 285,
        /// application/pkcs10
        Pkcs10: 286,
        /// application/pkix-cert
        PkixCert: 287,
        /// application/aif+cbor
        AifCbor: 290,
        /// application/aif+json
        AifJson: 291,
        /// application/senml+xml
        SenmlXml: 310,
        /// application/sensml+xml
        SensmlXml: 311,
        /// application/senml-etch+json
        SenmlEtchJson: 320,
        /// application/senml-etch+cbor
        SenmlEtchCbor: 322,
        /// application/yang-data+cbor
        YangDataCbor: 340,
        /// application/yang-data+cbor; id=name
        YangDataCborName: 341,
        /// application/td+json
        TdJson: 432,
        /// application/tm+json
        TmJson: 433,
        /// application/vnd.ocf+cbor
        VndOcfCbor: 10000,
        /// application/oscore
        Oscore: 10001,
        /// application/javascript
        Javascript: 10002,
        /// application/json deflate
        JsonDeflate: 11050,
        /// application/cbor deflate
        CborDeflate: 11060,
        /// application/vnd.oma.lwm2m+tlv
        VndOmaLwm2mTlv: 11542,
        /// application/vnd.oma.lwm2m+json
        VndOmaLwm2mJson: 11543,
        /// application/vnd.oma.lwm2m+cbor
        VndOmaLwm2mCbor: 11544,
        /// text/css
        TextCss: 20000,
        /// image/svg+xml
        ImageSvgXml: 30000,
    }
}

iana_registry! {
    /// CBOR Web Token (CWT) Claims
    /// From IANA registry <https://www.iana.org/assignments/cwt/cwt.xhtml>
    /// as of 2023-07-12.
    CwtClaimName {
        /// Health certificate ("hcert": map).
        Hcert: -260,
        /// Challenge nonce ("EUPHNonce": bstr).
        EuphNonce: -259,
        /// Signing prefix for multi-app restricted operating environment ("EATMAROEPrefix": bstr).
        EatMaroePrefix: -258,
        /// FIDO Device Onboarding EAT ("EAT-FDO": array).
        EatFido: -257,
        /// Reserved value.
        Reserved: 0,
        /// Issuer ("iss": tstr).
        Iss: 1,
        /// Subject ("sub": tstr)
        Sub: 2,
        /// Audience ("aud": tstr)
        Aud: 3,
        /// Expiration Time, as seconds since UNIX epoch ("exp": int/float)
        Exp: 4,
        /// Not Before, as seconds since UNIX epoch ("nbf": int/float)
        Nbf: 5,
        /// Issued at, as seconds since UNIX epoch ("iat": int/float)
        Iat: 6,
        /// CWT ID ("cti": bstr)
        Cti: 7,
        /// Confirmation ("cnf": map)
        Cnf: 8,
        /// Scope of an access token ("scope": bstr/tstr)
        Scope: 9,
        /// The ACE profile a token is supposed to be used with ("ace_profile": int)
        AceProfile: 38,
        /// The client-nonce sent to the AS by the RS via the client ("cnonce": bstr)
        CNonce: 39,
        /// The expiration time of a token measured from when it was received at the RS in seconds ("exi": int)
        Exi: 40,
    }
}

/// Integer values for CWT claims below this value are reserved for private use.
pub const CWT_CLAIM_PRIVATE_USE_MAX: i64 = -65536;

impl WithPrivateRange for CwtClaimName {
    fn is_private(i: i64) -> bool {
        i < CWT_CLAIM_PRIVATE_USE_MAX
    }
}
