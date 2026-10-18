//! Legacy RSA DTLS signing key and CAPWAP certificate-chain verification.
//!
//! Copyright (c) 2026  Wang Jian

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::{
    DecryptingKey, Signature as RsaSignature, SigningKey as RsaPkcs1SigningKey,
    VerifyingKey as RsaPkcs1VerifyingKey,
};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::{Decryptor, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rtc_dtls::config::VerifyPeerCertificateFn;
use rtc_dtls::crypto_provider::{
    CryptoAlgorithm, CryptoError, PublicKey, PublicKeyEncoding, SignatureScheme, SigningKey,
};
use sha1::Sha1;
use sha2::Sha256;
use x509_parser::parse_x509_certificate;

// OID 1.2.840.113549.1.1.5 (sha1WithRSAEncryption) and 1.2.840.113549.1.1.11
// (sha256WithRSAEncryption); compared by raw bytes because asn1_rs::Oid is not Copy.
const OID_SHA1_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

/// RSA PKCS#1 v1.5 signing key for legacy peers (1024-bit RSA, SHA-1/SHA-256).
///
/// The default crypto provider refuses to import sub-2048-bit RSA keys, so the server identity is
/// handed to `Certificate::from_signing_key` with a provider-neutral key instead.
pub struct RsaLegacySigningKey {
    key: RsaPrivateKey,
    public_key_der: Vec<u8>,
}

impl RsaLegacySigningKey {
    /// Loads an `RSA PRIVATE KEY` (PKCS#1) block.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|e| anyhow!("invalid PKCS#1 RSA key: {e}"))?;
        Self::from_key(key)
    }

    /// Loads a `PRIVATE KEY` (PKCS#8) block.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| anyhow!("invalid PKCS#8 RSA key: {e}"))?;
        Self::from_key(key)
    }

    fn from_key(key: RsaPrivateKey) -> Result<Self> {
        if key.n().bits() < 1024 {
            // 1024 bits is the smallest size the ring verifier accepts (with
            // insecure_verification) for PKCS#1 signatures.
            return Err(anyhow!("RSA key too small: {} bits", key.n().bits()));
        }
        let public_key_der = key
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|e| anyhow!("encode RSA public key: {e}"))?
            .as_bytes()
            .to_vec();
        Ok(Self {
            key,
            public_key_der,
        })
    }
}

impl SigningKey for RsaLegacySigningKey {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        matches!(
            scheme,
            SignatureScheme::RsaPkcs1Sha1 | SignatureScheme::RsaPkcs1Sha256
        )
    }

    fn public_key(&self) -> PublicKey<'_> {
        PublicKey {
            encoding: PublicKeyEncoding::RsaPkcs1Der,
            bytes: &self.public_key_der,
        }
    }

    fn sign(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        match scheme {
            SignatureScheme::RsaPkcs1Sha1 => RsaPkcs1SigningKey::<Sha1>::new(self.key.clone())
                .try_sign(message)
                .map(|sig| sig.to_bytes().to_vec())
                .map_err(|e| CryptoError::Provider(e.to_string())),
            SignatureScheme::RsaPkcs1Sha256 => RsaPkcs1SigningKey::<Sha256>::new(self.key.clone())
                .try_sign(message)
                .map(|sig| sig.to_bytes().to_vec())
                .map_err(|e| CryptoError::Provider(e.to_string())),
            _ => Err(CryptoError::UnsupportedAlgorithm(
                CryptoAlgorithm::Signature(scheme),
            )),
        }
    }

    fn rsa_decrypt(&self, ciphertext: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        // PKCS#1 v1.5 (type 2 padding) decryption, recovering the client's premaster secret.
        DecryptingKey::new(self.key.clone()).decrypt(ciphertext).map_err(|e| CryptoError::Provider(e.to_string()))
    }
}

/// Server identity loaded from `server.pem` (certificate chain + PKCS#1/PKCS#8 RSA key).
pub struct ServerIdentity {
    pub certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub signing_key: Arc<RsaLegacySigningKey>,
}

/// Loads the CAPWAP server identity from `dir/server.pem`.
pub fn load_identity(dir: &Path) -> Result<ServerIdentity> {
    let path = dir.join("server.pem");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read {} failed", path.display()))?;
    let mut certificate_chain = Vec::new();
    let mut signing_key = None;
    for block in pem::parse_many(text.as_bytes()).context("parse server.pem")? {
        match block.tag() {
            "CERTIFICATE" => certificate_chain.push(rustls::pki_types::CertificateDer::from(
                block.contents().to_vec(),
            )),
            "RSA PRIVATE KEY" => {
                signing_key = Some(RsaLegacySigningKey::from_pkcs1_der(block.contents())?)
            }
            "PRIVATE KEY" => {
                signing_key = Some(RsaLegacySigningKey::from_pkcs8_der(block.contents())?)
            }
            _ => {}
        }
    }
    let signing_key =
        signing_key.ok_or_else(|| anyhow!("no RSA private key in {}", path.display()))?;
    if certificate_chain.is_empty() {
        return Err(anyhow!("no CERTIFICATE block in {}", path.display()));
    }
    Ok(ServerIdentity {
        certificate_chain,
        signing_key: Arc::new(signing_key),
    })
}

/// Returns the DER of the first `CERTIFICATE` block in `dir/root.pem`.
pub fn load_root_cert_der(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("root.pem");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read {} failed", path.display()))?;
    for block in pem::parse_many(text.as_bytes()).context("parse root.pem")? {
        if block.tag() == "CERTIFICATE" {
            return Ok(block.contents().to_vec());
        }
    }
    Err(anyhow!("no CERTIFICATE block in {}", path.display()))
}

/// Builds a `verify_peer_certificate` callback that checks the client chain against
/// `root.pem` (the CAPWAP CA), skipping all validity-period checks.
///
/// The callback runs after the DTLS CertificateVerify was already verified against the
/// client's leaf key; it only pins the chain to the expected CA.
pub fn verify_client_chain_callback(root_der: Vec<u8>) -> VerifyPeerCertificateFn {
    Arc::new(
        move |certs: &[Vec<u8>], _chains: &[rustls::pki_types::CertificateDer<'static>]| {
            verify_client_chain(certs, &root_der)
                .map_err(|e| rtc_shared::error::Error::Other(e.to_string()))
        },
    )
}

/// Verifies that the leaf client certificate was signed by the root CA, ignoring dates.
fn verify_client_chain(certs: &[Vec<u8>], root_der: &[u8]) -> Result<()> {
    let leaf_der = certs
        .first()
        .ok_or_else(|| anyhow!("client presented no certificate"))?;
    let (_, leaf) = parse_x509_certificate(leaf_der).context("parse client certificate")?;
    let (_, root) = parse_x509_certificate(root_der).context("parse CA certificate")?;

    let message = leaf.tbs_certificate.as_ref();
    let signature = leaf.signature_value.as_ref();
    let ca_key = RsaPublicKey::from_public_key_der(root.public_key().raw)
        .map_err(|e| anyhow!("parse CA RSA public key: {e}"))?;

    let algorithm = leaf.signature_algorithm.algorithm.as_bytes();
    if algorithm == OID_SHA1_RSA {
        let verifying_key = RsaPkcs1VerifyingKey::<Sha1>::new(ca_key);
        let signature = RsaSignature::try_from(signature)
            .map_err(|e| anyhow!("bad signature encoding: {e}"))?;
        verifying_key
            .verify(message, &signature)
            .map_err(|e| anyhow!("client certificate signature invalid: {e}"))
    } else if algorithm == OID_SHA256_RSA {
        let verifying_key = RsaPkcs1VerifyingKey::<Sha256>::new(ca_key);
        let signature = RsaSignature::try_from(signature)
            .map_err(|e| anyhow!("bad signature encoding: {e}"))?;
        verifying_key
            .verify(message, &signature)
            .map_err(|e| anyhow!("client certificate signature invalid: {e}"))
    } else {
        Err(anyhow!("unsupported certificate signature algorithm"))
    }
}
