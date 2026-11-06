//! Legacy RSA DTLS signing key and CAPWAP server identity loading.
//!
//! Copyright (c) 2026  Wang Jian

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::{DecryptingKey, SigningKey as RsaPkcs1SigningKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::{Decryptor, PublicKeyParts};
use rsa::PrivateKey;
use rtc_dtls::crypto_provider::{
    CryptoAlgorithm, CryptoError, PublicKey, PublicKeyEncoding, SignatureScheme, SigningKey,
};
use sha1::Sha1;
use sha2::Sha256;

/// RSA PKCS#1 v1.5 signing key for legacy peers (1024-bit RSA, SHA-1/SHA-256).
///
/// The default crypto provider refuses to import sub-2048-bit RSA keys, so the server identity is
/// handed to `Certificate::from_signing_key` with a provider-neutral key instead.
pub struct RsaLegacySigningKey {
    key: PrivateKey,
    public_key_der: Vec<u8>,
}

impl RsaLegacySigningKey {
    /// Loads an `RSA PRIVATE KEY` (PKCS#1) block.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let key = PrivateKey::from_pkcs1_der(der)
            .map_err(|e| anyhow!("invalid PKCS#1 RSA key: {e}"))?;
        Self::from_key(key)
    }

    /// Loads a `PRIVATE KEY` (PKCS#8) block.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key = PrivateKey::from_pkcs8_der(der)
            .map_err(|e| anyhow!("invalid PKCS#8 RSA key: {e}"))?;
        Self::from_key(key)
    }

    fn from_key(key: PrivateKey) -> Result<Self> {
        if key.n().bit_width() < 1024 {
            // 1024 bits is the smallest size the ring verifier accepts (with
            // insecure_verification) for PKCS#1 signatures.
            return Err(anyhow!("RSA key too small: {} bits", key.n().bit_width()));
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

/// Loads the CAPWAP server identity from an explicit PEM file.
pub fn load_identity_file(path: &Path) -> Result<ServerIdentity> {
    let text = std::fs::read_to_string(path)
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
