// Spec: docs/specs/open-source-libs.md

//! PEM/key parsing utilities for RA-TLS certificate chains.
//!
//! This crate provides three focused helpers for working with `rustls` in
//! Remote Attestation TLS (RA-TLS) contexts, where the server (and optionally
//! client) certificate is a self-signed X.509 cert with a TDX attestation
//! quote embedded in a custom extension.
//!
//! # Example
//!
//! ```no_run
//! use ra_tls_parse::{parse_certificates, parse_private_key, build_root_store};
//!
//! let key_pem = std::fs::read_to_string("server.key").unwrap();
//! let cert_pem = std::fs::read_to_string("server.crt").unwrap();
//!
//! let key = parse_private_key(&key_pem).unwrap();
//! let certs = parse_certificates(&cert_pem).unwrap();
//! let root_store = build_root_store(&certs).unwrap();
//! ```

use anyhow::Result;

/// Parse a PEM-encoded private key. Accepts PKCS#8, SEC1 (EC), and PKCS#1 (RSA) formats.
///
/// Returns the first private key found in the PEM data. If the PEM contains
/// multiple items (e.g. a cert chain followed by a key), non-key items are
/// silently skipped.
///
/// # Errors
/// Returns an error if no private key is found, or if the PEM data is malformed.
pub fn parse_private_key(pem: &str) -> Result<rustls_pki_types::PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    for item in rustls_pemfile::read_all(&mut reader) {
        match item {
            Ok(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(rustls_pki_types::PrivateKeyDer::Pkcs8(key))
            }
            Ok(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(rustls_pki_types::PrivateKeyDer::Sec1(key))
            }
            Ok(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(rustls_pki_types::PrivateKeyDer::Pkcs1(key))
            }
            Ok(_) => continue,
            Err(e) => return Err(anyhow::anyhow!("error parsing PEM item: {}", e)),
        }
    }
    anyhow::bail!("no private key found in PEM data")
}

/// Parse PEM-encoded X.509 certificates from a string.
///
/// Returns all certificates found in the PEM data in order. Useful for
/// loading a full certificate chain (leaf → intermediate → root).
///
/// # Errors
/// Returns an error if the PEM data contains no certificates.
pub fn parse_certificates(pem: &str) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let mut certs = Vec::new();
    for item in rustls_pemfile::read_all(&mut reader).flatten() {
        if let rustls_pemfile::Item::X509Certificate(cert) = item {
            certs.push(cert);
        }
    }
    if certs.is_empty() {
        anyhow::bail!("no certificates found in PEM data");
    }
    Ok(certs)
}

/// Build a [`rustls::RootCertStore`] from a certificate chain.
///
/// In RA-TLS, both the server and client certificates are signed by the
/// dstack KMS CA. This function uses the **last** certificate in the chain
/// as the trust anchor, which is the standard RA-TLS pattern where the CA
/// cert appears at the end of the chain.
///
/// If `certs` is empty, an empty `RootCertStore` is returned (no error).
///
/// # Errors
/// Returns an error if a certificate cannot be added to the store (e.g.
/// malformed DER data).
pub fn build_root_store(
    certs: &[rustls_pki_types::CertificateDer<'static>],
) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    if let Some(root_cert) = certs.last() {
        root_store
            .add(root_cert.clone())
            .map_err(|e| anyhow::anyhow!("failed to add root cert to store: {}", e))?;
    }
    Ok(root_store)
}
