use ra_tls_parse::{build_root_store, parse_certificates, parse_private_key};
use rcgen::generate_simple_self_signed;

fn make_cert_and_key() -> (String, String) {
    let subject_alt_names = vec!["localhost".to_string()];
    let certified = generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    (cert_pem, key_pem)
}

// --- parse_private_key ---

#[test]
fn parse_private_key_pkcs8_succeeds() {
    let (_cert_pem, key_pem) = make_cert_and_key();
    let result = parse_private_key(&key_pem);
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);
}

#[test]
fn parse_private_key_cert_only_returns_err() {
    let (cert_pem, _key_pem) = make_cert_and_key();
    let result = parse_private_key(&cert_pem);
    assert!(result.is_err(), "expected Err when PEM contains only a certificate");
}

#[test]
fn parse_private_key_empty_string_returns_err() {
    let result = parse_private_key("");
    assert!(result.is_err(), "expected Err for empty PEM string");
}

// --- parse_certificates ---

#[test]
fn parse_certificates_single_cert_succeeds() {
    let (cert_pem, _key_pem) = make_cert_and_key();
    let result = parse_certificates(&cert_pem);
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn parse_certificates_chain_returns_correct_count() {
    // Build a two-cert chain by concatenating two PEMs.
    let (cert1_pem, _) = make_cert_and_key();
    let (cert2_pem, _) = make_cert_and_key();
    let chain_pem = format!("{}\n{}", cert1_pem, cert2_pem);

    let result = parse_certificates(&chain_pem);
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    assert_eq!(result.unwrap().len(), 2, "expected two certs in chain");
}

#[test]
fn parse_certificates_no_cert_pem_returns_err() {
    let (_cert_pem, key_pem) = make_cert_and_key();
    let result = parse_certificates(&key_pem);
    assert!(result.is_err(), "expected Err when PEM contains only a private key");
}

#[test]
fn parse_certificates_empty_string_returns_err() {
    let result = parse_certificates("");
    assert!(result.is_err(), "expected Err for empty PEM string");
}

// --- build_root_store ---

#[test]
fn build_root_store_empty_slice_returns_ok_empty_store() {
    let result = build_root_store(&[]);
    assert!(result.is_ok(), "expected Ok for empty slice");
    let store = result.unwrap();
    assert_eq!(store.len(), 0, "expected empty store");
}

#[test]
fn build_root_store_single_cert_returns_ok() {
    let (cert_pem, _key_pem) = make_cert_and_key();
    let certs = parse_certificates(&cert_pem).unwrap();

    let result = build_root_store(&certs);
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    let store = result.unwrap();
    assert_eq!(store.len(), 1, "expected one cert in store");
}

#[test]
fn build_root_store_multi_cert_chain_uses_last_cert_as_root() {
    // Build a two-cert chain; only the last should be added as the trust anchor.
    let (cert1_pem, _) = make_cert_and_key();
    let (cert2_pem, _) = make_cert_and_key();
    let chain_pem = format!("{}\n{}", cert1_pem, cert2_pem);

    let certs = parse_certificates(&chain_pem).unwrap();
    assert_eq!(certs.len(), 2, "setup: expected two certs in chain");

    let result = build_root_store(&certs);
    assert!(result.is_ok(), "expected Ok, got: {:?}", result);

    let store = result.unwrap();
    // Only the last cert (the root/CA) should be in the store.
    assert_eq!(store.len(), 1, "expected exactly one cert in root store");
}
