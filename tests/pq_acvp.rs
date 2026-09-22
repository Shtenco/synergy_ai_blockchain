#![cfg(feature = "reference-pq")]

use serde::Deserialize;
use synergy_pq_evm_core::{AuthScheme, ReferencePqSignatureVerifier};
use synergy_pq_evm_core::pq::SignatureVerifier;

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct KemFixture {
    provenance: Provenance,
    encapsulation: KemEncapsulationCase,
    decapsulation: KemDecapsulationCase,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    standard: String,
    algorithm: String,
    source_repository: String,
    source_path: String,
    source_blob_sha: String,
    upstream_nist_acvp_commit: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct KemEncapsulationCase {
    tgId: u64,
    tcId: u64,
    testType: String,
    parameterSet: String,
    function: String,
    ek: String,
    m: String,
    c: String,
    k: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct KemDecapsulationCase {
    tgId: u64,
    tcId: u64,
    testType: String,
    parameterSet: String,
    function: String,
    dk: String,
    c: String,
    k: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct DsaFixture {
    provenance: Provenance,
    group: DsaGroup,
    tests: Vec<DsaCase>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct DsaGroup {
    tgId: u64,
    testType: String,
    parameterSet: String,
    pk: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct DsaCase {
    tcId: u64,
    testPassed: bool,
    message: String,
    signature: String,
    reason: String,
}

fn decode_hex(input: &str) -> Vec<u8> {
    hex::decode(input).expect("fixture must contain valid hex")
}

#[test]
fn ml_kem_1024_acvp_encapsulation_tc51_matches_exact_ciphertext_and_shared_key() {
    use ml_kem::{
        ml_kem_1024::EncapsulationKey as MlKem1024EncapsulationKey,
        B32, Key,
    };

    let fixture: KemFixture =
        serde_json::from_str(include_str!("vectors/ml-kem-1024-acvp-subset.json"))
            .expect("ML-KEM fixture JSON");

    assert_eq!(fixture.provenance.standard, "FIPS 203");
    assert_eq!(fixture.provenance.algorithm, "ML-KEM-1024");
    assert_eq!(fixture.encapsulation.tgId, 3);
    assert_eq!(fixture.encapsulation.tcId, 51);
    assert_eq!(fixture.encapsulation.parameterSet, "ML-KEM-1024");
    assert_eq!(fixture.encapsulation.function, "encapsulation");

    let ek_bytes = decode_hex(&fixture.encapsulation.ek);
    let encoded_ek =
        Key::<MlKem1024EncapsulationKey>::try_from(ek_bytes.as_slice()).expect("encoded ML-KEM key");
    let ek = MlKem1024EncapsulationKey::new(&encoded_ek).expect("validated ML-KEM key");

    let m_bytes = decode_hex(&fixture.encapsulation.m);
    let m = B32::try_from(m_bytes.as_slice()).expect("32-byte deterministic message");
    let (ciphertext, shared_key) = ek.encapsulate_deterministic(&m);

    assert_eq!(
        hex::encode_upper(ciphertext.as_ref()),
        fixture.encapsulation.c
    );
    assert_eq!(
        hex::encode_upper(shared_key.as_ref()),
        fixture.encapsulation.k
    );

    // Keep decapsulation provenance in the same fixture even though the legacy
    // expanded secret key is not imported through the production-facing provider.
    assert_eq!(fixture.decapsulation.tgId, 6);
    assert_eq!(fixture.decapsulation.tcId, 96);
    assert_eq!(fixture.decapsulation.parameterSet, "ML-KEM-1024");
    assert!(!fixture.decapsulation.dk.is_empty());
    assert!(!fixture.decapsulation.c.is_empty());
    assert!(!fixture.decapsulation.k.is_empty());
}

#[test]
fn ml_dsa_87_acvp_valid_and_invalid_signature_cases_are_enforced() {
    let fixture: DsaFixture =
        serde_json::from_str(include_str!("vectors/ml-dsa-87-acvp-subset.json"))
            .expect("ML-DSA fixture JSON");

    assert_eq!(fixture.provenance.standard, "FIPS 204");
    assert_eq!(fixture.provenance.algorithm, "ML-DSA-87");
    assert_eq!(fixture.group.tgId, 3);
    assert_eq!(fixture.group.parameterSet, "ML-DSA-87");

    let public_key = decode_hex(&fixture.group.pk);
    let verifier = ReferencePqSignatureVerifier;

    let valid = fixture
        .tests
        .iter()
        .find(|case| case.tcId == 31)
        .expect("ACVP ML-DSA valid tcId=31");
    assert!(valid.testPassed);
    assert_eq!(valid.reason, "no modification");
    assert!(verifier.verify(
        AuthScheme::MlDsa87,
        &public_key,
        &decode_hex(&valid.message),
        &decode_hex(&valid.signature),
    ));

    let invalid = fixture
        .tests
        .iter()
        .find(|case| case.tcId == 39)
        .expect("ACVP ML-DSA invalid tcId=39");
    assert!(!invalid.testPassed);
    assert_eq!(invalid.reason, "modify signature");
    assert!(!verifier.verify(
        AuthScheme::MlDsa87,
        &public_key,
        &decode_hex(&invalid.message),
        &decode_hex(&invalid.signature),
    ));
}

#[test]
fn fixture_provenance_is_pinned_to_expected_upstream_blobs() {
    let kem: KemFixture =
        serde_json::from_str(include_str!("vectors/ml-kem-1024-acvp-subset.json")).unwrap();
    let dsa: DsaFixture =
        serde_json::from_str(include_str!("vectors/ml-dsa-87-acvp-subset.json")).unwrap();

    assert_eq!(
        kem.provenance.upstream_nist_acvp_commit,
        "65370b861b96efd30dfe0daae607bde26a78a5c8"
    );
    assert_eq!(
        kem.provenance.source_blob_sha,
        "7b93e2782989f4b6052a1056cb642a5272453ca5"
    );
    assert_eq!(kem.provenance.source_repository, "RustCrypto/KEMs");
    assert_eq!(kem.provenance.source_path, "ml-kem/tests/encap-decap.json");

    assert_eq!(
        dsa.provenance.upstream_nist_acvp_commit,
        "65370b861b96efd30dfe0daae607bde26a78a5c8"
    );
    assert_eq!(
        dsa.provenance.source_blob_sha,
        "f8af6142f52568dcb69f99039a771780a7f48e1d"
    );
    assert_eq!(dsa.provenance.source_repository, "RustCrypto/signatures");
    assert_eq!(dsa.provenance.source_path, "ml-dsa/tests/sig-ver.json");
}
