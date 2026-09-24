#![cfg(feature = "reference-pq")]

use serde::Deserialize;

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
#[allow(dead_code, non_snake_case)]
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
#[allow(dead_code, non_snake_case)]
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
#[allow(dead_code, non_snake_case)]
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

#[derive(Debug, Deserialize)]
struct SlhFixture {
    provenance: SlhProvenance,
    group: SlhGroup,
    tests: Vec<SlhCase>,
}

#[derive(Debug, Deserialize)]
struct SlhProvenance {
    standard: String,
    algorithm: String,
    source_repository: String,
    source_commit: String,
    source_prompt_path: String,
    source_prompt_blob_sha: String,
    source_expected_results_path: String,
    source_expected_results_blob_sha: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct SlhGroup {
    tgId: u64,
    testType: String,
    parameterSet: String,
    signatureInterface: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct SlhCase {
    tcId: u64,
    testPassed: bool,
    pk: String,
    message: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct WycheproofKemFixture {
    provenance: WycheproofProvenance,
    tests: Vec<WycheproofKemCase>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct WycheproofProvenance {
    suite: String,
    algorithm: String,
    parameterSet: String,
    source_repository: String,
    source_commit: String,
    source_path: String,
    source_blob_sha: String,
    source_schema: String,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct WycheproofKemCase {
    tcId: u64,
    comment: String,
    c: String,
    result: String,
    flags: Vec<String>,
}

fn decode_hex(input: &str) -> Vec<u8> {
    hex::decode(input).expect("fixture must contain valid hex")
}

#[test]
fn ml_kem_1024_acvp_encapsulation_tc51_matches_exact_ciphertext_and_shared_key() {
    use ml_kem::{ml_kem_1024::EncapsulationKey as MlKem1024EncapsulationKey, Key, B32};

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
    let encoded_ek = Key::<MlKem1024EncapsulationKey>::try_from(ek_bytes.as_slice())
        .expect("encoded ML-KEM key");
    let ek = MlKem1024EncapsulationKey::new(&encoded_ek).expect("validated ML-KEM key");

    let m_bytes = decode_hex(&fixture.encapsulation.m);
    let m = B32::try_from(m_bytes.as_slice()).expect("32-byte deterministic message");
    let (ciphertext, shared_key) = ek.encapsulate_deterministic(&m);

    assert_eq!(
        hex::encode_upper(ciphertext.as_slice()),
        fixture.encapsulation.c
    );
    assert_eq!(
        hex::encode_upper(shared_key.as_slice()),
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

    use ml_dsa::{MlDsa87, Signature, VerifyingKey};

    let public_key = decode_hex(&fixture.group.pk);
    let encoded_key = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key.as_slice())
        .expect("encoded ML-DSA-87 public key");
    let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_key);

    let valid = fixture
        .tests
        .iter()
        .find(|case| case.tcId == 31)
        .expect("ACVP ML-DSA valid tcId=31");
    assert!(valid.testPassed);
    assert_eq!(valid.reason, "no modification");
    let valid_signature = Signature::<MlDsa87>::try_from(decode_hex(&valid.signature).as_slice())
        .expect("encoded ML-DSA-87 signature");
    assert_eq!(
        verifying_key.verify_internal(&decode_hex(&valid.message), &valid_signature),
        valid.testPassed,
    );

    let invalid = fixture
        .tests
        .iter()
        .find(|case| case.tcId == 39)
        .expect("ACVP ML-DSA invalid tcId=39");
    assert!(!invalid.testPassed);
    assert_eq!(invalid.reason, "modify signature");
    let invalid_signature =
        Signature::<MlDsa87>::try_from(decode_hex(&invalid.signature).as_slice())
            .expect("encoded invalid ML-DSA-87 signature");
    assert_eq!(
        verifying_key.verify_internal(&decode_hex(&invalid.message), &invalid_signature),
        invalid.testPassed,
    );
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

#[test]
fn slh_dsa_shake_256s_fips205_acvp_valid_and_invalid_cases_are_enforced() {
    let fixture: SlhFixture =
        serde_json::from_str(include_str!("vectors/slh-dsa-shake-256s-acvp-subset.json"))
            .expect("SLH-DSA FIPS 205 ACVP fixture JSON");

    assert_eq!(fixture.provenance.standard, "FIPS 205");
    assert_eq!(fixture.provenance.algorithm, "SLH-DSA-SHAKE-256s");
    assert_eq!(
        fixture.provenance.source_repository,
        "usnistgov/ACVP-Server"
    );
    assert_eq!(
        fixture.provenance.source_commit,
        "975de31eb83d87039ec88934fdc47d8c312b892d"
    );
    assert_eq!(
        fixture.provenance.source_prompt_blob_sha,
        "85134f8b1fc3c6cd51378f6cf9e451efc7728e59"
    );
    assert_eq!(
        fixture.provenance.source_expected_results_blob_sha,
        "a04d2c683ba2a2cba2028e0922b137d30166a9cd"
    );
    assert_eq!(
        fixture.provenance.source_prompt_path,
        "gen-val/json-files/SLH-DSA-sigVer-FIPS205/prompt.json"
    );
    assert_eq!(
        fixture.provenance.source_expected_results_path,
        "gen-val/json-files/SLH-DSA-sigVer-FIPS205/expectedResults.json"
    );
    assert_eq!(fixture.group.tgId, 36);
    assert_eq!(fixture.group.testType, "AFT");
    assert_eq!(fixture.group.parameterSet, "SLH-DSA-SHAKE-256s");
    assert_eq!(fixture.group.signatureInterface, "internal");

    use slh_dsa::{Shake256s, Signature, VerifyingKey};

    let valid = fixture
        .tests
        .iter()
        .find(|case| case.tcId == 491)
        .expect("FIPS 205 valid tcId=491");
    assert!(valid.testPassed);
    let valid_key = VerifyingKey::<Shake256s>::try_from(decode_hex(&valid.pk).as_slice())
        .expect("encoded SLH-DSA-SHAKE-256s public key");
    let valid_signature = Signature::<Shake256s>::try_from(decode_hex(&valid.signature).as_slice())
        .expect("encoded SLH-DSA-SHAKE-256s signature");
    assert_eq!(
        valid_key
            .slh_verify_internal(&decode_hex(&valid.message), &valid_signature)
            .is_ok(),
        valid.testPassed,
    );

    let invalid = fixture
        .tests
        .iter()
        .find(|case| case.tcId == 492)
        .expect("FIPS 205 invalid tcId=492");
    assert!(!invalid.testPassed);
    let invalid_key = VerifyingKey::<Shake256s>::try_from(decode_hex(&invalid.pk).as_slice())
        .expect("encoded invalid-case SLH-DSA-SHAKE-256s public key");
    let invalid_signature =
        Signature::<Shake256s>::try_from(decode_hex(&invalid.signature).as_slice())
            .expect("encoded invalid-case SLH-DSA-SHAKE-256s signature");
    assert_eq!(
        invalid_key
            .slh_verify_internal(&decode_hex(&invalid.message), &invalid_signature)
            .is_ok(),
        invalid.testPassed,
    );
}

#[test]
fn ml_kem_1024_wycheproof_rejects_incorrect_ciphertext_lengths() {
    use synergy_pq_evm_core::network::MlKem1024Provider;
    use synergy_pq_evm_core::ReferenceMlKem1024Provider;

    let fixture: WycheproofKemFixture = serde_json::from_str(include_str!(
        "vectors/ml-kem-1024-wycheproof-negative-subset.json"
    ))
    .expect("ML-KEM Wycheproof fixture JSON");

    assert_eq!(fixture.provenance.suite, "Wycheproof");
    assert_eq!(fixture.provenance.algorithm, "ML-KEM");
    assert_eq!(fixture.provenance.parameterSet, "ML-KEM-1024");
    assert_eq!(fixture.provenance.source_repository, "C2SP/wycheproof");
    assert_eq!(
        fixture.provenance.source_commit,
        "3fa63dd0344abb611f1fb1d77e119938603ea230"
    );
    assert_eq!(
        fixture.provenance.source_path,
        "testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json"
    );
    assert_eq!(
        fixture.provenance.source_blob_sha,
        "d67b741ff0e0357964a045c8faa41b067bea4b49"
    );
    assert_eq!(
        fixture.provenance.source_schema,
        "mlkem_semi_expanded_decaps_test_schema.json"
    );

    let mut provider = ReferenceMlKem1024Provider::new();
    let (handle, _public_key) = provider
        .try_generate_keypair()
        .expect("ML-KEM key generation");

    assert_eq!(fixture.tests.len(), 2);
    for case in &fixture.tests {
        assert_eq!(case.result, "invalid");
        assert!(case
            .flags
            .iter()
            .any(|flag| flag == "IncorrectCiphertextLength"));
        assert!(case.comment.contains("Ciphertext"));
        assert!(matches!(case.tcId, 2 | 3));
        assert!(
            provider
                .decapsulate(&handle, &decode_hex(&case.c))
                .is_none(),
            "Wycheproof tcId={} must fail closed before ML-KEM decapsulation",
            case.tcId
        );
    }
}
