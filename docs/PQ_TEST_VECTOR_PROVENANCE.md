# Post-Quantum Test Vector Provenance

Date: 2026-09-22

This file records where external known-answer / validation vectors for M2 must come from. It is intentionally separate from implementation code so reviewers can verify provenance independently.

## ML-KEM-1024 — FIPS 203

Canonical validation source:

- NIST ACVP Server
- algorithm family: `ML-KEM-keyGen-FIPS203`
- algorithm family: `ML-KEM-encapDecap-FIPS203`
- pinned NIST ACVP commit used by the selected RustCrypto ML-KEM test suite:
  `65370b861b96efd30dfe0daae607bde26a78a5c8`

Upstream RustCrypto provenance file:

- repository: `RustCrypto/KEMs`
- path: `ml-kem/tests/README.md`

Required SYNERGY subset:

- parameter set: ML-KEM-1024 only;
- at least one deterministic key-generation vector;
- at least one encapsulation/decapsulation vector;
- malformed public-key rejection coverage;
- malformed/corrupted ciphertext implicit-rejection coverage;
- Wycheproof negative-vector subset where applicable.

No vector may be silently regenerated and described as a NIST vector. Imported fixtures must preserve source group/test identifiers.

## ML-DSA-87 — FIPS 204

Canonical validation source:

- NIST ACVP Server
- algorithm families:
  - `ML-DSA-keyGen-FIPS204`
  - `ML-DSA-sigGen-FIPS204`
  - `ML-DSA-sigVer-FIPS204`
- pinned NIST ACVP commit used by the selected RustCrypto ML-DSA test suite:
  `65370b861b96efd30dfe0daae607bde26a78a5c8`

Upstream RustCrypto provenance file:

- repository: `RustCrypto/signatures`
- path: `ml-dsa/tests/README.md`

Required SYNERGY subset:

- parameter set: ML-DSA-87 only;
- deterministic key-generation vector;
- signature-generation vector;
- signature-verification valid vector;
- signature-verification invalid vector;
- changed-message rejection;
- context/domain-separation coverage.

## SLH-DSA-SHAKE-256s — FIPS 205

Two evidence lanes are tracked separately:

1. NIST ACVP/standards validation vectors for the production M2 gate.
2. Historical SPHINCS+ known-answer lineage used by RustCrypto for implementation cross-checking.

RustCrypto KAT provenance currently documents:

- source repository: `sphincs/sphincsplus`
- source branch: `consistent_basew`
- source commit: `eccdc43a99e194f52d5ef0e4030ef4dd1e31828b`
- selected parameter set: `SHAKE-256s`
- upstream 10-iteration aggregate SHA-256:
  `7c8f16c7b9645df58518b1c0aa7a26f7a2e1b9ee860819f25305cf97aecce1f3`

That aggregate hash is provenance evidence for the upstream test corpus. It is not, by itself, a substitute for importing traceable FIPS-205/ACVP cases into SYNERGY.

### Imported executable FIPS 205 subset

The branch now commits `tests/vectors/slh-dsa-shake-256s-acvp-subset.json` and wires it into `tests/pq_acvp.rs`.

Pinned source:

- repository: `usnistgov/ACVP-Server`;
- commit: `975de31eb83d87039ec88934fdc47d8c312b892d`;
- prompt: `gen-val/json-files/SLH-DSA-sigVer-FIPS205/prompt.json`;
- prompt blob: `85134f8b1fc3c6cd51378f6cf9e451efc7728e59`;
- expected results: `gen-val/json-files/SLH-DSA-sigVer-FIPS205/expectedResults.json`;
- expected-results blob: `a04d2c683ba2a2cba2028e0922b137d30166a9cd`;
- parameter set: `SLH-DSA-SHAKE-256s`;
- group: `tgId=36`;
- valid case: `tcId=491`;
- invalid case: `tcId=492`.

The integration test parses the committed public key, message and signature and requires the reference FIPS-205 verifier to accept tcId 491 and reject tcId 492. This is executable test code, but it is not represented as passing until a Rust runner actually executes it.

## Wycheproof ML-KEM-1024 negative subset

The branch now commits `tests/vectors/ml-kem-1024-wycheproof-negative-subset.json`.

Pinned source:

- repository: `C2SP/wycheproof`;
- commit: `3fa63dd0344abb611f1fb1d77e119938603ea230`;
- source path: `testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json`;
- source blob: `d67b741ff0e0357964a045c8faa41b067bea4b49`;
- schema: `mlkem_semi_expanded_decaps_test_schema.json`;
- `tcId=2`: 1567-byte ciphertext, invalid, `IncorrectCiphertextLength`;
- `tcId=3`: 1569-byte ciphertext, invalid, `IncorrectCiphertextLength`.

These two cases intentionally exercise the protocol-facing provider boundary with a locally generated opaque secret handle. Because ciphertext length is invalid, the provider must return `None` before cryptographic decapsulation. This is a structural fail-closed Wycheproof gate, not a full imported raw-secret-key decapsulation KAT.

## Import policy

Every committed external fixture must carry:

- standard / algorithm;
- exact parameter set;
- upstream repository;
- upstream commit SHA;
- source file/path;
- source test-group/test-case identifier where available;
- whether expected result is valid or invalid;
- local SHA-256 of the fixture file.

Large upstream corpora should not be copied wholesale. M2 should commit a small representative subset and retain reproducible provenance to the complete upstream corpus.

## Reproducibility gate

M2 can become GREEN only when CI can execute:

```text
cargo test --all-targets
cargo test --all-targets --features reference-pq
```

and the external-vector subset is executed as part of the latter command.

As of branch head after commits `35fab7cada339e229a8326eb50e2fe6f87201e6e` and `fb3b3e86fa281f542be0d79fe6a7ae9437821c31`, the external subsets are committed and connected to executable Rust tests. Their **execution result remains pending** because GitHub Actions run `35764263197` failed before any step was scheduled (`steps=[]`) and the available local container has no `cargo`/`rustc`.
