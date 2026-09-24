# NEXUS V16 canonical MVP import

This directory freezes the distributed model manifest imported from `Shtenco/synergy_agi_olga@nexus-v16-distributed-weight-fusion` for the MVP integration line.

The manifest is evidence of the prior five-shard model lineage. The model bytes themselves are not duplicated here. `scripts/mvp_verify_nexus_v16_manifest.py` derives a deterministic ordered-shard root for binding into the current Rust `ModelManifestCommitment`/provider-discovery plane.
