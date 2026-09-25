#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

cat simulation_data/all_simulation_data_json_csv.tar.xz.part{01..10} > all_simulation_data_json_csv.tar.xz
sha256sum -c SHA256SUMS --ignore-missing

mkdir -p restored/latest restored/history restored/original_inputs restored/test_results restored/simulation_data

tar -xzf latest_source_tests_docs.tar.gz -C restored/latest
tar -xJf historical_source_snapshots_v2_v3_v4_v5_v8.tar.xz -C restored/history
tar -xJf original_inputs_source_only.tar.xz -C restored/original_inputs
tar -xJf key_test_results.tar.xz -C restored/test_results
tar -xJf all_simulation_data_json_csv.tar.xz -C restored/simulation_data

echo "SYNERGY archive restored under archive/restored/"
