# NEXUS V18 consensus export manifest

Source repository: `Shtenco/agi_olga`

Source report: `NEXUS_V18_UNIFIED_REPORT.md`

Reported source checkpoint SHA-256:

`74433965c8193b6f75b42c197a4394bb14e37f2ef0ea0c7eb8b826e46c65c4e4`

Reported freeze SHA-256:

`a3532b47e71db2545f7daa4123c7db355272f9bac8d7225de0c2494ea8b41d33`

Reported architecture:

- ARC graph ranker: 339,642 parameters;
- Russian small-world reasoner: 139,790 parameters;
- small-world dynamics: 131,825 parameters;
- total: 611,257 parameters;
- ring-plus-shortcuts small-world graph;
- gated residual mixture of `x`, `P x`, `P^2 x`, `P^4 x`.

## Consensus export status

`NOT_ACTIVATABLE_YET`

Required before chain activation:

1. recover the exact verified V18 weights from the project archive;
2. write a deterministic exporter to signed fixed-point integers;
3. freeze tensor ordering, scales, saturation and rounding rules;
4. generate the binary model artifact;
5. compute its model root;
6. generate at least 10,000 canonical inference vectors;
7. reproduce every vector bit-for-bit in two independent implementations;
8. benchmark and freeze gas schedule;
9. schedule activation block through chain governance.

The source checkpoint hash is provenance only. Consensus uses the future quantized artifact root.
