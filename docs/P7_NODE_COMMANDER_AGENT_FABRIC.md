# P7 — SYNERGY Node Commander + Agent Fabric

## Goal

P7 turns every physical SYNERGY node into an autonomous AI-compute host that can:

- expose local filesystem/process/system tools through MCP;
- run local AI agents under explicit capability policies;
- schedule tasks across a local swarm;
- delegate work to remote SYNERGY nodes over the P6 PQ-MESH;
- emit deterministic execution receipts that can later enter verification, settlement, slashing and SYNA reward flows.

The runtime remains off-consensus. Consensus only receives deterministic commitments and receipts.

## Architecture

```text
AI client / local NEXUS / external model
            |
            | MCP
            v
SYNERGY Node Commander
            |
            +-- filesystem tools
            +-- command execution
            +-- managed process sessions
            +-- system information
            +-- capability policy
            |
            v
SYNERGY Agent Fabric
            |
            +-- local scheduler
            +-- task leases
            +-- role/tool/resource matching
            +-- local-first placement
            |
            v
P6 PQ-MESH
            |
            v
remote SYNERGY nodes / agent swarms
            |
            v
AgentExecutionReceipt
            |
            v
verification / settlement / SYNA reward path
```

## P7.1 — Node Commander

Implemented in `node-runtime/crates/commander-core` and `node-runtime/crates/synergy-node`.

Current MCP tools:

- `read_file`
- `write_file`
- `list_directory`
- `run_command`
- `start_process`
- `read_process_output`
- `list_processes`
- `kill_process`
- `system_info`

The current default policy is intentionally restrictive:

- paths are constrained to one configured workspace root;
- absolute-path access is rejected;
- parent-directory traversal is rejected;
- command execution uses an explicit executable allowlist;
- write size is bounded;
- process inspection/termination applies only to processes created by the commander instance.

## P7.2 — Agent Fabric

Implemented in `node-runtime/crates/agent-fabric`.

The scheduler currently supports:

- agent registration;
- role matching;
- tool-capability matching;
- CPU and memory requirement matching;
- local-first placement;
- optional remote-agent eligibility;
- one active task lease per task;
- deterministic lease commitments.

## P7.3 — Declarative swarm configuration

Example: `examples/swarm/coding-swarm.yaml`.

The intended resource model is:

- `Workspace`
- `Model`
- `ToolPolicy`
- `Agent`
- `Swarm`
- `Task`

This follows the useful declarative separation of modern agent orchestrators without making SYNERGY dependent on Kubernetes or an external control plane.

## P7.4 — Blockchain receipt boundary

Implemented in `src/agent_execution.rs`.

`AgentTaskCommitment` binds:

- task id;
- parent task;
- workspace root;
- tool-policy root;
- model root;
- input root;
- CPU limit;
- memory limit;
- expiry epoch.

`AgentExecutionReceipt` binds:

- exact task root;
- worker node identity;
- agent identity;
- result root;
- execution trace root;
- resource usage;
- execution epochs;
- monotonic sequence.

Validation fails closed on:

- task-root substitution;
- zero worker/agent identity;
- empty result/trace;
- invalid time ordering;
- expiry;
- resource-limit violation;
- zero sequence.

This receipt is not itself proof that the work was correct. It is the deterministic object that later verifier receipts must attest to.

## P7.5 — MCP plugin mode

Current launch mode:

```bash
synergy-node mcp --stdio
```

Set the workspace boundary using:

```bash
SYNERGY_WORKSPACE=/absolute/path/to/workspace
```

Example client configuration is in:

`plugin/mcp.json.example`

## Security boundary

Node Commander and Agent Fabric are off-chain execution software.

They must never be invoked from deterministic consensus execution. They may use filesystem, processes, network, clocks and external model APIs only in the node-runtime layer.

Consensus consumes only canonical commitments, authenticated receipts and deterministic validation logic.

Remote command execution must not be exposed directly to arbitrary Internet clients. The production remote path must be authenticated and authorized through the SYNERGY node identity / PQ-MESH capability layer.

## Milestone gates

### P7.1 Local Commander
- [x] workspace-confined filesystem operations
- [x] allowlisted command execution
- [x] long-lived process sessions
- [x] MCP stdio surface
- [x] physical stdio smoke

### P7.2 Local Agent Fabric
- [x] role/tool/resource-aware scheduler
- [x] local-first scheduling
- [x] one-shot task lease
- [x] deterministic lease root

### P7.3 Receipt plane
- [x] deterministic task commitment
- [x] deterministic execution receipt
- [x] resource/expiry validation
- [ ] replay-state consumption
- [ ] PQ authorization envelope
- [ ] verifier aggregation binding
- [ ] SYNA reward integration

### P7.4 Distributed swarm
- [ ] remote agent advertisement over PQ-MESH
- [ ] encrypted task delegation
- [ ] remote lease acceptance
- [ ] result return over PQ-MESH
- [ ] worker failover / lease expiry

### P7.5 Sandbox hardening
- [ ] Windows Job Object sandbox
- [ ] Linux namespaces/cgroups/seccomp
- [ ] per-task filesystem mounts
- [ ] network capability isolation
- [ ] CPU/RAM/GPU/time quotas
- [ ] secrets isolation

### P7.6 Production MCP gateway
- [ ] authenticated HTTP transport
- [ ] PQ-MESH transport
- [ ] node-scoped capability tokens
- [ ] human approval policy for dangerous tools
- [ ] audit log / execution trace root

### P7.7 Physical distributed evidence
- [ ] 3 independent devices
- [ ] 10+ agents
- [ ] local + remote scheduling
- [ ] intentional worker failure
- [ ] reassignment/failover
- [ ] independent verification
- [ ] finalized execution receipt
- [ ] reward-path integration
