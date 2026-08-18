// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Deterministic consensus NEXUS precompile interface for SYNERGY PQ-EVM.
/// Inputs/outputs are signed Q16.16 integers; floating point and external network calls are forbidden.
interface INexusAI {
    enum Mode { Score, Policy, ProofAssist }

    function infer(
        bytes32 modelRoot,
        Mode mode,
        int64[] calldata inputQ16,
        uint16 maxOutputs
    ) external view returns (int64[] memory outputQ16);
}

library NexusPrecompile {
    address internal constant NEXUS = address(0x0910);

    function infer(
        bytes32 modelRoot,
        INexusAI.Mode mode,
        int64[] memory inputQ16,
        uint16 maxOutputs
    ) internal view returns (int64[] memory outputQ16) {
        (bool ok, bytes memory out) = NEXUS.staticcall(
            abi.encode(modelRoot, mode, inputQ16, maxOutputs)
        );
        require(ok, "NEXUS_PRECOMPILE_FAILED");
        outputQ16 = abi.decode(out, (int64[]));
    }
}
