// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Deterministic consensus NEXUS precompile interface for SYNERGY PQ-EVM.
/// Profile v1 exposes only the implemented Score kernel.
/// Inputs/outputs are signed Q16.16 integers; floating point and external network calls are forbidden.
interface INexusAI {
    function inferScore(
        bytes32 modelRoot,
        int64[] calldata inputQ16,
        uint16 maxOutputs
    ) external view returns (int64[] memory outputQ16);
}

library NexusPrecompile {
    address internal constant NEXUS = address(0x0910);

    function inferScore(
        bytes32 modelRoot,
        int64[] memory inputQ16,
        uint16 maxOutputs
    ) internal view returns (int64[] memory outputQ16) {
        (bool ok, bytes memory out) = NEXUS.staticcall(
            abi.encode(modelRoot, uint8(0), inputQ16, maxOutputs)
        );
        require(ok, "NEXUS_PRECOMPILE_FAILED");
        outputQ16 = abi.decode(out, (int64[]));
    }
}
