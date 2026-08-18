// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Consensus-native verifier surface exposed by SYNERGY PQ-EVM.
/// These addresses are chain-local reserved precompiles, not assumptions about Ethereum mainnet.
library PQPrecompiles {
    address internal constant ML_DSA_87 = address(0x0900);
    address internal constant SLH_DSA_SHAKE_256S = address(0x0901);
}

library PQVerify {
    error PrecompileFailure();

    function mlDsa87(bytes memory publicKey, bytes32 messageHash, bytes memory signature)
        internal view returns (bool)
    {
        return _verify(PQPrecompiles.ML_DSA_87, publicKey, messageHash, signature);
    }

    function slhDsa256s(bytes memory publicKey, bytes32 messageHash, bytes memory signature)
        internal view returns (bool)
    {
        return _verify(PQPrecompiles.SLH_DSA_SHAKE_256S, publicKey, messageHash, signature);
    }

    function _verify(address precompile, bytes memory publicKey, bytes32 messageHash, bytes memory signature)
        private view returns (bool)
    {
        (bool ok, bytes memory out) = precompile.staticcall(abi.encode(publicKey, messageHash, signature));
        if (!ok || out.length != 32) revert PrecompileFailure();
        return abi.decode(out, (bool));
    }
}
