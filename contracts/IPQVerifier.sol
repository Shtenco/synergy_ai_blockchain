// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Consensus-native verifier surface exposed by SYNERGY PQ-EVM.
/// These addresses are chain-local reserved precompiles, not assumptions about Ethereum mainnet.
library PQPrecompiles {
    address internal constant ML_DSA_87 = address(0x0900);
    address internal constant SLH_DSA_SHAKE_256S = address(0x0901);
}

library PQVerify {
    uint256 internal constant ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
    uint256 internal constant ML_DSA_87_SIGNATURE_BYTES = 4627;
    uint256 internal constant SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES = 64;
    uint256 internal constant SLH_DSA_SHAKE_256S_SIGNATURE_BYTES = 29792;
    uint256 internal constant MAX_FIPS_CONTEXT_BYTES = 255;

    error PrecompileFailure();

    function mlDsa87(
        bytes memory publicKey,
        bytes memory message,
        bytes memory context,
        bytes memory signature
    ) internal view returns (bool) {
        if (
            publicKey.length != ML_DSA_87_PUBLIC_KEY_BYTES
                || signature.length != ML_DSA_87_SIGNATURE_BYTES
                || context.length > MAX_FIPS_CONTEXT_BYTES
        ) {
            return false;
        }
        return _verify(PQPrecompiles.ML_DSA_87, publicKey, message, context, signature);
    }

    function slhDsa256s(
        bytes memory publicKey,
        bytes memory message,
        bytes memory context,
        bytes memory signature
    ) internal view returns (bool) {
        if (
            publicKey.length != SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES
                || signature.length != SLH_DSA_SHAKE_256S_SIGNATURE_BYTES
                || context.length > MAX_FIPS_CONTEXT_BYTES
        ) {
            return false;
        }
        return _verify(PQPrecompiles.SLH_DSA_SHAKE_256S, publicKey, message, context, signature);
    }

    function _verify(
        address precompile,
        bytes memory publicKey,
        bytes memory message,
        bytes memory context,
        bytes memory signature
    ) private view returns (bool) {
        (bool ok, bytes memory out) =
            precompile.staticcall(abi.encode(publicKey, message, context, signature));
        if (!ok || out.length != 32) revert PrecompileFailure();
        return abi.decode(out, (bool));
    }
}
