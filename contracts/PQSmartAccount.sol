// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {PQVerify} from "./IPQVerifier.sol";

/// @notice Native SYNERGY PQ-EVM account facade.
/// NEXUS AI is never an authorization oracle: only cryptographic signatures can execute calls.
contract PQSmartAccount {
    bytes public mlDsa87PublicKey;
    bytes public slhDsaPublicKey;
    bool public immutable requireDualPQ;
    uint256 public nonce;

    error Unauthorized();
    error CallFailed(bytes reason);

    event Executed(uint256 indexed nonce, address indexed target, uint256 value, bytes32 callHash);

    constructor(bytes memory mlDsa87PublicKey_, bytes memory slhDsaPublicKey_, bool requireDualPQ_) {
        require(mlDsa87PublicKey_.length > 0, "MLDSA_KEY_REQUIRED");
        if (requireDualPQ_) require(slhDsaPublicKey_.length > 0, "SLHDSA_KEY_REQUIRED");
        mlDsa87PublicKey = mlDsa87PublicKey_;
        slhDsaPublicKey = slhDsaPublicKey_;
        requireDualPQ = requireDualPQ_;
    }

    receive() external payable {}

    function authorizationHash(address target, uint256 value, bytes calldata data, uint256 txNonce)
        public view returns (bytes32)
    {
        return keccak256(
            abi.encode(
                "SYNERGY_PQ_ACCOUNT_V1",
                block.chainid,
                address(this),
                target,
                value,
                keccak256(data),
                txNonce
            )
        );
    }

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata mlDsaSignature,
        bytes calldata slhDsaSignature
    ) external returns (bytes memory result) {
        uint256 current = nonce;
        bytes32 digest = authorizationHash(target, value, data, current);
        if (!PQVerify.mlDsa87(mlDsa87PublicKey, digest, mlDsaSignature)) revert Unauthorized();
        if (requireDualPQ && !PQVerify.slhDsa256s(slhDsaPublicKey, digest, slhDsaSignature)) {
            revert Unauthorized();
        }

        nonce = current + 1;
        (bool ok, bytes memory out) = target.call{value: value}(data);
        if (!ok) revert CallFailed(out);
        emit Executed(current, target, value, keccak256(data));
        return out;
    }
}
