// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {PQVerify} from "./IPQVerifier.sol";

/// @notice Native SYNERGY PQ-EVM account facade.
/// NEXUS AI is never an authorization oracle: only mandatory dual-PQ signatures can execute calls.
contract PQSmartAccount {
    uint16 public constant CRYPTO_PROFILE_VERSION = 1;
    uint8 public constant AUTH_DOMAIN_TRANSACTION = 1;
    uint8 public constant AUTH_POLICY_PQ_ONLY = 3;

    bytes public mlDsa87PublicKey;
    bytes public slhDsaPublicKey;
    uint256 public nonce;

    error InvalidKeyMaterial();
    error InvalidSignatureEncoding();
    error Unauthorized();
    error CallFailed(bytes reason);

    event Executed(uint256 indexed nonce, address indexed target, uint256 value, bytes32 callHash);

    constructor(bytes memory mlDsa87PublicKey_, bytes memory slhDsaPublicKey_) {
        if (
            mlDsa87PublicKey_.length != 2592
                || slhDsaPublicKey_.length != 64
        ) {
            revert InvalidKeyMaterial();
        }
        mlDsa87PublicKey = mlDsa87PublicKey_;
        slhDsaPublicKey = slhDsaPublicKey_;
    }

    receive() external payable {}

    function authorizationMessage(address target, uint256 value, bytes calldata data, uint256 txNonce)
        public view returns (bytes memory)
    {
        return abi.encode(
            "SYNERGY/PQ-SMART-ACCOUNT/V2",
            CRYPTO_PROFILE_VERSION,
            block.chainid,
            address(this),
            AUTH_DOMAIN_TRANSACTION,
            AUTH_POLICY_PQ_ONLY,
            target,
            value,
            keccak256(data),
            txNonce
        );
    }

    function fipsContext() public view returns (bytes memory) {
        return abi.encodePacked(
            "SYNERGY/PQ-FIPS-CONTEXT",
            bytes1(0),
            bytes2(CRYPTO_PROFILE_VERSION),
            bytes32(block.chainid),
            bytes1(AUTH_DOMAIN_TRANSACTION),
            bytes1(AUTH_POLICY_PQ_ONLY),
            bytes1(uint8(2)),
            bytes1(uint8(3)),
            bytes1(uint8(4))
        );
    }

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata mlDsaSignature,
        bytes calldata slhDsaSignature
    ) external returns (bytes memory result) {
        if (mlDsaSignature.length != 4627 || slhDsaSignature.length != 29792) {
            revert InvalidSignatureEncoding();
        }

        uint256 current = nonce;
        bytes memory message = authorizationMessage(target, value, data, current);
        bytes memory context = fipsContext();

        if (!PQVerify.mlDsa87(mlDsa87PublicKey, message, context, mlDsaSignature)) {
            revert Unauthorized();
        }
        if (!PQVerify.slhDsa256s(slhDsaPublicKey, message, context, slhDsaSignature)) {
            revert Unauthorized();
        }

        nonce = current + 1;
        (bool ok, bytes memory out) = target.call{value: value}(data);
        if (!ok) revert CallFailed(out);

        emit Executed(current, target, value, keccak256(data));
        return out;
    }
}
