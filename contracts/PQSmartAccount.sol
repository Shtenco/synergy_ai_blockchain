// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {PQVerify} from "./IPQVerifier.sol";

/// @notice Native SYNERGY PQ-EVM account facade.
/// NEXUS AI is never an authorization oracle: only mandatory dual-PQ signatures can execute calls.
contract PQSmartAccount {
    uint16 public constant CRYPTO_PROFILE_VERSION = 1;
    uint8 public constant AUTH_DOMAIN_TRANSACTION = 1;
    uint8 public constant AUTH_POLICY_PQ_ONLY = 3;
    uint64 public constant AUTHORIZATION_EPOCH = 1;
    uint256 public constant MAX_AUTHORIZATION_LIFETIME_SECONDS = 86_400;

    bytes public mlDsa87PublicKey;
    bytes public slhDsaPublicKey;
    uint64 public nonce;
    bool private executing;

    error InvalidKeyMaterial();
    error InvalidSignatureEncoding();
    error Unauthorized();
    error ReentrantExecution();

    event Executed(
        uint256 indexed nonce,
        address indexed target,
        uint256 value,
        bytes32 callHash,
        bool success,
        bytes32 returnDataHash
    );

    constructor(bytes memory mlDsa87PublicKey_, bytes memory slhDsaPublicKey_) {
        if (
            mlDsa87PublicKey_.length != 2592
                || slhDsaPublicKey_.length != 64
                || !_hasNonZeroByte(mlDsa87PublicKey_)
                || !_hasNonZeroByte(slhDsaPublicKey_)
        ) {
            revert InvalidKeyMaterial();
        }
        mlDsa87PublicKey = mlDsa87PublicKey_;
        slhDsaPublicKey = slhDsaPublicKey_;
    }

    function _hasNonZeroByte(bytes memory value) private pure returns (bool) {
        for (uint256 i = 0; i < value.length; ++i) {
            if (value[i] != 0) return true;
        }
        return false;
    }

    receive() external payable {}

    function callPayloadCommitment(
        address target,
        uint256 value,
        bytes calldata data
    ) public view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                "SYNERGY/PQ-SMART-ACCOUNT-CALL/V1",
                bytes1(0),
                bytes32(block.chainid),
                address(this),
                target,
                bytes32(value),
                keccak256(data)
            )
        );
    }

    function authorizationMessage(
        address target,
        uint256 value,
        bytes calldata data,
        uint64 txNonce,
        uint64 validUntil
    ) public view returns (bytes memory) {
        bytes32 payloadCommitment = callPayloadCommitment(target, value, data);
        return abi.encodePacked(
            "SYNERGY/PQ-AUTH",
            bytes1(0),
            bytes2(CRYPTO_PROFILE_VERSION),
            bytes32(block.chainid),
            bytes1(AUTH_DOMAIN_TRANSACTION),
            bytes1(AUTH_POLICY_PQ_ONLY),
            bytes1(uint8(2)),
            bytes1(uint8(3)),
            bytes1(uint8(4)),
            bytes8(AUTHORIZATION_EPOCH),
            bytes8(txNonce),
            bytes8(validUntil),
            payloadCommitment
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
        uint64 validUntil,
        bytes calldata mlDsaSignature,
        bytes calldata slhDsaSignature
    ) external returns (bool success, bytes memory result) {
        if (executing) revert ReentrantExecution();
        if (mlDsaSignature.length != 4627 || slhDsaSignature.length != 29792) {
            revert InvalidSignatureEncoding();
        }
        if (
            block.timestamp >= uint256(validUntil)
                || uint256(validUntil) - block.timestamp > MAX_AUTHORIZATION_LIFETIME_SECONDS
        ) {
            revert Unauthorized();
        }

        uint64 current = nonce;
        if (current == type(uint64).max) revert Unauthorized();
        bytes memory message = authorizationMessage(target, value, data, current, validUntil);
        bytes memory context = fipsContext();

        if (!PQVerify.mlDsa87(mlDsa87PublicKey, message, context, mlDsaSignature)) {
            revert Unauthorized();
        }
        if (!PQVerify.slhDsa256s(slhDsaPublicKey, message, context, slhDsaSignature)) {
            revert Unauthorized();
        }

        // Authorization nonce is consumed before the downstream call. A target
        // failure is an execution outcome, not a reason to resurrect an already
        // authorized signed operation.
        nonce = current + 1;
        executing = true;
        (success, result) = target.call{value: value}(data);
        executing = false;

        emit Executed(
            current,
            target,
            value,
            keccak256(data),
            success,
            keccak256(result)
        );
        return (success, result);
    }
}
