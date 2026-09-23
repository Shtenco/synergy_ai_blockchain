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
    uint256 public constant MAX_TX_CALLDATA_BYTES = 1_048_576;
    uint256 public constant MAX_RETURN_DATA_BYTES = 4_096;
    uint256 public constant POST_CALL_GAS_RESERVE = 250_000;

    bytes public mlDsa87PublicKey;
    bytes public slhDsaPublicKey;
    uint64 public nonce;
    bool private executing;

    error InvalidKeyMaterial();
    error InvalidSignatureEncoding();
    error Unauthorized();
    error ReentrantExecution();
    error InvalidExecutionBounds();
    error InsufficientExecutionGas();

    event Executed(
        uint256 indexed nonce,
        address indexed target,
        uint256 value,
        bytes32 callHash,
        bool success,
        bytes32 boundedReturnDataHash,
        bool returnDataTruncated
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
        bytes calldata data,
        uint64 callGasLimit
    ) public view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                "SYNERGY/PQ-SMART-ACCOUNT-CALL/V1",
                bytes1(0),
                bytes32(block.chainid),
                address(this),
                target,
                bytes32(value),
                keccak256(data),
                callGasLimit
            )
        );
    }

    function authorizationEnvelopeMessage(
        bytes32 payloadCommitment,
        uint64 txNonce,
        uint64 validUntil
    ) public view returns (bytes memory) {
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
            AUTHORIZATION_EPOCH,
            txNonce,
            validUntil,
            payloadCommitment
        );
    }

    function authorizationMessage(
        address target,
        uint256 value,
        bytes calldata data,
        uint64 callGasLimit,
        uint64 txNonce,
        uint64 validUntil
    ) public view returns (bytes memory) {
        return authorizationEnvelopeMessage(
            callPayloadCommitment(target, value, data, callGasLimit),
            txNonce,
            validUntil
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

    function _boundedCall(
        address target,
        uint256 value,
        bytes memory callData,
        uint64 callGasLimit
    ) private returns (bool success, bytes memory result, bool truncated) {
        uint256 maxReturnData = MAX_RETURN_DATA_BYTES;
        uint256 fullReturnDataSize;

        assembly {
            success := call(
                callGasLimit,
                target,
                value,
                add(callData, 0x20),
                mload(callData),
                0,
                0
            )

            fullReturnDataSize := returndatasize()
            let copySize := fullReturnDataSize
            if gt(copySize, maxReturnData) {
                copySize := maxReturnData
            }

            result := mload(0x40)
            mstore(result, copySize)
            let resultData := add(result, 0x20)
            returndatacopy(resultData, 0, copySize)
            mstore(
                0x40,
                and(add(add(resultData, copySize), 31), not(31))
            )
        }

        truncated = fullReturnDataSize > maxReturnData;
    }

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint64 callGasLimit,
        uint64 validUntil,
        bytes calldata mlDsaSignature,
        bytes calldata slhDsaSignature
    ) external returns (bool success, bytes memory result) {
        if (executing) revert ReentrantExecution();
        if (mlDsaSignature.length != 4627 || slhDsaSignature.length != 29792) {
            revert InvalidSignatureEncoding();
        }
        if (data.length > MAX_TX_CALLDATA_BYTES || callGasLimit == 0) {
            revert InvalidExecutionBounds();
        }
        if (
            block.timestamp >= uint256(validUntil)
                || uint256(validUntil) - block.timestamp > MAX_AUTHORIZATION_LIFETIME_SECONDS
        ) {
            revert Unauthorized();
        }

        uint64 current = nonce;
        if (current == type(uint64).max) revert Unauthorized();
        bytes32 callHash = keccak256(data);
        bytes memory message =
            authorizationMessage(target, value, data, callGasLimit, current, validUntil);
        bytes memory context = fipsContext();

        if (!PQVerify.mlDsa87(mlDsa87PublicKey, message, context, mlDsaSignature)) {
            revert Unauthorized();
        }
        if (!PQVerify.slhDsa256s(slhDsaPublicKey, message, context, slhDsaSignature)) {
            revert Unauthorized();
        }

        // All potentially reverting authorization and local allocation work is
        // completed before nonce consumption. After this point the target receives
        // only a signed, bounded gas budget and returndata copying is capped.
        bytes memory callData = data;
        uint256 requiredGas = uint256(callGasLimit) + POST_CALL_GAS_RESERVE;
        if (gasleft() <= requiredGas) revert InsufficientExecutionGas();

        nonce = current + 1;
        executing = true;
        bool truncated;
        (success, result, truncated) =
            _boundedCall(target, value, callData, callGasLimit);
        executing = false;

        emit Executed(
            current,
            target,
            value,
            callHash,
            success,
            keccak256(result),
            truncated
        );
        return (success, result);
    }
}
