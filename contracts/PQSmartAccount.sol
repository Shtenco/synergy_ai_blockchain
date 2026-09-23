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

    function authorizationMessage(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 txNonce,
        uint256 validUntil
    ) public view returns (bytes memory) {
        return abi.encode(
            "SYNERGY/PQ-SMART-ACCOUNT/V2",
            CRYPTO_PROFILE_VERSION,
            block.chainid,
            address(this),
            AUTH_DOMAIN_TRANSACTION,
            AUTH_POLICY_PQ_ONLY,
            AUTHORIZATION_EPOCH,
            target,
            value,
            keccak256(data),
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

    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 validUntil,
        bytes calldata mlDsaSignature,
        bytes calldata slhDsaSignature
    ) external returns (bytes memory result) {
        if (mlDsaSignature.length != 4627 || slhDsaSignature.length != 29792) {
            revert InvalidSignatureEncoding();
        }
        if (
            block.timestamp >= validUntil
                || validUntil - block.timestamp > MAX_AUTHORIZATION_LIFETIME_SECONDS
        ) {
            revert Unauthorized();
        }

        uint256 current = nonce;
        bytes memory message = authorizationMessage(target, value, data, current, validUntil);
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
