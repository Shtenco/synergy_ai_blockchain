// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Minimal ICrossDomainMessenger-style corridor for Base <-> SINERGY L1.
/// @dev This is intentionally a trusted-relayer transport. It does NOT claim
///      OptimismPortal security and it does not bridge native ETH value.
contract TrustedRelayerCrossDomainMessenger {
    bytes32 public constant MESSAGE_DOMAIN = keccak256("SINERGY_TRUSTED_XDM_V1");
    uint256 public constant MAX_MESSAGE_BYTES = 65_536;

    uint256 public immutable LOCAL_CHAIN_ID;
    uint256 public immutable REMOTE_CHAIN_ID;
    address public governor;
    address public trustedRelayer;
    uint256 public messageNonce;

    mapping(bytes32 => bool) public successfulMessages;

    address private _xDomainMessageSender;
    uint256 private _xDomainSourceChainId;
    bytes32 private _xDomainSourceEventId;
    bool private _relaying;

    error Unauthorized();
    error WrongChain();
    error InvalidMessage();
    error Replay();
    error ReentrantRelay();
    error NativeValueUnsupported();
    error RelayCallFailed(bytes reason);

    event SentMessage(
        address indexed target,
        address sender,
        bytes message,
        uint256 messageNonce,
        uint32 minGasLimit
    );
    event RelayedMessage(bytes32 indexed sourceEventId, bytes32 indexed messageHash);
    event TrustedRelayerChanged(address indexed oldRelayer, address indexed newRelayer);
    event GovernorChanged(address indexed oldGovernor, address indexed newGovernor);

    constructor(uint256 remoteChainId_, address governor_, address trustedRelayer_) {
        if (remoteChainId_ == 0 || remoteChainId_ == block.chainid) revert WrongChain();
        if (governor_ == address(0) || trustedRelayer_ == address(0)) revert InvalidMessage();
        LOCAL_CHAIN_ID = block.chainid;
        REMOTE_CHAIN_ID = remoteChainId_;
        governor = governor_;
        trustedRelayer = trustedRelayer_;
    }

    function setTrustedRelayer(address next) external {
        if (msg.sender != governor) revert Unauthorized();
        if (next == address(0)) revert InvalidMessage();
        address old = trustedRelayer;
        trustedRelayer = next;
        emit TrustedRelayerChanged(old, next);
    }

    function setGovernor(address next) external {
        if (msg.sender != governor) revert Unauthorized();
        if (next == address(0)) revert InvalidMessage();
        address old = governor;
        governor = next;
        emit GovernorChanged(old, next);
    }

    /// @notice Emits an outbound message for the trusted relayer to pick up.
    /// @dev No native value is transported in V1. Canonical assets stay in their
    ///      chain-local vaults; this corridor transports intents and receipts.
    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable {
        if (msg.value != 0) revert NativeValueUnsupported();
        if (target == address(0) || message.length > MAX_MESSAGE_BYTES) revert InvalidMessage();
        uint256 nonce = messageNonce++;
        emit SentMessage(target, msg.sender, message, nonce, minGasLimit);
    }

    /// @notice Relays a remote SentMessage after the configured relayer has
    ///         independently observed the remote chain and its confirmation policy.
    /// @param sourceEventId Relayer-computed unique source log identity. For V1 it
    ///        MUST commit to source chain, source block hash, source tx hash and log index.
    function relayMessage(
        uint256 sourceChainId,
        uint256 sourceNonce,
        address sourceSender,
        address target,
        uint32 minGasLimit,
        bytes calldata message,
        bytes32 sourceEventId
    ) external payable returns (bytes memory returnData) {
        if (msg.value != 0) revert NativeValueUnsupported();
        if (msg.sender != trustedRelayer) revert Unauthorized();
        if (sourceChainId != REMOTE_CHAIN_ID) revert WrongChain();
        if (
            sourceSender == address(0) || target == address(0) || sourceEventId == bytes32(0)
                || message.length > MAX_MESSAGE_BYTES
        ) revert InvalidMessage();
        if (successfulMessages[sourceEventId]) revert Replay();
        if (_relaying) revert ReentrantRelay();

        bytes32 messageHash = keccak256(
            abi.encode(
                MESSAGE_DOMAIN,
                sourceChainId,
                LOCAL_CHAIN_ID,
                sourceNonce,
                sourceSender,
                target,
                minGasLimit,
                keccak256(message),
                sourceEventId
            )
        );

        _relaying = true;
        _xDomainMessageSender = sourceSender;
        _xDomainSourceChainId = sourceChainId;
        _xDomainSourceEventId = sourceEventId;
        successfulMessages[sourceEventId] = true;

        uint256 gasToForward = gasleft();
        if (gasToForward < uint256(minGasLimit)) revert InvalidMessage();
        (bool ok, bytes memory out) = target.call{gas: gasToForward}(message);
        if (!ok) revert RelayCallFailed(out);

        _xDomainMessageSender = address(0);
        _xDomainSourceChainId = 0;
        _xDomainSourceEventId = bytes32(0);
        _relaying = false;

        emit RelayedMessage(sourceEventId, messageHash);
        return out;
    }

    /// @notice Remote application sender while relayMessage is executing.
    function xDomainMessageSender() external view returns (address) {
        return _xDomainMessageSender;
    }

    function xDomainSourceChainId() external view returns (uint256) {
        return _xDomainSourceChainId;
    }

    function xDomainSourceEventId() external view returns (bytes32) {
        return _xDomainSourceEventId;
    }

    function isRelaying() external view returns (bool) {
        return _relaying;
    }
}
