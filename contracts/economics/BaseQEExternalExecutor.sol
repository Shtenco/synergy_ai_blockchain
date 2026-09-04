// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

interface IBaseMessengerForQE {
    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable;
    function xDomainMessageSender() external view returns (address);
    function xDomainSourceChainId() external view returns (uint256);
}

interface ISinergyQESettlementReceiver {
    function settleFromBase(
        uint256 intentId,
        uint256 canonicalNavBeforeUsdc6,
        uint256 canonicalNavAfterUsdc6,
        uint256 externalGrossValueUsdc6,
        uint256 totalExternalCostsUsdc6
    ) external;
}

/// @notice Adapter boundary for the real Base DEX implementation.
/// @dev The adapter is separately codehash-pinned by BaseQEExternalExecutor.
interface IBaseQEExecutionAdapter {
    /// @notice Hash of the exact venue/address/fee universe used by the adapter.
    function venueSetHash() external view returns (bytes32);

    /// @notice Consolidated executable Base NAV of `vault` in native USDC 6-decimal units.
    /// Must include canonical WETH at an executable liquidation quote and subtract any
    /// protocol-owned LP/reserve loss that the adapter controls.
    function canonicalNavUsdc6(address vault) external returns (uint256);

    /// @notice Execute the bounded QE-directed external leg using assets authorized by `vault`.
    /// `externalGrossValueUsdc6` and `totalExternalCostsUsdc6` are diagnostics; the binding
    /// acceptance metric remains the post-operation canonical NAV delta.
    function executeQE(
        address vault,
        int32 qePremiumBps,
        uint128 principalUsdc6,
        uint64 deadline
    ) external returns (uint256 externalGrossValueUsdc6, uint256 totalExternalCostsUsdc6);

    /// @notice Fail-closed settlement invariant: no flash debt, no hidden executor residual,
    /// and no adapter-side debt left after executeQE.
    function settlementClean(address vault) external view returns (bool);
}

/// @notice Base-side canonical value gate for SINERGY QE intents.
/// @dev This contract does not assume that QE creates profit. If the configured adapter
///      cannot finish the complete external operation with the required canonical NAV gain,
///      the transaction reverts atomically and no settlement receipt is emitted.
contract BaseQEExternalExecutor {
    uint256 public constant SINERGY_CHAIN_ID = 8_453_001;

    address public governor;
    IBaseMessengerForQE public immutable messenger;
    address public immutable sinergyController;
    IBaseQEExecutionAdapter public adapter;
    bytes32 public adapterCodehash;

    uint256 public cumulativeAcceptedCanonicalGainUsdc6;
    uint256 public lastIntentId;
    uint256 public lastNavBeforeUsdc6;
    uint256 public lastNavAfterUsdc6;

    error Unauthorized();
    error WrongRemote();
    error InvalidAdapter();
    error InvalidIntent();
    error SettlementDirty();
    error CanonicalGainTooLow();

    event AdapterChanged(address indexed oldAdapter, address indexed newAdapter, bytes32 codehash);
    event GovernorChanged(address indexed oldGovernor, address indexed newGovernor);
    event QEExternalSettlement(
        uint256 indexed intentId,
        int32 qePremiumBps,
        uint256 principalUsdc6,
        uint256 canonicalNavBeforeUsdc6,
        uint256 canonicalNavAfterUsdc6,
        uint256 canonicalGainUsdc6,
        uint256 externalGrossValueUsdc6,
        uint256 totalExternalCostsUsdc6,
        bytes32 venueSetHash
    );

    constructor(
        address governor_,
        IBaseMessengerForQE messenger_,
        address sinergyController_,
        IBaseQEExecutionAdapter adapter_
    ) {
        if (
            governor_ == address(0) || address(messenger_) == address(0) || sinergyController_ == address(0)
                || address(adapter_) == address(0)
        ) revert InvalidIntent();
        governor = governor_;
        messenger = messenger_;
        sinergyController = sinergyController_;
        _setAdapter(adapter_);
    }

    function setGovernor(address next) external {
        if (msg.sender != governor || next == address(0)) revert Unauthorized();
        address old = governor;
        governor = next;
        emit GovernorChanged(old, next);
    }

    function setAdapter(IBaseQEExecutionAdapter next) external {
        if (msg.sender != governor) revert Unauthorized();
        _setAdapter(next);
    }

    function _setAdapter(IBaseQEExecutionAdapter next) internal {
        address a = address(next);
        bytes32 h = a.codehash;
        if (a == address(0) || h == bytes32(0)) revert InvalidAdapter();
        address old = address(adapter);
        adapter = next;
        adapterCodehash = h;
        emit AdapterChanged(old, a, h);
    }

    /// @notice Relay target for a SINERGY L1 QE intent.
    function onQEIntent(
        uint256 intentId,
        int32 qePremiumBps,
        uint128 principalUsdc6,
        uint128 minCanonicalGainUsdc6,
        bytes32 venueSetHash,
        uint64 deadline
    ) external {
        if (msg.sender != address(messenger)) revert WrongRemote();
        if (
            messenger.xDomainSourceChainId() != SINERGY_CHAIN_ID
                || messenger.xDomainMessageSender() != sinergyController
        ) revert WrongRemote();
        if (intentId == 0 || principalUsdc6 == 0 || deadline < block.timestamp) revert InvalidIntent();
        if (address(adapter).codehash != adapterCodehash || adapterCodehash == bytes32(0)) {
            revert InvalidAdapter();
        }
        if (adapter.venueSetHash() != venueSetHash) revert InvalidAdapter();

        uint256 navBefore = adapter.canonicalNavUsdc6(address(this));
        (uint256 gross, uint256 costs) =
            adapter.executeQE(address(this), qePremiumBps, principalUsdc6, deadline);
        if (!adapter.settlementClean(address(this))) revert SettlementDirty();
        uint256 navAfter = adapter.canonicalNavUsdc6(address(this));

        uint256 requiredAfter = navBefore + uint256(minCanonicalGainUsdc6);
        if (navAfter < requiredAfter) revert CanonicalGainTooLow();

        uint256 gain = navAfter - navBefore;
        cumulativeAcceptedCanonicalGainUsdc6 += gain;
        lastIntentId = intentId;
        lastNavBeforeUsdc6 = navBefore;
        lastNavAfterUsdc6 = navAfter;

        emit QEExternalSettlement(
            intentId,
            qePremiumBps,
            principalUsdc6,
            navBefore,
            navAfter,
            gain,
            gross,
            costs,
            venueSetHash
        );

        messenger.sendMessage(
            sinergyController,
            abi.encodeCall(
                ISinergyQESettlementReceiver.settleFromBase,
                (intentId, navBefore, navAfter, gross, costs)
            ),
            450_000
        );
    }
}
