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

/// @notice Adapter boundary for the real Base external-pool implementation.
/// @dev A position may remain open across blocks. Therefore persistent canonical
///      Base inventory, not a cross-block flash loan, funds the OPEN phase.
interface IBaseQEGradientAdapter {
    function venueSetHash() external view returns (bytes32);

    /// @notice Consolidated executable Base NAV of `vault` in native USDC-6 units.
    function canonicalNavUsdc6(address vault) external returns (uint256);

    /// @notice Transfer a bounded fraction of the SINERGY internal QE gradient
    /// into the external Base pool. Positive QE buys the external base asset;
    /// negative QE sells it. The adapter must return all output to `vault`.
    function openGradient(
        address vault,
        uint256 intentId,
        int32 qePremiumBps,
        uint16 gradientTransferBps,
        uint128 principalUsdc6,
        uint64 deadline
    ) external returns (uint256 externalGrossValueUsdc6, uint256 totalExternalCostsUsdc6);

    /// @notice Close the previously opened gradient position at current executable Base prices.
    function closeGradient(address vault, uint256 intentId, uint64 deadline)
        external
        returns (uint256 externalGrossValueUsdc6, uint256 totalExternalCostsUsdc6);

    /// @notice True only after the adapter has no debt or hidden residual for this intent.
    function settlementClean(address vault, uint256 intentId) external view returns (bool);
}

/// @notice Base-side two-phase value gate for SINERGY QE intents.
///
/// Phase 1 (OPEN): a bounded fraction of the internal QE gradient is physically
/// transferred into a real Base pool. The resulting inventory may remain open
/// while outside order flow changes the external executable state.
///
/// Phase 2 (CLOSE): anyone may attempt to close. The entire close transaction
/// reverts unless final canonical Base NAV is at least `navBefore + minGain`.
/// Thus an unprofitable attempted close cannot crystallize a loss accidentally.
///
/// After expiry the governor may force-unwind to clear risk; that settlement may
/// report a loss to SINERGY L1 instead of hiding it.
contract BaseQEExternalExecutor {
    uint256 public constant SINERGY_CHAIN_ID = 8_453_001;

    enum PositionState {
        NONE,
        OPEN,
        SETTLED,
        FORCED_UNWIND
    }

    struct Position {
        PositionState state;
        int32 qePremiumBps;
        uint16 gradientTransferBps;
        uint128 principalUsdc6;
        uint128 minCanonicalGainUsdc6;
        uint64 deadline;
        bytes32 venueSetHash;
        uint256 navBeforeUsdc6;
        uint256 navOpenUsdc6;
        uint256 openGrossUsdc6;
        uint256 openCostsUsdc6;
        uint256 closeGrossUsdc6;
        uint256 closeCostsUsdc6;
    }

    address public governor;
    IBaseMessengerForQE public immutable messenger;
    address public immutable sinergyController;
    IBaseQEGradientAdapter public adapter;
    bytes32 public adapterCodehash;

    mapping(uint256 => Position) public positions;

    uint256 public cumulativeAcceptedCanonicalGainUsdc6;
    uint256 public cumulativeForcedCanonicalLossUsdc6;
    uint256 public lastIntentId;
    uint256 public lastNavBeforeUsdc6;
    uint256 public lastNavAfterUsdc6;

    error Unauthorized();
    error WrongRemote();
    error InvalidAdapter();
    error InvalidIntent();
    error InvalidState();
    error SettlementDirty();
    error CanonicalGainTooLow();
    error NotExpired();

    event AdapterChanged(address indexed oldAdapter, address indexed newAdapter, bytes32 codehash);
    event GovernorChanged(address indexed oldGovernor, address indexed newGovernor);
    event QEGradientOpened(
        uint256 indexed intentId,
        int32 qePremiumBps,
        uint16 gradientTransferBps,
        uint256 principalUsdc6,
        uint256 canonicalNavBeforeUsdc6,
        uint256 canonicalNavOpenUsdc6,
        uint256 externalGrossValueUsdc6,
        uint256 totalExternalCostsUsdc6,
        bytes32 venueSetHash
    );
    event QEExternalSettlement(
        uint256 indexed intentId,
        bool forcedUnwind,
        uint256 canonicalNavBeforeUsdc6,
        uint256 canonicalNavAfterUsdc6,
        int256 canonicalDeltaUsdc6,
        uint256 externalGrossValueUsdc6,
        uint256 totalExternalCostsUsdc6,
        bytes32 venueSetHash
    );

    constructor(
        address governor_,
        IBaseMessengerForQE messenger_,
        address sinergyController_,
        IBaseQEGradientAdapter adapter_
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

    /// @dev Adapter rotation is allowed only by governance. Existing positions
    /// must be settled before operationally rotating adapters; each position also
    /// commits its venueSetHash so a mismatched replacement cannot close it silently.
    function setAdapter(IBaseQEGradientAdapter next) external {
        if (msg.sender != governor) revert Unauthorized();
        _setAdapter(next);
    }

    function _setAdapter(IBaseQEGradientAdapter next) internal {
        address a = address(next);
        bytes32 h = a.codehash;
        if (a == address(0) || h == bytes32(0)) revert InvalidAdapter();
        address old = address(adapter);
        adapter = next;
        adapterCodehash = h;
        emit AdapterChanged(old, a, h);
    }

    /// @notice Relay target for a SINERGY L1 QE intent. This opens, but does not
    /// finalize, the external gradient position.
    function onQEIntent(
        uint256 intentId,
        int32 qePremiumBps,
        uint16 gradientTransferBps,
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
        if (
            intentId == 0 || principalUsdc6 == 0 || gradientTransferBps == 0 || gradientTransferBps > 10_000
                || deadline <= block.timestamp
        ) revert InvalidIntent();
        if (positions[intentId].state != PositionState.NONE) revert InvalidState();
        _assertAdapter(venueSetHash);

        uint256 navBefore = adapter.canonicalNavUsdc6(address(this));
        (uint256 gross, uint256 costs) = adapter.openGradient(
            address(this), intentId, qePremiumBps, gradientTransferBps, principalUsdc6, deadline
        );
        uint256 navOpen = adapter.canonicalNavUsdc6(address(this));

        positions[intentId] = Position({
            state: PositionState.OPEN,
            qePremiumBps: qePremiumBps,
            gradientTransferBps: gradientTransferBps,
            principalUsdc6: principalUsdc6,
            minCanonicalGainUsdc6: minCanonicalGainUsdc6,
            deadline: deadline,
            venueSetHash: venueSetHash,
            navBeforeUsdc6: navBefore,
            navOpenUsdc6: navOpen,
            openGrossUsdc6: gross,
            openCostsUsdc6: costs,
            closeGrossUsdc6: 0,
            closeCostsUsdc6: 0
        });

        emit QEGradientOpened(
            intentId,
            qePremiumBps,
            gradientTransferBps,
            principalUsdc6,
            navBefore,
            navOpen,
            gross,
            costs,
            venueSetHash
        );
    }

    /// @notice Permissionless profitable close attempt. If current external
    /// state does not support the required final NAV, the whole call reverts and
    /// the OPEN state remains unchanged.
    function closeQEIntent(uint256 intentId) external {
        Position storage p = positions[intentId];
        if (p.state != PositionState.OPEN) revert InvalidState();
        if (block.timestamp > p.deadline) revert NotExpired();
        _assertAdapter(p.venueSetHash);

        (uint256 closeGross, uint256 closeCosts) = adapter.closeGradient(address(this), intentId, p.deadline);
        if (!adapter.settlementClean(address(this), intentId)) revert SettlementDirty();
        uint256 navAfter = adapter.canonicalNavUsdc6(address(this));
        uint256 requiredAfter = p.navBeforeUsdc6 + uint256(p.minCanonicalGainUsdc6);
        if (navAfter < requiredAfter) revert CanonicalGainTooLow();

        p.closeGrossUsdc6 = closeGross;
        p.closeCostsUsdc6 = closeCosts;
        p.state = PositionState.SETTLED;

        uint256 gain = navAfter - p.navBeforeUsdc6;
        cumulativeAcceptedCanonicalGainUsdc6 += gain;
        _recordAndSendSettlement(intentId, p, navAfter, false);
    }

    /// @notice Risk-off path after expiry. Unlike the normal close, a loss is
    /// permitted and is reported explicitly to SINERGY L1 so QT can clear the
    /// internal impulse and the reserve loss remains visible.
    function forceUnwindExpired(uint256 intentId) external {
        if (msg.sender != governor) revert Unauthorized();
        Position storage p = positions[intentId];
        if (p.state != PositionState.OPEN) revert InvalidState();
        if (block.timestamp <= p.deadline) revert NotExpired();
        _assertAdapter(p.venueSetHash);

        // Adapter close receives the current timestamp so an expired position can
        // be unwound even though its original economic-intent deadline has passed.
        (uint256 closeGross, uint256 closeCosts) =
            adapter.closeGradient(address(this), intentId, uint64(block.timestamp + 10 minutes));
        if (!adapter.settlementClean(address(this), intentId)) revert SettlementDirty();
        uint256 navAfter = adapter.canonicalNavUsdc6(address(this));

        p.closeGrossUsdc6 = closeGross;
        p.closeCostsUsdc6 = closeCosts;
        p.state = PositionState.FORCED_UNWIND;

        if (navAfter < p.navBeforeUsdc6) {
            cumulativeForcedCanonicalLossUsdc6 += p.navBeforeUsdc6 - navAfter;
        }
        _recordAndSendSettlement(intentId, p, navAfter, true);
    }

    function _assertAdapter(bytes32 expectedVenueSetHash) internal view {
        if (address(adapter).codehash != adapterCodehash || adapterCodehash == bytes32(0)) {
            revert InvalidAdapter();
        }
        if (adapter.venueSetHash() != expectedVenueSetHash) revert InvalidAdapter();
    }

    function _recordAndSendSettlement(
        uint256 intentId,
        Position storage p,
        uint256 navAfter,
        bool forcedUnwind
    ) internal {
        lastIntentId = intentId;
        lastNavBeforeUsdc6 = p.navBeforeUsdc6;
        lastNavAfterUsdc6 = navAfter;

        uint256 gross = p.openGrossUsdc6 + p.closeGrossUsdc6;
        uint256 costs = p.openCostsUsdc6 + p.closeCostsUsdc6;
        int256 delta = navAfter >= p.navBeforeUsdc6
            ? int256(navAfter - p.navBeforeUsdc6)
            : -int256(p.navBeforeUsdc6 - navAfter);

        emit QEExternalSettlement(
            intentId,
            forcedUnwind,
            p.navBeforeUsdc6,
            navAfter,
            delta,
            gross,
            costs,
            p.venueSetHash
        );

        messenger.sendMessage(
            sinergyController,
            abi.encodeCall(
                ISinergyQESettlementReceiver.settleFromBase,
                (intentId, p.navBeforeUsdc6, navAfter, gross, costs)
            ),
            450_000
        );
    }
}
