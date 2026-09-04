// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

interface ISinergyMessenger {
    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable;
    function xDomainMessageSender() external view returns (address);
    function xDomainSourceChainId() external view returns (uint256);
}

interface IBaseQEExternalExecutor {
    function onQEIntent(
        uint256 intentId,
        int32 qePremiumBps,
        uint16 gradientTransferBps,
        uint128 principalUsdc6,
        uint128 minCanonicalGainUsdc6,
        bytes32 venueSetHash,
        uint64 deadline
    ) external;
}

/// @notice SINERGY L1 monetary controller for the
/// QE -> internal gradient -> partial Base transfer -> QT -> canonical settlement cycle.
/// @dev Internal QE debt is never canonical profit. Canonical settlement arrives
///      only from the configured Base executor through the local messenger.
contract SinergyQEController {
    uint256 public constant BASE_CHAIN_ID = 8453;
    uint256 public constant BPS = 10_000;
    uint256 public constant MAX_ABS_QE_BPS = 2_000; // +/-20% in V1
    uint256 public constant MAX_INTENT_LIFETIME = 1 hours;

    struct Intent {
        bool exists;
        bool settled;
        bool cancelled;
        bool economicPass;
        int32 qePremiumBps;
        uint16 gradientTransferBps;
        uint128 principalUsdc6;
        uint128 minCanonicalGainUsdc6;
        uint128 qeDebtUsdc6;
        uint64 deadline;
        bytes32 venueSetHash;
        uint256 canonicalNavBeforeUsdc6;
        uint256 canonicalNavAfterUsdc6;
        uint256 totalExternalCostsUsdc6;
        uint256 externalGrossValueUsdc6;
    }

    address public governor;
    address public nexusPolicy;
    ISinergyMessenger public immutable messenger;
    address public immutable baseExecutor;

    uint256 public neutralPriceX18;
    uint256 public qePriceX18;
    uint256 public qeDebtUsdc6;
    uint256 public nextIntentId = 1;
    uint256 public activeIntentId;

    mapping(uint256 => Intent) public intents;

    error Unauthorized();
    error InvalidIntent();
    error ActiveIntent();
    error NotExpired();
    error WrongRemote();

    event QEIntentOpened(
        uint256 indexed intentId,
        int32 qePremiumBps,
        uint16 gradientTransferBps,
        uint256 principalUsdc6,
        uint256 qeDebtUsdc6,
        uint256 qePriceX18,
        uint256 minCanonicalGainUsdc6,
        bytes32 venueSetHash,
        uint64 deadline
    );
    event QESettled(
        uint256 indexed intentId,
        bool economicPass,
        uint256 canonicalNavBeforeUsdc6,
        uint256 canonicalNavAfterUsdc6,
        int256 canonicalDeltaUsdc6,
        uint256 externalGrossValueUsdc6,
        uint256 totalExternalCostsUsdc6
    );
    event QTCleared(uint256 indexed intentId, uint256 burnedDebtUsdc6);
    event QEIntentCancelled(uint256 indexed intentId, uint256 burnedDebtUsdc6);
    event NeutralPriceChanged(uint256 oldPriceX18, uint256 newPriceX18);
    event GovernorChanged(address oldGovernor, address newGovernor);
    event NexusPolicyChanged(address oldPolicy, address newPolicy);

    constructor(
        address governor_,
        address nexusPolicy_,
        ISinergyMessenger messenger_,
        address baseExecutor_,
        uint256 neutralPriceX18_
    ) {
        if (
            governor_ == address(0) || address(messenger_) == address(0) || baseExecutor_ == address(0)
                || neutralPriceX18_ == 0
        ) revert InvalidIntent();
        governor = governor_;
        nexusPolicy = nexusPolicy_;
        messenger = messenger_;
        baseExecutor = baseExecutor_;
        neutralPriceX18 = neutralPriceX18_;
        qePriceX18 = neutralPriceX18_;
    }

    modifier onlyPolicy() {
        if (msg.sender != governor && msg.sender != nexusPolicy) revert Unauthorized();
        _;
    }

    function setGovernor(address next) external {
        if (msg.sender != governor || next == address(0)) revert Unauthorized();
        address old = governor;
        governor = next;
        emit GovernorChanged(old, next);
    }

    function setNexusPolicy(address next) external {
        if (msg.sender != governor) revert Unauthorized();
        address old = nexusPolicy;
        nexusPolicy = next;
        emit NexusPolicyChanged(old, next);
    }

    function setNeutralPrice(uint256 nextPriceX18) external {
        if (msg.sender != governor || nextPriceX18 == 0 || activeIntentId != 0) revert Unauthorized();
        uint256 old = neutralPriceX18;
        neutralPriceX18 = nextPriceX18;
        qePriceX18 = nextPriceX18;
        emit NeutralPriceChanged(old, nextPriceX18);
    }

    /// @notice Opens one bounded QE impulse and emits a cross-domain execution intent.
    /// @param gradientTransferBps Fraction (1..10000) of the QE-directed principal
    ///        that the Base adapter may use to move/hedge against the external pool.
    ///        This is the explicit "partial gradient transfer" control.
    /// @dev Only one impulse can be active in V1; this makes debt attribution exact.
    function openQEIntent(
        int32 qePremiumBps,
        uint16 gradientTransferBps,
        uint128 principalUsdc6,
        uint128 minCanonicalGainUsdc6,
        bytes32 venueSetHash,
        uint64 deadline,
        uint32 remoteMinGasLimit
    ) external onlyPolicy returns (uint256 intentId) {
        if (activeIntentId != 0) revert ActiveIntent();
        if (
            principalUsdc6 == 0 || venueSetHash == bytes32(0) || gradientTransferBps == 0
                || gradientTransferBps > BPS
        ) revert InvalidIntent();
        if (deadline <= block.timestamp || deadline > block.timestamp + MAX_INTENT_LIFETIME) {
            revert InvalidIntent();
        }

        int256 bps = int256(qePremiumBps);
        int256 absBps = bps < 0 ? -bps : bps;
        if (absBps == 0 || uint256(absBps) > MAX_ABS_QE_BPS) revert InvalidIntent();

        int256 numerator = int256(BPS) + bps;
        if (numerator <= 0) revert InvalidIntent();
        uint256 targetPrice = uint256(int256(neutralPriceX18) * numerator / int256(BPS));
        if (targetPrice == 0) revert InvalidIntent();

        uint256 debt = uint256(principalUsdc6) * uint256(absBps) / BPS;
        if (debt > type(uint128).max) revert InvalidIntent();

        intentId = nextIntentId++;
        intents[intentId] = Intent({
            exists: true,
            settled: false,
            cancelled: false,
            economicPass: false,
            qePremiumBps: qePremiumBps,
            gradientTransferBps: gradientTransferBps,
            principalUsdc6: principalUsdc6,
            minCanonicalGainUsdc6: minCanonicalGainUsdc6,
            qeDebtUsdc6: uint128(debt),
            deadline: deadline,
            venueSetHash: venueSetHash,
            canonicalNavBeforeUsdc6: 0,
            canonicalNavAfterUsdc6: 0,
            totalExternalCostsUsdc6: 0,
            externalGrossValueUsdc6: 0
        });

        activeIntentId = intentId;
        qeDebtUsdc6 += debt;
        qePriceX18 = targetPrice;

        emit QEIntentOpened(
            intentId,
            qePremiumBps,
            gradientTransferBps,
            principalUsdc6,
            debt,
            targetPrice,
            minCanonicalGainUsdc6,
            venueSetHash,
            deadline
        );

        messenger.sendMessage(
            baseExecutor,
            abi.encodeCall(
                IBaseQEExternalExecutor.onQEIntent,
                (
                    intentId,
                    qePremiumBps,
                    gradientTransferBps,
                    principalUsdc6,
                    minCanonicalGainUsdc6,
                    venueSetHash,
                    deadline
                )
            ),
            remoteMinGasLimit
        );
    }

    /// @notice Canonical Base settlement callback relayed from Base.
    /// @dev A failed economic cycle is still settled and its QE debt is cleared;
    ///      losses are not hidden by leaving the intent open.
    function settleFromBase(
        uint256 intentId,
        uint256 canonicalNavBeforeUsdc6,
        uint256 canonicalNavAfterUsdc6,
        uint256 externalGrossValueUsdc6,
        uint256 totalExternalCostsUsdc6
    ) external {
        if (msg.sender != address(messenger)) revert WrongRemote();
        if (
            messenger.xDomainSourceChainId() != BASE_CHAIN_ID
                || messenger.xDomainMessageSender() != baseExecutor
        ) revert WrongRemote();

        Intent storage intent = intents[intentId];
        if (!intent.exists || intent.settled || intent.cancelled || activeIntentId != intentId) {
            revert InvalidIntent();
        }

        intent.canonicalNavBeforeUsdc6 = canonicalNavBeforeUsdc6;
        intent.canonicalNavAfterUsdc6 = canonicalNavAfterUsdc6;
        intent.externalGrossValueUsdc6 = externalGrossValueUsdc6;
        intent.totalExternalCostsUsdc6 = totalExternalCostsUsdc6;

        uint256 requiredAfter = canonicalNavBeforeUsdc6 + uint256(intent.minCanonicalGainUsdc6);
        bool pass = canonicalNavAfterUsdc6 >= requiredAfter;
        intent.economicPass = pass;
        intent.settled = true;

        int256 delta = canonicalNavAfterUsdc6 >= canonicalNavBeforeUsdc6
            ? int256(canonicalNavAfterUsdc6 - canonicalNavBeforeUsdc6)
            : -int256(canonicalNavBeforeUsdc6 - canonicalNavAfterUsdc6);

        uint256 burned = uint256(intent.qeDebtUsdc6);
        if (burned > qeDebtUsdc6) revert InvalidIntent();
        qeDebtUsdc6 -= burned;
        qePriceX18 = neutralPriceX18;
        activeIntentId = 0;

        emit QESettled(
            intentId,
            pass,
            canonicalNavBeforeUsdc6,
            canonicalNavAfterUsdc6,
            delta,
            externalGrossValueUsdc6,
            totalExternalCostsUsdc6
        );
        emit QTCleared(intentId, burned);
    }

    /// @notice Fail-closed expiry path when the cross-domain execution never settles.
    function cancelExpired(uint256 intentId) external {
        if (msg.sender != governor) revert Unauthorized();
        Intent storage intent = intents[intentId];
        if (!intent.exists || intent.settled || intent.cancelled || activeIntentId != intentId) {
            revert InvalidIntent();
        }
        if (block.timestamp <= intent.deadline) revert NotExpired();

        intent.cancelled = true;
        uint256 burned = uint256(intent.qeDebtUsdc6);
        if (burned > qeDebtUsdc6) revert InvalidIntent();
        qeDebtUsdc6 -= burned;
        qePriceX18 = neutralPriceX18;
        activeIntentId = 0;

        emit QEIntentCancelled(intentId, burned);
        emit QTCleared(intentId, burned);
    }
}
