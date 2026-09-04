// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {TrustedRelayerCrossDomainMessenger} from "../contracts/bridge/TrustedRelayerCrossDomainMessenger.sol";
import {SinergyQEController, ISinergyMessenger} from "../contracts/economics/SinergyQEController.sol";
import {
    BaseQEExternalExecutor,
    IBaseQEGradientAdapter,
    IBaseMessengerForQE
} from "../contracts/economics/BaseQEExternalExecutor.sol";

contract MockMessenger {
    address private sender_;
    uint256 private sourceChain_;

    address public lastTarget;
    address public lastSender;
    bytes public lastMessage;
    uint32 public lastMinGasLimit;
    uint256 public sentCount;

    function sendMessage(address target, bytes calldata message, uint32 minGasLimit) external payable {
        require(msg.value == 0, "NO_VALUE");
        lastTarget = target;
        lastSender = msg.sender;
        lastMessage = message;
        lastMinGasLimit = minGasLimit;
        sentCount++;
    }

    function xDomainMessageSender() external view returns (address) { return sender_; }
    function xDomainSourceChainId() external view returns (uint256) { return sourceChain_; }

    function relay(address target, address remoteSender, uint256 sourceChain, bytes calldata data)
        external
        returns (bytes memory)
    {
        sender_ = remoteSender;
        sourceChain_ = sourceChain;
        (bool ok, bytes memory out) = target.call(data);
        sender_ = address(0);
        sourceChain_ = 0;
        require(ok, string(out));
        return out;
    }
}

contract MessengerReceiver {
    TrustedRelayerCrossDomainMessenger public immutable messenger;
    address public immutable expectedRemote;
    uint256 public value;

    constructor(TrustedRelayerCrossDomainMessenger messenger_, address expectedRemote_) {
        messenger = messenger_;
        expectedRemote = expectedRemote_;
    }

    function receiveNumber(uint256 n) external {
        require(msg.sender == address(messenger), "MESSENGER_ONLY");
        require(messenger.xDomainMessageSender() == expectedRemote, "REMOTE_SENDER");
        require(messenger.xDomainSourceChainId() == 8453, "REMOTE_CHAIN");
        value = n;
    }
}

contract MockGradientAdapter is IBaseQEGradientAdapter {
    bytes32 public immutable override venueSetHash;
    uint256 public navUsdc6 = 1_000_000;
    uint256 public closeNavUsdc6 = 990_000;
    bool public positionOpen;
    uint256 public lastIntent;
    uint16 public lastTransferBps;

    constructor() { venueSetHash = keccak256("MOCK_VENUE_SET"); }
    function setCloseNav(uint256 next) external { closeNavUsdc6 = next; }
    function canonicalNavUsdc6(address) external returns (uint256) { return navUsdc6; }

    function openGradient(
        address,
        uint256 intentId,
        int32,
        uint16 gradientTransferBps,
        uint128 principalUsdc6,
        uint64
    ) external returns (uint256, uint256) {
        require(!positionOpen, "OPEN");
        positionOpen = true;
        lastIntent = intentId;
        lastTransferBps = gradientTransferBps;
        navUsdc6 = 999_000;
        return (uint256(principalUsdc6) * gradientTransferBps / 10_000, 300);
    }

    function closeGradient(address, uint256 intentId, uint64) external returns (uint256, uint256) {
        require(positionOpen && intentId == lastIntent, "NO_POSITION");
        positionOpen = false;
        navUsdc6 = closeNavUsdc6;
        return (100_000, 300);
    }

    function settlementClean(address, uint256 intentId) external view returns (bool) {
        return intentId == lastIntent && !positionOpen;
    }
}

contract SinergyL1BaseQEV1Test {
    function testMessengerAuthenticatesRemoteSenderAndRejectsReplay() external {
        address remoteEconomic = address(0xBEEF);
        TrustedRelayerCrossDomainMessenger messenger =
            new TrustedRelayerCrossDomainMessenger(8453, address(this), address(this));
        MessengerReceiver receiver = new MessengerReceiver(messenger, remoteEconomic);

        bytes memory message = abi.encodeCall(MessengerReceiver.receiveNumber, (42));
        bytes32 eventId = keccak256("base-event-1");
        messenger.relayMessage(8453, 7, remoteEconomic, address(receiver), 0, message, eventId);
        require(receiver.value() == 42, "NOT_RELAYED");
        require(messenger.successfulMessages(eventId), "NOT_CONSUMED");

        (bool replayOk,) = address(messenger).call(
            abi.encodeCall(
                TrustedRelayerCrossDomainMessenger.relayMessage,
                (8453, 7, remoteEconomic, address(receiver), 0, message, eventId)
            )
        );
        require(!replayOk, "REPLAY_ACCEPTED");
    }

    function testL1QEIntentCarriesPartialGradientAndQTClosesDebt() external {
        MockMessenger messenger = new MockMessenger();
        address baseExecutor = address(0xBACE);
        uint256 neutral = 2_500e18;
        SinergyQEController controller = new SinergyQEController(
            address(this),
            address(0),
            ISinergyMessenger(address(messenger)),
            baseExecutor,
            neutral
        );

        bytes32 venueHash = keccak256("BASE_PINNED_POOL");
        uint256 intentId = controller.openQEIntent(
            1_000,
            2_500,
            100_000,
            100,
            venueHash,
            uint64(block.timestamp + 30 minutes),
            450_000
        );

        require(intentId == 1, "INTENT_ID");
        require(controller.activeIntentId() == 1, "NOT_ACTIVE");
        require(controller.qePriceX18() == neutral * 110 / 100, "QE_PRICE");
        require(controller.qeDebtUsdc6() == 10_000, "QE_DEBT");
        require(messenger.lastTarget() == baseExecutor, "BASE_TARGET");

        messenger.relay(
            address(controller),
            baseExecutor,
            8453,
            abi.encodeCall(SinergyQEController.settleFromBase, (intentId, 1_000_000, 1_000_150, 25_000, 80))
        );

        require(controller.qeDebtUsdc6() == 0, "QT_NOT_CLOSED");
        require(controller.qePriceX18() == neutral, "NOT_NEUTRAL");
        require(controller.activeIntentId() == 0, "STILL_ACTIVE");
    }

    function testBaseOpenCloseWaitsForCanonicalProfit() external {
        MockMessenger messenger = new MockMessenger();
        MockGradientAdapter adapter = new MockGradientAdapter();
        address sinergyController = address(0x51A7);
        BaseQEExternalExecutor executor = new BaseQEExternalExecutor(
            address(this),
            IBaseMessengerForQE(address(messenger)),
            sinergyController,
            adapter
        );

        bytes memory open = abi.encodeCall(
            BaseQEExternalExecutor.onQEIntent,
            (
                1,
                int32(1_000),
                uint16(2_500),
                uint128(100_000),
                uint128(5_000),
                adapter.venueSetHash(),
                uint64(block.timestamp + 30 minutes)
            )
        );
        messenger.relay(address(executor), sinergyController, 8_453_001, open);
        require(adapter.positionOpen(), "POSITION_NOT_OPEN");
        require(adapter.lastTransferBps() == 2_500, "TRANSFER_BPS");

        (bool lowCloseOk,) = address(executor).call(abi.encodeCall(BaseQEExternalExecutor.closeQEIntent, (1)));
        require(!lowCloseOk, "LOSS_CLOSE_ACCEPTED");
        require(adapter.positionOpen(), "REVERT_DID_NOT_RESTORE_POSITION");

        adapter.setCloseNav(1_010_000);
        executor.closeQEIntent(1);
        require(!adapter.positionOpen(), "POSITION_NOT_CLOSED");
        require(executor.cumulativeAcceptedCanonicalGainUsdc6() == 10_000, "GAIN_ACCOUNTING");
        require(messenger.sentCount() == 1, "SETTLEMENT_NOT_SENT");
        require(messenger.lastTarget() == sinergyController, "WRONG_SETTLEMENT_TARGET");
    }
}
