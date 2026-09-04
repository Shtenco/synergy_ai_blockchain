// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

interface IERC20Gradient {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IUniV3PoolIdentity {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function fee() external view returns (uint24);
}

interface IUniQuoterV2Gradient {
    struct QuoteExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint24 fee;
        uint160 sqrtPriceLimitX96;
    }

    function quoteExactInputSingle(QuoteExactInputSingleParams memory params)
        external
        returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate);
}

interface IUniRouter02Gradient {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

/// @notice Concrete V11-style partial-gradient adapter against the pinned Base
/// WETH/USDC Uniswap V3 0.30% pool used by the previous SYNERGY fork harness.
///
/// Positive internal QE (P_internal > P_external):
///     USDC -> WETH on Base, physically pushing a bounded part of the gradient outward.
///
/// Negative internal QE (P_internal < P_external):
///     WETH -> USDC on Base, physically pushing the opposite direction.
///
/// The opened inventory remains in the Base executor vault. A later CLOSE performs
/// the inverse leg at then-current executable pool state. Without intervening outside
/// flow, fees/price impact make the round trip non-profitable; the parent executor's
/// canonical-NAV gate therefore refuses to call such a round trip a successful cycle.
contract BasePinnedPoolGradientAdapter {
    uint256 public constant BPS = 10_000;
    uint256 public constant FEE_DENOMINATOR = 1_000_000;

    address public constant WETH = 0x4200000000000000000000000000000000000006;
    address public constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address public constant POOL = 0x6c561B446416E1A00E8E93E221854d6eA4171372;
    address public constant QUOTER_V2 = 0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a;
    address public constant SWAP_ROUTER_02 = 0x2626664c2603336E57b271c5C0b26F421741e481;
    uint24 public constant POOL_FEE = 3000;

    struct Position {
        bool open;
        bool positiveQE;
        uint256 openInput;
        uint256 openOutput;
        uint256 transferNotionalUsdc6;
        uint64 openedAt;
    }

    address public immutable executor;
    uint16 public immutable slippageBps;
    bytes32 public immutable venueSetHash;
    mapping(uint256 => Position) public positions;

    error Unauthorized();
    error InvalidConfig();
    error InvalidIntent();
    error PositionExists();
    error PositionMissing();
    error TransferFailed();
    error QuoteFailed();
    error Slippage();
    error Residual();

    event GradientOpened(
        uint256 indexed intentId,
        bool positiveQE,
        uint256 transferNotionalUsdc6,
        address tokenIn,
        uint256 amountIn,
        address tokenOut,
        uint256 amountOut
    );
    event GradientClosed(
        uint256 indexed intentId,
        bool positiveQE,
        address tokenIn,
        uint256 amountIn,
        address tokenOut,
        uint256 amountOut
    );

    constructor(address executor_, uint16 slippageBps_) {
        if (executor_ == address(0) || slippageBps_ > 500) revert InvalidConfig();
        executor = executor_;
        slippageBps = slippageBps_;
        if (!verifyPinnedPool()) revert InvalidConfig();

        venueSetHash = keccak256(
            abi.encode(
                "SINERGY_BASE_V11_PINNED_GRADIENT_V1",
                block.chainid,
                WETH,
                USDC,
                POOL,
                POOL_FEE,
                QUOTER_V2,
                SWAP_ROUTER_02,
                slippageBps_
            )
        );

        _forceApprove(USDC, SWAP_ROUTER_02, type(uint256).max);
        _forceApprove(WETH, SWAP_ROUTER_02, type(uint256).max);
    }

    modifier onlyExecutor(address vault) {
        if (msg.sender != executor || vault != executor) revert Unauthorized();
        _;
    }

    function verifyPinnedPool() public view returns (bool) {
        if (block.chainid != 8453 && block.chainid != 31337) {
            // Base fork tests often preserve 8453; 31337 is allowed only when the
            // pinned address has been deliberately etched/mock-provisioned.
            return false;
        }
        IUniV3PoolIdentity p = IUniV3PoolIdentity(POOL);
        try p.token0() returns (address t0) {
            try p.token1() returns (address t1) {
                try p.fee() returns (uint24 f) {
                    bool pair = (t0 == WETH && t1 == USDC) || (t0 == USDC && t1 == WETH);
                    return pair && f == POOL_FEE;
                } catch {
                    return false;
                }
            } catch {
                return false;
            }
        } catch {
            return false;
        }
    }

    /// @notice Executable canonical NAV: native USDC plus a current executable
    /// WETH->USDC quote for all WETH held in the executor vault.
    function canonicalNavUsdc6(address vault) external returns (uint256 navUsdc6) {
        if (vault != executor) revert Unauthorized();
        uint256 u = IERC20Gradient(USDC).balanceOf(vault);
        uint256 w = IERC20Gradient(WETH).balanceOf(vault);
        if (w == 0) return u;
        return u + _quote(WETH, USDC, w);
    }

    function openGradient(
        address vault,
        uint256 intentId,
        int32 qePremiumBps,
        uint16 gradientTransferBps,
        uint128 principalUsdc6,
        uint64 deadline
    ) external onlyExecutor(vault) returns (uint256 externalGrossValueUsdc6, uint256 totalExternalCostsUsdc6) {
        if (
            intentId == 0 || qePremiumBps == 0 || gradientTransferBps == 0 || gradientTransferBps > BPS
                || principalUsdc6 == 0 || deadline <= block.timestamp
        ) revert InvalidIntent();
        if (positions[intentId].open) revert PositionExists();

        uint256 notional = uint256(principalUsdc6) * uint256(gradientTransferBps) / BPS;
        if (notional == 0) revert InvalidIntent();

        bool positive = qePremiumBps > 0;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 amountOut;

        if (positive) {
            // Old V11 USDC pump: internal ETH is dearer -> buy external WETH.
            tokenIn = USDC;
            tokenOut = WETH;
            amountIn = notional;
        } else {
            // Old V11 ETH pump: internal ETH is cheaper -> sell external WETH.
            // Size the WETH leg from the same USDC-denominated transferred notional.
            tokenIn = WETH;
            tokenOut = USDC;
            amountIn = _quote(USDC, WETH, notional);
        }
        if (amountIn == 0) revert QuoteFailed();

        _pull(tokenIn, vault, amountIn);
        amountOut = _swap(tokenIn, tokenOut, amountIn, deadline);
        _push(tokenOut, vault, amountOut);

        positions[intentId] = Position({
            open: true,
            positiveQE: positive,
            openInput: amountIn,
            openOutput: amountOut,
            transferNotionalUsdc6: notional,
            openedAt: uint64(block.timestamp)
        });

        externalGrossValueUsdc6 = notional;
        totalExternalCostsUsdc6 = notional * uint256(POOL_FEE) / FEE_DENOMINATOR;

        emit GradientOpened(intentId, positive, notional, tokenIn, amountIn, tokenOut, amountOut);
        _requireNoResidual();
    }

    function closeGradient(address vault, uint256 intentId, uint64 deadline)
        external
        onlyExecutor(vault)
        returns (uint256 externalGrossValueUsdc6, uint256 totalExternalCostsUsdc6)
    {
        Position memory p = positions[intentId];
        if (!p.open) revert PositionMissing();
        if (deadline <= block.timestamp) revert InvalidIntent();

        // Inverse pump uses exactly the output inventory created by OPEN.
        address tokenIn = p.positiveQE ? WETH : USDC;
        address tokenOut = p.positiveQE ? USDC : WETH;
        uint256 amountIn = p.openOutput;

        _pull(tokenIn, vault, amountIn);
        uint256 amountOut = _swap(tokenIn, tokenOut, amountIn, deadline);
        _push(tokenOut, vault, amountOut);

        delete positions[intentId];

        if (tokenOut == USDC) {
            externalGrossValueUsdc6 = amountOut;
        } else {
            externalGrossValueUsdc6 = _quote(WETH, USDC, amountOut);
        }
        totalExternalCostsUsdc6 = p.transferNotionalUsdc6 * uint256(POOL_FEE) / FEE_DENOMINATOR;

        emit GradientClosed(intentId, p.positiveQE, tokenIn, amountIn, tokenOut, amountOut);
        _requireNoResidual();
    }

    function settlementClean(address vault, uint256 intentId) external view returns (bool) {
        if (vault != executor) return false;
        return !positions[intentId].open && IERC20Gradient(USDC).balanceOf(address(this)) == 0
            && IERC20Gradient(WETH).balanceOf(address(this)) == 0;
    }

    function quoteUsdcToWeth(uint256 amountUsdc6) external returns (uint256) {
        return _quote(USDC, WETH, amountUsdc6);
    }

    function quoteWethToUsdc(uint256 amountWeth) external returns (uint256) {
        return _quote(WETH, USDC, amountWeth);
    }

    function _quote(address tokenIn, address tokenOut, uint256 amountIn) internal returns (uint256 amountOut) {
        if (amountIn == 0) return 0;
        IUniQuoterV2Gradient.QuoteExactInputSingleParams memory q = IUniQuoterV2Gradient.QuoteExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            fee: POOL_FEE,
            sqrtPriceLimitX96: 0
        });
        try IUniQuoterV2Gradient(QUOTER_V2).quoteExactInputSingle(q) returns (
            uint256 out,
            uint160,
            uint32,
            uint256
        ) {
            if (out == 0) revert QuoteFailed();
            return out;
        } catch {
            revert QuoteFailed();
        }
    }

    function _swap(address tokenIn, address tokenOut, uint256 amountIn, uint64 deadline)
        internal
        returns (uint256 actualOut)
    {
        if (deadline <= block.timestamp) revert InvalidIntent();
        uint256 quote = _quote(tokenIn, tokenOut, amountIn);
        uint256 minOut = quote * (BPS - uint256(slippageBps)) / BPS;
        uint256 beforeOut = IERC20Gradient(tokenOut).balanceOf(address(this));

        IUniRouter02Gradient.ExactInputSingleParams memory p = IUniRouter02Gradient.ExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: POOL_FEE,
            recipient: address(this),
            amountIn: amountIn,
            amountOutMinimum: minOut,
            sqrtPriceLimitX96: 0
        });
        IUniRouter02Gradient(SWAP_ROUTER_02).exactInputSingle(p);

        actualOut = IERC20Gradient(tokenOut).balanceOf(address(this)) - beforeOut;
        if (actualOut < minOut) revert Slippage();
    }

    function _pull(address token, address from, uint256 amount) internal {
        if (!IERC20Gradient(token).transferFrom(from, address(this), amount)) revert TransferFailed();
    }

    function _push(address token, address to, uint256 amount) internal {
        if (!IERC20Gradient(token).transfer(to, amount)) revert TransferFailed();
    }

    function _forceApprove(address token, address spender, uint256 amount) internal {
        if (!IERC20Gradient(token).approve(spender, 0)) revert TransferFailed();
        if (!IERC20Gradient(token).approve(spender, amount)) revert TransferFailed();
    }

    function _requireNoResidual() internal view {
        if (
            IERC20Gradient(USDC).balanceOf(address(this)) != 0
                || IERC20Gradient(WETH).balanceOf(address(this)) != 0
        ) revert Residual();
    }
}
