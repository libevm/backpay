pragma solidity ^0.8.12;

import "./IUniswap.sol";
import "./BasePaymaster.sol";
import "forge-std/console.sol";

contract BackrunningPaymaster is BasePaymaster {
    using SafeERC20 for IERC20;

    uint256 private constant VALID_TIMESTAMP_OFFSET = 20;

    uint256 private constant SIGNATURE_OFFSET = 84;

    address constant wmatic = 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270;

    constructor(IEntryPoint _entryPoint) BasePaymaster(_entryPoint) {}

    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 /*userOpHash*/,
        uint256 /*requiredPreFund*/
    ) internal override returns (bytes memory context, uint256 validationData) {
        if (userOp.paymasterAndData.length <= 20) {
            return ("", _packValidationData(false, 0, 0));
        }
        return (userOp.paymasterAndData[20:], _packValidationData(false, 0, 0));
    }

    function _postOp(
        PostOpMode /*mode*/,
        bytes calldata context,
        uint256 /*actualGasCost*/
    ) internal override {
        if (context.length == 0) {
            return;
        }

        (
            address token,
            address pair1,
            address pair2,
            uint256 wmaticLoanAmount
        ) = abi.decode(context, (address, address, address, uint256));

        // Loaned WMATIC from pair2, need to buy token from pair1
        // and repay pair2 in token
        IUniswapV2Pair(pair2).swap(
            wmatic < token ? wmaticLoanAmount : 0,
            wmatic > token ? wmaticLoanAmount : 0,
            address(this),
            context
        );
    }

    function uniswapV2Call(
        address /*originalSender*/,
        uint256 amount0Out,
        uint256 amount1Out,
        bytes calldata data
    ) external {
        // No auth woooo, PoC lets GO baby
        (address token, address pair1, address pair2, uint256 i, address recipient) = abi.decode(
            data,
            (address, address, address, uint256, address)
        );

        /*
            1. Borrow x WMATIC from pair 2 (to contract)
            > Callback 1 (univ2, from pair 2):
                1.1 Send (x - delta) WMATIC to pair 1
                1.2 Call swap on pair 1, send y TOKEN to pair 2
        */
        uint256 wmaticReceived = wmatic < token ? amount0Out : amount1Out;

        (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(pair2)
            .getReserves();
        uint256 tokenAmtToReturn;
        if (wmatic < token) {
            tokenAmtToReturn = getAmountIn(wmaticReceived, reserve1, reserve0);
        } else {
            tokenAmtToReturn = getAmountIn(wmaticReceived, reserve0, reserve1);
        }

        uint256 wmaticNeeded;
        (reserve0, reserve1, ) = IUniswapV2Pair(pair1).getReserves();
        if (token < wmatic) {
            wmaticNeeded = getAmountIn(tokenAmtToReturn, reserve1, reserve0);
        } else {
            wmaticNeeded = getAmountIn(tokenAmtToReturn, reserve0, reserve1);
        }

        // Profit!!!!
        uint256 wmaticProfit = wmaticReceived - wmaticNeeded;

        // Transfer wmatic needed
        IERC20(wmatic).safeTransfer(pair1, wmaticNeeded);
        IUniswapV2Pair(pair1).swap(
            token < wmatic ? tokenAmtToReturn : 0,
            token > wmatic ? tokenAmtToReturn : 0,
            pair2,
            new bytes(0)
        );

        // Profit!!
        IERC20(wmatic).safeTransfer(recipient, wmaticProfit);
    }

    // given an input amount of an asset and pair reserves, returns the maximum output amount of the other asset
    function getAmountOut(
        uint amountIn,
        uint reserveIn,
        uint reserveOut
    ) internal pure returns (uint amountOut) {
        require(amountIn > 0, "UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT");
        require(
            reserveIn > 0 && reserveOut > 0,
            "UniswapV2Library: INSUFFICIENT_LIQUIDITY"
        );
        uint amountInWithFee = amountIn * 997;
        uint numerator = amountInWithFee * reserveOut;
        uint denominator = (reserveIn * 1000) + amountInWithFee;
        amountOut = numerator / denominator;
    }

    // given an output amount of an asset and pair reserves, returns a required input amount of the other asset
    function getAmountIn(
        uint amountOut,
        uint reserveIn,
        uint reserveOut
    ) internal pure returns (uint amountIn) {
        require(amountOut > 0, "UniswapV2Library: INSUFFICIENT_OUTPUT_AMOUNT");
        require(
            reserveIn > 0 && reserveOut > 0,
            "UniswapV2Library: INSUFFICIENT_LIQUIDITY"
        );
        uint numerator = reserveIn * amountOut * 1000;
        uint denominator = (reserveOut - amountOut) * 997;
        amountIn = (numerator / denominator) + 1;
    }
}
