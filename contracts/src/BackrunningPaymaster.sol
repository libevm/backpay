pragma solidity ^0.8.12;

import "./BasePaymaster.sol";

contract BackrunningPaymaster is BasePaymaster {
    using SafeERC20 for IERC20;

    uint256 private constant VALID_TIMESTAMP_OFFSET = 20;

    uint256 private constant SIGNATURE_OFFSET = 84;

    address constant wmatic = 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270;

    struct Univ2CallbackData {
        address token;
        address univ2Pair1;
        address univ2Pair2;
        uint128 tokenOut;
        uint128 wmaticIn;
        uint256 wmaticOut;
    }

    constructor(IEntryPoint _entryPoint) BasePaymaster(_entryPoint) {}

    function parsePaymasterAndData(bytes calldata paymasterAndData) public pure returns(uint48 validUntil, uint48 validAfter, bytes calldata signature) {
        (validUntil, validAfter) = abi.decode(paymasterAndData[VALID_TIMESTAMP_OFFSET:SIGNATURE_OFFSET],(uint48, uint48));
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }

    function _validatePaymasterUserOp(
        UserOperation calldata /*userOp*/,
        bytes32 /*userOpHash*/,
        uint256 /*requiredPreFund*/
    )
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        return ("",_packValidationData(false,0,0));
    }

    function _postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) internal override {}

    function uniswapV2Call(
        address /*originalSender*/,
        uint256 /* amount0Out */,
        uint256 /* amount1Out */,
        bytes calldata data
    ) internal {
        // No auth woooo, PoC lets GO baby
        Univ2CallbackData memory cbData = abi.decode(data, (Univ2CallbackData));

        /*
            1. Borrow x WMATIC from pair 2 (to contract)
            > Callback 1 (univ2, from pair 2):
                1.1 Send (x - delta) WETH to pair 1
                1.2 Call swap on pair 1, send y TOKEN to pair 2
        */
        // uint256 wmaticReceived = wmatic < cbData.token
        //     ? amount0Out
        //     : amount1Out;

        // Just an example back running
        // require(wmaticReceived >= cbData.wethOut, "!weth-out");

        IERC20(wmatic).safeTransfer(cbData.univ2Pair1, cbData.wmaticIn);
        IUniswapV2Pair(cbData.univ2Pair1).swap(
            cbData.token < wmatic ? cbData.tokenOut : 0,
            cbData.token > wmatic ? cbData.tokenOut : 0,
            cbData.univ2Pair2,
            new bytes(0)
        );
    }
}
