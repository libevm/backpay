// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/BackrunningPaymaster.sol";
import "../src/SimpleAccountFactory.sol";
import "../src/EntryPoint.sol";
import "../src/Weenus.sol";
import "../src/IUniswap.sol";

contract BackrunningPaymasterTest is Test {
    BackrunningPaymaster public paymaster;

    WeenusToken weenus;
    EntryPoint entrypoint;
    SimpleAccountFactory simpleAccountFactory;

    address internal constant WMATIC = 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270;

    IUniswapV2Factory sushiFactory = IUniswapV2Factory(0xc35DADB65012eC5796536bD9864eD8773aBc74C4);
    IUniswapV2Factory quickswapFactory = IUniswapV2Factory(0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32);

    IUniswapRouter quickswapRouter =
        IUniswapRouter(0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff);
    IUniswapRouter sushiRouter =
        IUniswapRouter(0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506);

    receive() external payable {}

    function setUp() public {
        entrypoint = EntryPoint(
            payable(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)
        );
        paymaster = new BackrunningPaymaster(entrypoint);
        paymaster.deposit{value: 1e18}();

        simpleAccountFactory = new SimpleAccountFactory(entrypoint);
        weenus = new WeenusToken();
    }

    function testBackrun() public {
        // Create two pools, balanced, but tiny
        weenus.drip(address(this), 100e18);
        weenus.approve(address(sushiRouter), type(uint256).max);
        weenus.approve(address(quickswapRouter), type(uint256).max);

        sushiRouter.addLiquidityETH{value: 1e9}(
            address(weenus),
            50e18,
            0,
            0,
            address(this),
            block.timestamp
        );
        quickswapRouter.addLiquidityETH{value: 1e9}(
            address(weenus),
            50e18,
            0,
            0,
            address(this),
            block.timestamp
        );

        // Random cheap user
        uint256 cheapUserPrivateKey = 0x42069080085;
        address cheapUser = vm.addr(cheapUserPrivateKey);

        // Make the smart wallet contract
        SimpleAccount cheapAccount = simpleAccountFactory.createAccount(
            cheapUser,
            0
        );
        uint256 nonce = cheapAccount.getNonce();
        weenus.drip(address(cheapAccount), 100e18);

        // Approve tokens to swap
        UserOperation memory approveUserOps = _getApproveUserOp(
            cheapUserPrivateKey,
            address(cheapAccount),
            nonce
        );

        // User swaps it
        UserOperation memory swapUserOps = _getSwapOps(
            cheapUserPrivateKey,
            address(cheapAccount),
            nonce + 1
        );

        // Entrypoint
        UserOperation[] memory userOpsArr = new UserOperation[](2);
        userOpsArr[0] = approveUserOps;
        userOpsArr[1] = swapUserOps;

        entrypoint.handleOps(userOpsArr, payable(address(0x42)));
    }

    function _getApproveUserOp(
        uint256 eoaPrivateKey,
        address smartWalletContract,
        uint256 nonce
    ) internal view returns (UserOperation memory) {
        bytes memory approveCalldata = abi.encodeWithSelector(
            WeenusToken.approve.selector,
            address(sushiRouter),
            type(uint256).max
        );
        bytes memory callData1 = abi.encodeWithSignature(
            "execute(address,uint256,bytes)",
            address(weenus),
            0,
            approveCalldata
        );
        UserOperation memory approveUserOps = UserOperation({
            sender: address(smartWalletContract),
            nonce: nonce,
            initCode: new bytes(0), // No need to initialize
            callData: callData1,
            callGasLimit: 1000000,
            verificationGasLimit: 1000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 1e9,
            maxPriorityFeePerGas: 1e9,
            paymasterAndData: abi.encodePacked(
                address(paymaster)
            ),
            signature: new bytes(0)
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            eoaPrivateKey,
            ECDSA.toEthSignedMessageHash(
                entrypoint.getUserOpHash(approveUserOps)
            )
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        approveUserOps.signature = signature;

        return approveUserOps;
    }

    function _getSwapOps(
        uint256 eoaPrivateKey,
        address smartContractWallet,
        uint256 nonce
    ) internal view returns (UserOperation memory) {
        address[] memory path = new address[](2);
        path[0] = address(weenus);
        path[1] = sushiRouter.WETH();
        bytes memory swapCalldata = abi.encodeWithSelector(
            IUniswapRouter.swapExactTokensForETH.selector,
            50e18,
            0,
            path,
            smartContractWallet,
            block.timestamp
        );
        bytes memory callData2 = abi.encodeWithSignature(
            "execute(address,uint256,bytes)",
            address(sushiRouter),
            0,
            swapCalldata
        );

        // User sold WEENUS on sushi, causing price to crash on sushi
        // So, we buy WEENUS on sushi and sell on quickswap
        // Flashloan MATIC on quickswap, buy WEENUS on sushi
        // Refund quickswap with weenus

        address pair1 = sushiFactory.getPair(address(weenus), WMATIC);
        address pair2 = quickswapFactory.getPair(address(weenus), WMATIC);

        UserOperation memory swapUserOps = UserOperation({
            sender: smartContractWallet,
            nonce: nonce,
            initCode: new bytes(0), // No need to initialize
            callData: callData2,
            callGasLimit: 1000000,
            verificationGasLimit: 1000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 1e9,
            maxPriorityFeePerGas: 1e9,
            paymasterAndData: abi.encodePacked(
                address(paymaster),
                abi.encode(
                    address(weenus),
                    address(pair1),
                    address(pair2),
                    uint256(0.1e9),
                    address(this)
                )
            ),
            signature: new bytes(0)
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            eoaPrivateKey,
            ECDSA.toEthSignedMessageHash(entrypoint.getUserOpHash(swapUserOps))
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        swapUserOps.signature = signature;

        return swapUserOps;
    }
}
