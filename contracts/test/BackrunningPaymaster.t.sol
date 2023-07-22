// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/BackrunningPaymaster.sol";
import "../src/ISimpleAccountFactory.sol";

interface IWeenus {
    function drip() external;
}

contract BackrunningPaymasterTest is Test {
    BackrunningPaymaster public paymaster;

    address WEENUS = 0x6Db590ae1A42D37f1C2e365cbB7cB7536E5906Ef;

    IEntryPoint entrypoint =
        IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
    ISimpleAccountFactory simpleAccountFactory =
        ISimpleAccountFactory(0x19Fe133a5C488f3D36271402dF49EA48b2a9B9a5);

    receive() external payable {}

    function setUp() public {
        paymaster = new BackrunningPaymaster(entrypoint);
        paymaster.deposit{value: 1e18}();
    }

    function testBackrun() public {
        // Random cheap user
        uint256 cheapUserPrivateKey = 0x4242;
        address cheapUser = vm.addr(cheapUserPrivateKey);

        // Make the contract
        // address sender = simpleAccountFactory.getAddress(cheapUser, 0);
        address sender = simpleAccountFactory.createAccount(cheapUser, 0);
        ISimpleAccount cheapAccount = ISimpleAccount(sender);

        // Woallah
        uint256 nonce = cheapAccount.getNonce();

        // Get drip
        bytes memory dripCallData = abi.encodeWithSignature("drip()");
        bytes memory callData = abi.encodeWithSignature(
            "execute(address,uint256,bytes)",
            WEENUS,
            0,
            dripCallData
        );

        UserOperation memory userOps = UserOperation({
            sender: sender,
            nonce: nonce,
            initCode: new bytes(0), // No need to initialize
            callData: callData,
            callGasLimit: 600000,
            verificationGasLimit: 600000,
            preVerificationGas: 600000,
            maxFeePerGas: 1e9,
            maxPriorityFeePerGas: 1e9,
            paymasterAndData: abi.encodePacked(address(paymaster), uint256(0), uint256(0)),
            signature: new bytes(0)
        });

        bytes32 userOpsHash = entrypoint.getUserOpHash(userOps);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            cheapUserPrivateKey,
            userOpsHash
        );
        bytes memory signature = abi.encodePacked(r, s, v);
        userOps.signature = signature;

        // Label stuff
        vm.label(address(entrypoint), "entrypoint");
        vm.label(address(simpleAccountFactory), "simpleAccountFactory");
        vm.label(address(cheapUser), "cheapUser EOA");
        vm.label(address(sender), "cheapUser smart contract wallet");

        // Entrypoint
        UserOperation[] memory userOpsArr = new UserOperation[](1);
        userOpsArr[0] = userOps;

        vm.prank(address(0x42));
        entrypoint.handleOps(userOpsArr, payable(address(0x42)));
        // entrypoint.simulateHandleOp(userOps, address(0), new bytes(0));
    }
}
