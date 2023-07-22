pragma solidity ^0.8.12;

import "./BasePaymaster.sol";
import "./SimpleAccountFactory.sol";

// : GPL-3.0
pragma solidity ^0.8.12;


// File contracts/utils/Exec.sol

// : LGPL-3.0-only
pragma solidity >=0.7.5 <0.9.0;

// solhint-disable no-inline-assembly

/**
 * Utility functions helpful when making different kinds of contract calls in Solidity.
 */
library Exec {

    function call(
        address to,
        uint256 value,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly {
            success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function staticcall(
        address to,
        bytes memory data,
        uint256 txGas
    ) internal view returns (bool success) {
        assembly {
            success := staticcall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function delegateCall(
        address to,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly {
            success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    // get returned data from last call or calldelegate
    function getReturnData(uint256 maxLen) internal pure returns (bytes memory returnData) {
        assembly {
            let len := returndatasize()
            if gt(len, maxLen) {
                len := maxLen
            }
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }

    // revert with explicit byte array (probably reverted info from call)
    function revertWithData(bytes memory returnData) internal pure {
        assembly {
            revert(add(returnData, 32), mload(returnData))
        }
    }

    function callAndRevert(address to, bytes memory data, uint256 maxLen) internal {
        bool success = call(to,0,data,gasleft());
        if (!success) {
            revertWithData(getReturnData(maxLen));
        }
    }
}

/**
 * helper contract for EntryPoint, to call userOp.initCode from a "neutral" address,
 * which is explicitly not the entryPoint itself.
 */
contract SenderCreator {

    /**
     * call the "initCode" factory to create and return the sender account address
     * @param initCode the initCode value from a UserOp. contains 20 bytes of factory address, followed by calldata
     * @return sender the returned address of the created account, or zero address on failure.
     */
    function createSender(bytes calldata initCode) external returns (address sender) {
        address factory = address(bytes20(initCode[0 : 20]));
        bytes memory initCallData = initCode[20 :];
        bool success;
        /* solhint-disable no-inline-assembly */
        assembly {
            success := call(gas(), factory, 0, add(initCallData, 0x20), mload(initCallData), 0, 32)
            sender := mload(0)
        }
        if (!success) {
            sender = address(0);
        }
    }
}


// File contracts/core/StakeManager.sol

// : GPL-3.0-only
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable not-rely-on-time */
/**
 * manage deposits and stakes.
 * deposit is just a balance used to pay for UserOperations (either by a paymaster or an account)
 * stake is value locked for at least "unstakeDelay" by a paymaster.
 */
abstract contract StakeManager is IStakeManager {

    /// maps paymaster to their deposits and stakes
    mapping(address => DepositInfo) public deposits;

    /// @inheritdoc IStakeManager
    function getDepositInfo(address account) public view returns (DepositInfo memory info) {
        return deposits[account];
    }

    // internal method to return just the stake info
    function _getStakeInfo(address addr) internal view returns (StakeInfo memory info) {
        DepositInfo storage depositInfo = deposits[addr];
        info.stake = depositInfo.stake;
        info.unstakeDelaySec = depositInfo.unstakeDelaySec;
    }

    /// return the deposit (for gas payment) of the account
    function balanceOf(address account) public view returns (uint256) {
        return deposits[account].deposit;
    }

    receive() external payable {
        depositTo(msg.sender);
    }

    function _incrementDeposit(address account, uint256 amount) internal {
        DepositInfo storage info = deposits[account];
        uint256 newAmount = info.deposit + amount;
        require(newAmount <= type(uint112).max, "deposit overflow");
        info.deposit = uint112(newAmount);
    }

    /**
     * add to the deposit of the given account
     */
    function depositTo(address account) public payable {
        _incrementDeposit(account, msg.value);
        DepositInfo storage info = deposits[account];
        emit Deposited(account, info.deposit);
    }

    /**
     * add to the account's stake - amount and delay
     * any pending unstake is first cancelled.
     * @param unstakeDelaySec the new lock duration before the deposit can be withdrawn.
     */
    function addStake(uint32 unstakeDelaySec) public payable {
        DepositInfo storage info = deposits[msg.sender];
        require(unstakeDelaySec > 0, "must specify unstake delay");
        require(unstakeDelaySec >= info.unstakeDelaySec, "cannot decrease unstake time");
        uint256 stake = info.stake + msg.value;
        require(stake > 0, "no stake specified");
        require(stake <= type(uint112).max, "stake overflow");
        deposits[msg.sender] = DepositInfo(
            info.deposit,
            true,
            uint112(stake),
            unstakeDelaySec,
            0
        );
        emit StakeLocked(msg.sender, stake, unstakeDelaySec);
    }

    /**
     * attempt to unlock the stake.
     * the value can be withdrawn (using withdrawStake) after the unstake delay.
     */
    function unlockStake() external {
        DepositInfo storage info = deposits[msg.sender];
        require(info.unstakeDelaySec != 0, "not staked");
        require(info.staked, "already unstaking");
        uint48 withdrawTime = uint48(block.timestamp) + info.unstakeDelaySec;
        info.withdrawTime = withdrawTime;
        info.staked = false;
        emit StakeUnlocked(msg.sender, withdrawTime);
    }


    /**
     * withdraw from the (unlocked) stake.
     * must first call unlockStake and wait for the unstakeDelay to pass
     * @param withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external {
        DepositInfo storage info = deposits[msg.sender];
        uint256 stake = info.stake;
        require(stake > 0, "No stake to withdraw");
        require(info.withdrawTime > 0, "must call unlockStake() first");
        require(info.withdrawTime <= block.timestamp, "Stake withdrawal is not due");
        info.unstakeDelaySec = 0;
        info.withdrawTime = 0;
        info.stake = 0;
        emit StakeWithdrawn(msg.sender, withdrawAddress, stake);
        (bool success,) = withdrawAddress.call{value : stake}("");
        require(success, "failed to withdraw stake");
    }

    /**
     * withdraw from the deposit.
     * @param withdrawAddress the address to send withdrawn value.
     * @param withdrawAmount the amount to withdraw.
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external {
        DepositInfo storage info = deposits[msg.sender];
        require(withdrawAmount <= info.deposit, "Withdraw amount too large");
        info.deposit = uint112(info.deposit - withdrawAmount);
        emit Withdrawn(msg.sender, withdrawAddress, withdrawAmount);
        (bool success,) = withdrawAddress.call{value : withdrawAmount}("");
        require(success, "failed to withdraw");
    }
}


// File contracts/core/NonceManager.sol

// : GPL-3.0
pragma solidity ^0.8.12;

/**
 * nonce management functionality
 */
contract NonceManager is INonceManager {

    /**
     * The next valid sequence number for a given nonce key.
     */
    mapping(address => mapping(uint192 => uint256)) public nonceSequenceNumber;

    function getNonce(address sender, uint192 key)
    public view override returns (uint256 nonce) {
        return nonceSequenceNumber[sender][key] | (uint256(key) << 64);
    }

    // allow an account to manually increment its own nonce.
    // (mainly so that during construction nonce can be made non-zero,
    // to "absorb" the gas cost of first nonce increment to 1st transaction (construction),
    // not to 2nd transaction)
    function incrementNonce(uint192 key) public override {
        nonceSequenceNumber[msg.sender][key]++;
    }

    /**
     * validate nonce uniqueness for this account.
     * called just after validateUserOp()
     */
    function _validateAndUpdateNonce(address sender, uint256 nonce) internal returns (bool) {

        uint192 key = uint192(nonce >> 64);
        uint64 seq = uint64(nonce);
        return nonceSequenceNumber[sender][key]++ == seq;
    }

}


// File @openzeppelin/contracts/security/ReentrancyGuard.sol@v4.9.2

// : MIT
// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }
}


// File contracts/core/EntryPoint.sol

/**
 ** Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 ** Only one instance required on each chain.
 **/
// : GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */








contract EntryPoint is IEntryPoint, StakeManager, NonceManager, ReentrancyGuard {

    using UserOperationLib for UserOperation;

    SenderCreator private immutable senderCreator = new SenderCreator();

    // internal value used during simulation: need to query aggregator.
    address private constant SIMULATE_FIND_AGGREGATOR = address(1);

    // marker for inner call revert on out of gas
    bytes32 private constant INNER_OUT_OF_GAS = hex'deaddead';

    uint256 private constant REVERT_REASON_MAX_LEN = 2048;

    /**
     * for simulation purposes, validateUserOp (and validatePaymasterUserOp) must return this value
     * in case of signature failure, instead of revert.
     */
    uint256 public constant SIG_VALIDATION_FAILED = 1;

    /**
     * compensate the caller's beneficiary address with the collected fees of all UserOperations.
     * @param beneficiary the address to receive the fees
     * @param amount amount to transfer.
     */
    function _compensate(address payable beneficiary, uint256 amount) internal {
        require(beneficiary != address(0), "AA90 invalid beneficiary");
        (bool success,) = beneficiary.call{value : amount}("");
        require(success, "AA91 failed send to beneficiary");
    }

    /**
     * execute a user op
     * @param opIndex index into the opInfo array
     * @param userOp the userOp to execute
     * @param opInfo the opInfo filled by validatePrepayment for this userOp.
     * @return collected the total amount this userOp paid.
     */
    function _executeUserOp(uint256 opIndex, UserOperation calldata userOp, UserOpInfo memory opInfo) private returns (uint256 collected) {
        uint256 preGas = gasleft();
        bytes memory context = getMemoryBytesFromOffset(opInfo.contextOffset);

        try this.innerHandleOp(userOp.callData, opInfo, context) returns (uint256 _actualGasCost) {
            collected = _actualGasCost;
        } catch {
            bytes32 innerRevertCode;
            assembly {
                returndatacopy(0, 0, 32)
                innerRevertCode := mload(0)
            }
            // handleOps was called with gas limit too low. abort entire bundle.
            if (innerRevertCode == INNER_OUT_OF_GAS) {
                //report paymaster, since if it is not deliberately caused by the bundler,
                // it must be a revert caused by paymaster.
                revert FailedOp(opIndex, "AA95 out of gas");
            }

            uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
            collected = _handlePostOp(opIndex, IPaymaster.PostOpMode.postOpReverted, opInfo, context, actualGas);
        }
    }

    /**
     * Execute a batch of UserOperations.
     * no signature aggregator is used.
     * if any account requires an aggregator (that is, it returned an aggregator when
     * performing simulateValidation), then handleAggregatedOps() must be used instead.
     * @param ops the operations to execute
     * @param beneficiary the address to receive the fees
     */
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) public nonReentrant {

        uint256 opslen = ops.length;
        UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);

    unchecked {
        for (uint256 i = 0; i < opslen; i++) {
            UserOpInfo memory opInfo = opInfos[i];
            (uint256 validationData, uint256 pmValidationData) = _validatePrepayment(i, ops[i], opInfo);
            _validateAccountAndPaymasterValidationData(i, validationData, pmValidationData, address(0));
        }

        uint256 collected = 0;
        emit BeforeExecution();

        for (uint256 i = 0; i < opslen; i++) {
            collected += _executeUserOp(i, ops[i], opInfos[i]);
        }

        _compensate(beneficiary, collected);
    } //unchecked
    }

    /**
     * Execute a batch of UserOperation with Aggregators
     * @param opsPerAggregator the operations to execute, grouped by aggregator (or address(0) for no-aggregator accounts)
     * @param beneficiary the address to receive the fees
     */
    function handleAggregatedOps(
        UserOpsPerAggregator[] calldata opsPerAggregator,
        address payable beneficiary
    ) public nonReentrant {

        uint256 opasLen = opsPerAggregator.length;
        uint256 totalOps = 0;
        for (uint256 i = 0; i < opasLen; i++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[i];
            UserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;

            //address(1) is special marker of "signature error"
            require(address(aggregator) != address(1), "AA96 invalid aggregator");

            if (address(aggregator) != address(0)) {
                // solhint-disable-next-line no-empty-blocks
                try aggregator.validateSignatures(ops, opa.signature) {}
                catch {
                    revert SignatureValidationFailed(address(aggregator));
                }
            }

            totalOps += ops.length;
        }

        UserOpInfo[] memory opInfos = new UserOpInfo[](totalOps);

        emit BeforeExecution();

        uint256 opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            UserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;

            uint256 opslen = ops.length;
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[opIndex];
                (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(opIndex, ops[i], opInfo);
                _validateAccountAndPaymasterValidationData(i, validationData, paymasterValidationData, address(aggregator));
                opIndex++;
            }
        }

        uint256 collected = 0;
        opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            emit SignatureAggregatorChanged(address(opa.aggregator));
            UserOperation[] calldata ops = opa.userOps;
            uint256 opslen = ops.length;

            for (uint256 i = 0; i < opslen; i++) {
                collected += _executeUserOp(opIndex, ops[i], opInfos[opIndex]);
                opIndex++;
            }
        }
        emit SignatureAggregatorChanged(address(0));

        _compensate(beneficiary, collected);
    }

    /// @inheritdoc IEntryPoint
    function simulateHandleOp(UserOperation calldata op, address target, bytes calldata targetCallData) external override {

        UserOpInfo memory opInfo;
        _simulationOnlyValidations(op);
        (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(0, op, opInfo);
        ValidationData memory data = _intersectTimeRange(validationData, paymasterValidationData);

        numberMarker();
        uint256 paid = _executeUserOp(0, op, opInfo);
        numberMarker();
        bool targetSuccess;
        bytes memory targetResult;
        if (target != address(0)) {
            (targetSuccess, targetResult) = target.call(targetCallData);
        }
        revert ExecutionResult(opInfo.preOpGas, paid, data.validAfter, data.validUntil, targetSuccess, targetResult);
    }


    // A memory copy of UserOp static fields only.
    // Excluding: callData, initCode and signature. Replacing paymasterAndData with paymaster.
    struct MemoryUserOp {
        address sender;
        uint256 nonce;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        address paymaster;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
    }

    struct UserOpInfo {
        MemoryUserOp mUserOp;
        bytes32 userOpHash;
        uint256 prefund;
        uint256 contextOffset;
        uint256 preOpGas;
    }

    /**
     * inner function to handle a UserOperation.
     * Must be declared "external" to open a call context, but it can only be called by handleOps.
     */
    function innerHandleOp(bytes memory callData, UserOpInfo memory opInfo, bytes calldata context) external returns (uint256 actualGasCost) {
        uint256 preGas = gasleft();
        require(msg.sender == address(this), "AA92 internal call only");
        MemoryUserOp memory mUserOp = opInfo.mUserOp;

        uint callGasLimit = mUserOp.callGasLimit;
    unchecked {
        // handleOps was called with gas limit too low. abort entire bundle.
        if (gasleft() < callGasLimit + mUserOp.verificationGasLimit + 5000) {
            assembly {
                mstore(0, INNER_OUT_OF_GAS)
                revert(0, 32)
            }
        }
    }

        IPaymaster.PostOpMode mode = IPaymaster.PostOpMode.opSucceeded;
        if (callData.length > 0) {
            bool success = Exec.call(mUserOp.sender, 0, callData, callGasLimit);
            if (!success) {
                bytes memory result = Exec.getReturnData(REVERT_REASON_MAX_LEN);
                if (result.length > 0) {
                    emit UserOperationRevertReason(opInfo.userOpHash, mUserOp.sender, mUserOp.nonce, result);
                }
                mode = IPaymaster.PostOpMode.opReverted;
            }
        }

    unchecked {
        uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
        //note: opIndex is ignored (relevant only if mode==postOpReverted, which is only possible outside of innerHandleOp)
        return _handlePostOp(0, mode, opInfo, context, actualGas);
    }
    }

    /**
     * generate a request Id - unique identifier for this request.
     * the request ID is a hash over the content of the userOp (except the signature), the entrypoint and the chainid.
     */
    function getUserOpHash(UserOperation calldata userOp) public view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }

    /**
     * copy general fields from userOp into the memory opInfo structure.
     */
    function _copyUserOpToMemory(UserOperation calldata userOp, MemoryUserOp memory mUserOp) internal pure {
        mUserOp.sender = userOp.sender;
        mUserOp.nonce = userOp.nonce;
        mUserOp.callGasLimit = userOp.callGasLimit;
        mUserOp.verificationGasLimit = userOp.verificationGasLimit;
        mUserOp.preVerificationGas = userOp.preVerificationGas;
        mUserOp.maxFeePerGas = userOp.maxFeePerGas;
        mUserOp.maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes calldata paymasterAndData = userOp.paymasterAndData;
        if (paymasterAndData.length > 0) {
            require(paymasterAndData.length >= 20, "AA93 invalid paymasterAndData");
            mUserOp.paymaster = address(bytes20(paymasterAndData[: 20]));
        } else {
            mUserOp.paymaster = address(0);
        }
    }

    /**
     * Simulate a call to account.validateUserOp and paymaster.validatePaymasterUserOp.
     * @dev this method always revert. Successful result is ValidationResult error. other errors are failures.
     * @dev The node must also verify it doesn't use banned opcodes, and that it doesn't reference storage outside the account's data.
     * @param userOp the user operation to validate.
     */
    function simulateValidation(UserOperation calldata userOp) external {
        UserOpInfo memory outOpInfo;

        _simulationOnlyValidations(userOp);
        (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(0, userOp, outOpInfo);
        StakeInfo memory paymasterInfo = _getStakeInfo(outOpInfo.mUserOp.paymaster);
        StakeInfo memory senderInfo = _getStakeInfo(outOpInfo.mUserOp.sender);
        StakeInfo memory factoryInfo;
        {
            bytes calldata initCode = userOp.initCode;
            address factory = initCode.length >= 20 ? address(bytes20(initCode[0 : 20])) : address(0);
            factoryInfo = _getStakeInfo(factory);
        }

        ValidationData memory data = _intersectTimeRange(validationData, paymasterValidationData);
        address aggregator = data.aggregator;
        bool sigFailed = aggregator == address(1);
        ReturnInfo memory returnInfo = ReturnInfo(outOpInfo.preOpGas, outOpInfo.prefund,
            sigFailed, data.validAfter, data.validUntil, getMemoryBytesFromOffset(outOpInfo.contextOffset));

        if (aggregator != address(0) && aggregator != address(1)) {
            AggregatorStakeInfo memory aggregatorInfo = AggregatorStakeInfo(aggregator, _getStakeInfo(aggregator));
            revert ValidationResultWithAggregation(returnInfo, senderInfo, factoryInfo, paymasterInfo, aggregatorInfo);
        }
        revert ValidationResult(returnInfo, senderInfo, factoryInfo, paymasterInfo);

    }

    function _getRequiredPrefund(MemoryUserOp memory mUserOp) internal pure returns (uint256 requiredPrefund) {
    unchecked {
        //when using a Paymaster, the verificationGasLimit is used also to as a limit for the postOp call.
        // our security model might call postOp eventually twice
        uint256 mul = mUserOp.paymaster != address(0) ? 3 : 1;
        uint256 requiredGas = mUserOp.callGasLimit + mUserOp.verificationGasLimit * mul + mUserOp.preVerificationGas;

        requiredPrefund = requiredGas * mUserOp.maxFeePerGas;
    }
    }

    // create the sender's contract if needed.
    function _createSenderIfNeeded(uint256 opIndex, UserOpInfo memory opInfo, bytes calldata initCode) internal {
        if (initCode.length != 0) {
            address sender = opInfo.mUserOp.sender;
            if (sender.code.length != 0) revert FailedOp(opIndex, "AA10 sender already constructed");
            address sender1 = senderCreator.createSender{gas : opInfo.mUserOp.verificationGasLimit}(initCode);
            if (sender1 == address(0)) revert FailedOp(opIndex, "AA13 initCode failed or OOG");
            if (sender1 != sender) revert FailedOp(opIndex, "AA14 initCode must return sender");
            if (sender1.code.length == 0) revert FailedOp(opIndex, "AA15 initCode must create sender");
            address factory = address(bytes20(initCode[0 : 20]));
            emit AccountDeployed(opInfo.userOpHash, sender, factory, opInfo.mUserOp.paymaster);
        }
    }

    /**
     * Get counterfactual sender address.
     *  Calculate the sender contract address that will be generated by the initCode and salt in the UserOperation.
     * this method always revert, and returns the address in SenderAddressResult error
     * @param initCode the constructor code to be passed into the UserOperation.
     */
    function getSenderAddress(bytes calldata initCode) public {
        address sender = senderCreator.createSender(initCode);
        revert SenderAddressResult(sender);
    }

    function _simulationOnlyValidations(UserOperation calldata userOp) internal view {
        // solhint-disable-next-line no-empty-blocks
        try this._validateSenderAndPaymaster(userOp.initCode, userOp.sender, userOp.paymasterAndData) {}
        catch Error(string memory revertReason) {
            if (bytes(revertReason).length != 0) {
                revert FailedOp(0, revertReason);
            }
        }
    }

    /**
    * Called only during simulation.
    * This function always reverts to prevent warm/cold storage differentiation in simulation vs execution.
    */
    function _validateSenderAndPaymaster(bytes calldata initCode, address sender, bytes calldata paymasterAndData) external view {
        if (initCode.length == 0 && sender.code.length == 0) {
            // it would revert anyway. but give a meaningful message
            revert("AA20 account not deployed");
        }
        if (paymasterAndData.length >= 20) {
            address paymaster = address(bytes20(paymasterAndData[0 : 20]));
            if (paymaster.code.length == 0) {
                // it would revert anyway. but give a meaningful message
                revert("AA30 paymaster not deployed");
            }
        }
        // always revert
        revert("");
    }

    /**
     * call account.validateUserOp.
     * revert (with FailedOp) in case validateUserOp reverts, or account didn't send required prefund.
     * decrement account's deposit if needed
     */
    function _validateAccountPrepayment(uint256 opIndex, UserOperation calldata op, UserOpInfo memory opInfo, uint256 requiredPrefund)
    internal returns (uint256 gasUsedByValidateAccountPrepayment, uint256 validationData) {
    unchecked {
        uint256 preGas = gasleft();
        MemoryUserOp memory mUserOp = opInfo.mUserOp;
        address sender = mUserOp.sender;
        _createSenderIfNeeded(opIndex, opInfo, op.initCode);
        address paymaster = mUserOp.paymaster;
        numberMarker();
        uint256 missingAccountFunds = 0;
        if (paymaster == address(0)) {
            uint256 bal = balanceOf(sender);
            missingAccountFunds = bal > requiredPrefund ? 0 : requiredPrefund - bal;
        }
        try IAccount(sender).validateUserOp{gas : mUserOp.verificationGasLimit}(op, opInfo.userOpHash, missingAccountFunds)
        returns (uint256 _validationData) {
            validationData = _validationData;
        } catch Error(string memory revertReason) {
            revert FailedOp(opIndex, string.concat("AA23 reverted: ", revertReason));
        } catch {
            revert FailedOp(opIndex, "AA23 reverted (or OOG)");
        }
        if (paymaster == address(0)) {
            DepositInfo storage senderInfo = deposits[sender];
            uint256 deposit = senderInfo.deposit;
            if (requiredPrefund > deposit) {
                revert FailedOp(opIndex, "AA21 didn't pay prefund");
            }
            senderInfo.deposit = uint112(deposit - requiredPrefund);
        }
        gasUsedByValidateAccountPrepayment = preGas - gasleft();
    }
    }

    /**
     * In case the request has a paymaster:
     * Validate paymaster has enough deposit.
     * Call paymaster.validatePaymasterUserOp.
     * Revert with proper FailedOp in case paymaster reverts.
     * Decrement paymaster's deposit
     */
    function _validatePaymasterPrepayment(uint256 opIndex, UserOperation calldata op, UserOpInfo memory opInfo, uint256 requiredPreFund, uint256 gasUsedByValidateAccountPrepayment)
    internal returns (bytes memory context, uint256 validationData) {
    unchecked {
        MemoryUserOp memory mUserOp = opInfo.mUserOp;
        uint256 verificationGasLimit = mUserOp.verificationGasLimit;
        require(verificationGasLimit > gasUsedByValidateAccountPrepayment, "AA41 too little verificationGas");
        uint256 gas = verificationGasLimit - gasUsedByValidateAccountPrepayment;

        address paymaster = mUserOp.paymaster;
        DepositInfo storage paymasterInfo = deposits[paymaster];
        uint256 deposit = paymasterInfo.deposit;
        if (deposit < requiredPreFund) {
            revert FailedOp(opIndex, "AA31 paymaster deposit too low");
        }
        paymasterInfo.deposit = uint112(deposit - requiredPreFund);
        try IPaymaster(paymaster).validatePaymasterUserOp{gas : gas}(op, opInfo.userOpHash, requiredPreFund) returns (bytes memory _context, uint256 _validationData){
            context = _context;
            validationData = _validationData;
        } catch Error(string memory revertReason) {
            revert FailedOp(opIndex, string.concat("AA33 reverted: ", revertReason));
        } catch {
            revert FailedOp(opIndex, "AA33 reverted (or OOG)");
        }
    }
    }

    /**
     * revert if either account validationData or paymaster validationData is expired
     */
    function _validateAccountAndPaymasterValidationData(uint256 opIndex, uint256 validationData, uint256 paymasterValidationData, address expectedAggregator) internal view {
        (address aggregator, bool outOfTimeRange) = _getValidationData(validationData);
        if (expectedAggregator != aggregator) {
            revert FailedOp(opIndex, "AA24 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA22 expired or not due");
        }
        //pmAggregator is not a real signature aggregator: we don't have logic to handle it as address.
        // non-zero address means that the paymaster fails due to some signature check (which is ok only during estimation)
        address pmAggregator;
        (pmAggregator, outOfTimeRange) = _getValidationData(paymasterValidationData);
        if (pmAggregator != address(0)) {
            revert FailedOp(opIndex, "AA34 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA32 paymaster expired or not due");
        }
    }

    function _getValidationData(uint256 validationData) internal view returns (address aggregator, bool outOfTimeRange) {
        if (validationData == 0) {
            return (address(0), false);
        }
        ValidationData memory data = _parseValidationData(validationData);
        // solhint-disable-next-line not-rely-on-time
        outOfTimeRange = block.timestamp > data.validUntil || block.timestamp < data.validAfter;
        aggregator = data.aggregator;
    }

    /**
     * validate account and paymaster (if defined).
     * also make sure total validation doesn't exceed verificationGasLimit
     * this method is called off-chain (simulateValidation()) and on-chain (from handleOps)
     * @param opIndex the index of this userOp into the "opInfos" array
     * @param userOp the userOp to validate
     */
    function _validatePrepayment(uint256 opIndex, UserOperation calldata userOp, UserOpInfo memory outOpInfo)
    private returns (uint256 validationData, uint256 paymasterValidationData) {

        uint256 preGas = gasleft();
        MemoryUserOp memory mUserOp = outOpInfo.mUserOp;
        _copyUserOpToMemory(userOp, mUserOp);
        outOpInfo.userOpHash = getUserOpHash(userOp);

        // validate all numeric values in userOp are well below 128 bit, so they can safely be added
        // and multiplied without causing overflow
        uint256 maxGasValues = mUserOp.preVerificationGas | mUserOp.verificationGasLimit | mUserOp.callGasLimit |
        userOp.maxFeePerGas | userOp.maxPriorityFeePerGas;
        require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

        uint256 gasUsedByValidateAccountPrepayment;
        (uint256 requiredPreFund) = _getRequiredPrefund(mUserOp);
        (gasUsedByValidateAccountPrepayment, validationData) = _validateAccountPrepayment(opIndex, userOp, outOpInfo, requiredPreFund);

        if (!_validateAndUpdateNonce(mUserOp.sender, mUserOp.nonce)) {
            revert FailedOp(opIndex, "AA25 invalid account nonce");
        }

        //a "marker" where account opcode validation is done and paymaster opcode validation is about to start
        // (used only by off-chain simulateValidation)
        numberMarker();

        bytes memory context;
        if (mUserOp.paymaster != address(0)) {
            (context, paymasterValidationData) = _validatePaymasterPrepayment(opIndex, userOp, outOpInfo, requiredPreFund, gasUsedByValidateAccountPrepayment);
        }
    unchecked {
        uint256 gasUsed = preGas - gasleft();

        if (userOp.verificationGasLimit < gasUsed) {
            revert FailedOp(opIndex, "AA40 over verificationGasLimit");
        }
        outOpInfo.prefund = requiredPreFund;
        outOpInfo.contextOffset = getOffsetOfMemoryBytes(context);
        outOpInfo.preOpGas = preGas - gasleft() + userOp.preVerificationGas;
    }
    }

    /**
     * process post-operation.
     * called just after the callData is executed.
     * if a paymaster is defined and its validation returned a non-empty context, its postOp is called.
     * the excess amount is refunded to the account (or paymaster - if it was used in the request)
     * @param opIndex index in the batch
     * @param mode - whether is called from innerHandleOp, or outside (postOpReverted)
     * @param opInfo userOp fields and info collected during validation
     * @param context the context returned in validatePaymasterUserOp
     * @param actualGas the gas used so far by this user operation
     */
    function _handlePostOp(uint256 opIndex, IPaymaster.PostOpMode mode, UserOpInfo memory opInfo, bytes memory context, uint256 actualGas) private returns (uint256 actualGasCost) {
        uint256 preGas = gasleft();
    unchecked {
        address refundAddress;
        MemoryUserOp memory mUserOp = opInfo.mUserOp;
        uint256 gasPrice = getUserOpGasPrice(mUserOp);

        address paymaster = mUserOp.paymaster;
        if (paymaster == address(0)) {
            refundAddress = mUserOp.sender;
        } else {
            refundAddress = paymaster;
            if (context.length > 0) {
                actualGasCost = actualGas * gasPrice;
                if (mode != IPaymaster.PostOpMode.postOpReverted) {
                    IPaymaster(paymaster).postOp{gas : mUserOp.verificationGasLimit}(mode, context, actualGasCost);
                } else {
                    // solhint-disable-next-line no-empty-blocks
                    try IPaymaster(paymaster).postOp{gas : mUserOp.verificationGasLimit}(mode, context, actualGasCost) {}
                    catch Error(string memory reason) {
                        revert FailedOp(opIndex, string.concat("AA50 postOp reverted: ", reason));
                    }
                    catch {
                        revert FailedOp(opIndex, "AA50 postOp revert");
                    }
                }
            }
        }
        actualGas += preGas - gasleft();
        actualGasCost = actualGas * gasPrice;
        if (opInfo.prefund < actualGasCost) {
            revert FailedOp(opIndex, "AA51 prefund below actualGasCost");
        }
        uint256 refund = opInfo.prefund - actualGasCost;
        _incrementDeposit(refundAddress, refund);
        bool success = mode == IPaymaster.PostOpMode.opSucceeded;
        emit UserOperationEvent(opInfo.userOpHash, mUserOp.sender, mUserOp.paymaster, mUserOp.nonce, success, actualGasCost, actualGas);
    } // unchecked
    }

    /**
     * the gas price this UserOp agrees to pay.
     * relayer/block builder might submit the TX with higher priorityFee, but the user should not
     */
    function getUserOpGasPrice(MemoryUserOp memory mUserOp) internal view returns (uint256) {
    unchecked {
        uint256 maxFeePerGas = mUserOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = mUserOp.maxPriorityFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            //legacy mode (for networks that don't support basefee opcode)
            return maxFeePerGas;
        }
        return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
    }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function getOffsetOfMemoryBytes(bytes memory data) internal pure returns (uint256 offset) {
        assembly {offset := data}
    }

    function getMemoryBytesFromOffset(uint256 offset) internal pure returns (bytes memory data) {
        assembly {data := offset}
    }

    //place the NUMBER opcode in the code.
    // this is used as a marker during simulation, as this OP is completely banned from the simulated code of the
    // account and paymaster.
    function numberMarker() internal view {
        assembly {mstore(0, number())}
    }
}
