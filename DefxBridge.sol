// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import "./library/ValidatorLibrary.sol";
import "./library/SignatureLibrary.sol";
import "./library/Utils.sol";

import "./common/Structs.sol";
import "./common/Events.sol";
import "./common/Errors.sol";

contract DefxBridge is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for ERC20PermitUpgradeable;

    ERC20PermitUpgradeable[] public enabledTokens;
    mapping(address => bool) public enabledTokensMap;

    bytes32 public domainSeparator;
    uint64 public withdrawalDisputePeriodSeconds;
    uint64 public validatorSetDisputePeriodSeconds;
    uint64 public blockDurationMillis;

    mapping(string => uint64) public operationNonce; // nonce for methods that are prone to replay attacks

    ValidatorSet private validatorsHotWallets;
    ValidatorSet private validatorsColdWallets;
    uint64 public cumulativeValidatorPower;
    PendingValidatorSetUpdate public pendingValidatorSetUpdate;

    mapping(bytes32 => WithdrawalData) public requestedWithdrawals;
    mapping(bytes32 => bool) public finalizedWithdrawals;
    mapping(bytes32 => bool) public invalidatedWithdrawals;

    uint64 public lockerThreshold;
    mapping(address => bool) public lockers;
    address[] public lockersVotingLock;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _initialOwner,
        address[] calldata tokenContractsUpdate,
        uint64 _withdrawalDisputePeriodSeconds,
        uint64 _validatorSetDisputePeriodSeconds,
        uint64 _blockDurationMillis,
        uint64 _lockerThreshold,
        ValidatorUpdateRequest calldata _initialValidatorWallets
    ) public initializer {
        __Ownable_init(_initialOwner);
        __UUPSUpgradeable_init();
        __Pausable_init();
        // initialize the ERC20 tokens used to deposit/withdraw
        _updateTokenContracts(tokenContractsUpdate);

        domainSeparator = SignatureLibrary.makeDomainSeparator();

        withdrawalDisputePeriodSeconds = _withdrawalDisputePeriodSeconds;
        validatorSetDisputePeriodSeconds = _validatorSetDisputePeriodSeconds;
        blockDurationMillis = _blockDurationMillis;
        lockerThreshold = _lockerThreshold;

        // initialize the validators
        _updateValidatorSet(
            _initialValidatorWallets.coldValidatorSet,
            _initialValidatorWallets.hotValidatorSet,
            _initialValidatorWallets.powers
        );
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    function _updateValidatorSet(
        address[] memory coldValidatorSet,
        address[] memory hotValidatorSet,
        uint64[] memory powers
    ) internal {
        ValidatorSet memory oldValidatorsColdWallets = validatorsColdWallets;

        validatorsHotWallets = ValidatorSet(hotValidatorSet, powers);
        validatorsColdWallets = ValidatorSet(coldValidatorSet, powers);

        uint64 cumulativePower;
        for (uint256 i = 0; i < powers.length; i++) {
            cumulativePower += powers[i];
        }
        cumulativeValidatorPower = cumulativePower;

        // remove old validators from lockers
        for (
            uint256 i = 0;
            i < oldValidatorsColdWallets.validators.length;
            i++
        ) {
            lockers[oldValidatorsColdWallets.validators[i]] = false;
        }

        // add new validators to lockers
        for (uint256 i = 0; i < validatorsColdWallets.validators.length; i++) {
            lockers[validatorsColdWallets.validators[i]] = true;
        }

        emit FinalizedValidatorSetUpdate(
            pendingValidatorSetUpdate.epochTimestampInSeconds,
            pendingValidatorSetUpdate.hotValidatorSet,
            pendingValidatorSetUpdate.coldValidatorSet,
            pendingValidatorSetUpdate.powers
        );
        pendingValidatorSetUpdate = PendingValidatorSetUpdate({
            epochTimestampInSeconds: 0,
            updateEpochTimestampInSeconds: 0,
            updateBlockNumber: Utils.getCurrentBlockNumber(),
            hotValidatorSet: hotValidatorSet,
            coldValidatorSet: coldValidatorSet,
            powers: powers
        });
    }

    function _updateTokenContracts(
        address[] memory contractAddresses
    ) internal {
        uint256 noOfNewTokens = contractAddresses.length;
        if (noOfNewTokens == 0) {
            revert NotEnoughTokensToUpdate();
        }

        ERC20PermitUpgradeable[]
            memory contracts = new ERC20PermitUpgradeable[](noOfNewTokens);

        for (uint256 i = 0; i < noOfNewTokens; i++) {
            if (contractAddresses[i] == address(0)) {
                revert InvalidTokenContract();
            }
            contracts[i] = ERC20PermitUpgradeable(contractAddresses[i]);
        }

        // disable the old tokens
        uint256 noOfOldEnabledTokens = enabledTokens.length;
        for (uint256 i = 0; i < noOfOldEnabledTokens; i++) {
            enabledTokensMap[address(enabledTokens[i])] = false;
        }

        // enable the new tokens
        for (uint256 i = 0; i < noOfNewTokens; i++) {
            enabledTokensMap[address(contracts[i])] = true;
        }

        enabledTokens = contracts;

        emit ChangedTokenContract(contractAddresses);
    }

    function _verifyAndIncrementNonce(
        string memory operation,
        uint64 nonce
    ) internal {
        if (operationNonce[operation] != nonce) {
            revert InvalidNonce();
        }
        operationNonce[operation]++;
    }

    /** Pausing **/
    function pause() external whenNotPaused {
        // validate the sender is a locker
        if (!lockers[msg.sender]) {
            revert NotALocker();
        }

        // check if the locker has already voted to pause
        for (uint256 i = 0; i < lockersVotingLock.length; i++) {
            if (lockersVotingLock[i] == msg.sender) {
                revert AlreadyVoted();
            }
        }

        // register the locker vote
        lockersVotingLock.push(msg.sender);

        // check if the locker threshold is met
        if (lockersVotingLock.length >= lockerThreshold) {
            _pause();
            emit ContractPaused();
        }
    }

    function unpause() external whenPaused {
        // validate the sender is a locker
        if (!lockers[msg.sender]) {
            revert NotALocker();
        }

        // check if the locker has voted to pause before since same lockers can only vote to unpause
        bool found = false;
        for (uint256 i = 0; i < lockersVotingLock.length; i++) {
            if (lockersVotingLock[i] == msg.sender) {
                found = true;
                break;
            }
        }
        if (!found) {
            revert NotVotedPreviously();
        }

        // remove the locker from the list
        for (uint256 i = 0; i < lockersVotingLock.length; i++) {
            if (lockersVotingLock[i] == msg.sender) {
                lockersVotingLock[i] = lockersVotingLock[
                    lockersVotingLock.length - 1
                ];
                lockersVotingLock.pop();
                break;
            }
        }

        // check if all lockers voted to unpause
        if (lockersVotingLock.length == 0) {
            _unpause();
            emit ContractResumed();
        }
    }

    /** End Pausing **/

    /** Config mutations **/
    function updateTokenContracts(
        address[] calldata tokenContractsUpdate,
        uint64 nonce,
        Signature[] calldata signatures
    ) external {
        // validate the nonce
        _verifyAndIncrementNonce("updateTokenContracts", nonce);

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(
                abi.encode("updateTokenContracts", tokenContractsUpdate, nonce)
            ),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsColdWallets
        );

        // update the token contracts
        _updateTokenContracts(tokenContractsUpdate);
    }

    function modifyLocker(
        address locker,
        bool isEnabled,
        uint64 nonce,
        Signature[] calldata signatures
    ) external {
        // validate the nonce
        _verifyAndIncrementNonce("modifyLocker", nonce);

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(abi.encode("modifyLocker", locker, isEnabled, nonce)),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsColdWallets
        );

        // modify the locker
        lockers[locker] = isEnabled;
        emit ModifiedLocker(locker, isEnabled);
    }

    function changeBlockDurationMillis(
        uint64 newBlockDurationMillis,
        uint64 nonce,
        Signature[] calldata signatures
    ) external {
        // validate the nonce
        _verifyAndIncrementNonce("changeBlockDurationMillis", nonce);

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(
                abi.encode(
                    "changeBlockDurationMillis",
                    newBlockDurationMillis,
                    nonce
                )
            ),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsColdWallets
        );

        uint64 oldBlockDurationMillis = blockDurationMillis;
        blockDurationMillis = newBlockDurationMillis;
        emit ChangedBlockDurationMillis(
            oldBlockDurationMillis,
            newBlockDurationMillis
        );
    }

    function changeWithdrawalDisputePeriodSeconds(
        uint64 newDisputePeriodSeconds,
        uint64 nonce,
        Signature[] calldata signatures
    ) external {
        // validate the nonce
        _verifyAndIncrementNonce("changeWithdrawalDisputePeriodSeconds", nonce);

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(
                abi.encode(
                    "changeWithdrawalDisputePeriodSeconds",
                    newDisputePeriodSeconds,
                    nonce
                )
            ),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsColdWallets
        );

        uint64 oldDisputePeriodSeconds = withdrawalDisputePeriodSeconds;
        withdrawalDisputePeriodSeconds = newDisputePeriodSeconds;
        emit ChangedWithdrawalDisputePeriod(
            oldDisputePeriodSeconds,
            newDisputePeriodSeconds
        );
    }

    function changeValidatorSetDisputePeriodSeconds(
        uint64 newDisputePeriodSeconds,
        uint64 nonce,
        Signature[] calldata signatures
    ) external {
        // validate the nonce
        _verifyAndIncrementNonce(
            "changeValidatorSetDisputePeriodSeconds",
            nonce
        );

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(
                abi.encode(
                    "changeValidatorSetDisputePeriodSeconds",
                    newDisputePeriodSeconds,
                    nonce
                )
            ),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsColdWallets
        );

        uint64 oldDisputePeriodSeconds = validatorSetDisputePeriodSeconds;
        validatorSetDisputePeriodSeconds = newDisputePeriodSeconds;
        emit ChangedValidatorSetDisputePeriod(
            oldDisputePeriodSeconds,
            newDisputePeriodSeconds
        );
    }

    function changeLockerThreshold(
        uint64 newLockerThreshold,
        uint64 nonce,
        Signature[] calldata signatures
    ) external {
        // validate the nonce
        _verifyAndIncrementNonce("changeLockerThreshold", nonce);

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(
                abi.encode("changeLockerThreshold", newLockerThreshold, nonce)
            ),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsColdWallets
        );

        uint64 oldLockerThreshold = lockerThreshold;
        lockerThreshold = newLockerThreshold;
        emit ChangedLockerThreshold(oldLockerThreshold, newLockerThreshold);
    }

    /** End Config mutations **/

    /** Deposit */
    function batchDepositWithPermit(
        DepositWithPermit[] calldata deposits
    ) external whenNotPaused nonReentrant {
        // validate the deposit request
        uint256 noOfDeposits = deposits.length;

        if (noOfDeposits == 0) {
            revert DepositsEmpty();
        }

        if (noOfDeposits > 10) {
            revert MoreThanTenDeposits();
        }

        for (uint256 i = 0; i < noOfDeposits; i++) {
            if (deposits[i].user == address(0)) {
                revert ZeroUserAddress();
            }

            if (deposits[i].amount <= 0) {
                revert DepositAmountShouldBeGreaterThanZero();
            }

            if (deposits[i].deadline < block.timestamp) {
                revert PermitDeadlineExpired();
            }

            if (
                deposits[i].token == address(0) ||
                !enabledTokensMap[deposits[i].token]
            ) {
                revert InvalidTokenContract();
            }

            // deposit the tokens
            ERC20PermitUpgradeable transactionToken = ERC20PermitUpgradeable(
                deposits[i].token
            );
            address spender = address(this);

            try
                transactionToken.permit(
                    deposits[i].user,
                    spender,
                    deposits[i].amount,
                    deposits[i].deadline,
                    deposits[i].signature.v,
                    bytes32(deposits[i].signature.r),
                    bytes32(deposits[i].signature.s)
                )
            {} catch {
                if (
                    transactionToken.allowance(deposits[i].user, spender) <
                    deposits[i].amount
                ) {
                    revert FailedPermitDeposit(
                        deposits[i].user,
                        deposits[i].amount,
                        deposits[i].token
                    );
                }
            }

            transactionToken.safeTransferFrom(
                deposits[i].user,
                spender,
                deposits[i].amount
            );
        }
    }

    /** End Deposit **/

    /** Withdrawal **/
    /**
     * Failed Withdrawal Reason Codes
     * 1: Withdrawal has been invalidated
     * 2: Withdrawal has already been requested
     * 3: Withdrawal has been invalidated but trying to finalize
     * 4: Withdrawal has already been finalized
     * 5: Withdrawal does not exist
     * 6: Dispute period not satisfied
     */

    function batchRequestWithdrawals(
        RequestWithdrawal[] calldata withdrawals
    ) external whenNotPaused nonReentrant {
        // validate the withdrawal request
        if (withdrawals.length == 0) {
            revert WithdrawalsEmpty();
        }

        if (withdrawals.length > 10) {
            revert MoreThanTenWithdrawals();
        }

        for (uint256 i = 0; i < withdrawals.length; i++) {
            if (withdrawals[i].user == address(0)) {
                revert ZeroUserAddress();
            }
            if (withdrawals[i].amount <= 0) {
                revert WithdrawalAmountShouldBeGreaterThanZero();
            }

            if (
                withdrawals[i].token == address(0) ||
                !enabledTokensMap[withdrawals[i].token]
            ) {
                revert InvalidTokenContract();
            }

            // generate the message hash used to sign the request
            bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
                keccak256(
                    abi.encode(
                        "batchRequestWithdrawals",
                        withdrawals[i].user,
                        withdrawals[i].amount,
                        withdrawals[i].token,
                        withdrawals[i].nonce
                    )
                ),
                address(this)
            );

            // verify the validator quorum
            ValidatorLibrary.verifyValidatorQuorom(
                messageHash,
                withdrawals[i].signatures,
                cumulativeValidatorPower,
                domainSeparator,
                validatorsHotWallets
            );

            // Check if the withdrawal has been invalidated
            if (invalidatedWithdrawals[messageHash]) {
                emit WithdrawalFailed(messageHash, 1);
                return;
            }

            // Check if the withdrawal has been requested
            if (
                requestedWithdrawals[messageHash]
                    .requestedEpochTimestampInSeconds != 0
            ) {
                emit WithdrawalFailed(messageHash, 2);
                return;
            }

            // request the withdrawal
            uint64 requestedTime = uint64(block.timestamp);
            uint64 requestedBlockNumber = Utils.getCurrentBlockNumber();
            WithdrawalData memory withdrawalData = WithdrawalData({
                user: withdrawals[i].user,
                token: withdrawals[i].token,
                amount: withdrawals[i].amount,
                nonce: withdrawals[i].nonce,
                requestedEpochTimestampInSeconds: requestedTime,
                requestedBlockNumber: requestedBlockNumber,
                message: messageHash
            });
            requestedWithdrawals[messageHash] = withdrawalData;

            emit RequestedWithdrawal(withdrawalData);
        }
    }

    function invalidateWithdrawals(
        bytes32[] calldata messages,
        uint64 nonce,
        Signature[] calldata signatures
    ) external nonReentrant {
        // validate the nonce
        _verifyAndIncrementNonce("invalidateWithdrawals", nonce);

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(abi.encode("invalidateWithdrawals", messages, nonce)),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsHotWallets
        );

        for (uint256 i = 0; i < messages.length; i++) {
            if (
                requestedWithdrawals[messages[i]]
                    .requestedEpochTimestampInSeconds == 0
            ) {
                revert WithdrawalDoesNotExist(messages[i]);
            }
            if (
                !Utils.isTransactionInDisputeWindow(
                    requestedWithdrawals[messages[i]]
                        .requestedEpochTimestampInSeconds,
                    requestedWithdrawals[messages[i]].requestedBlockNumber,
                    withdrawalDisputePeriodSeconds,
                    blockDurationMillis
                )
            ) {
                revert WithdrawalDisputePeriodElapsed(messages[i]);
            }
            invalidatedWithdrawals[messages[i]] = true;
            emit InvalidatedWithdrawal(requestedWithdrawals[messages[i]]);
        }
    }

    function finalizeWithdrawal(
        bytes32 message
    ) external whenNotPaused nonReentrant {
        // Check if withdrawal has not been invalidated
        if (invalidatedWithdrawals[message]) {
            emit WithdrawalFailed(message, 3);
            return;
        }

        // Check if withdrawal has already been finalized
        if (finalizedWithdrawals[message]) {
            emit WithdrawalFailed(message, 4);
            return;
        }

        // Check if withdrawal exists
        if (
            requestedWithdrawals[message].requestedEpochTimestampInSeconds == 0
        ) {
            emit WithdrawalFailed(message, 5);
            return;
        }

        // Check if the dispute period has passed
        if (
            Utils.isTransactionInDisputeWindow(
                requestedWithdrawals[message].requestedEpochTimestampInSeconds,
                requestedWithdrawals[message].requestedBlockNumber,
                withdrawalDisputePeriodSeconds,
                blockDurationMillis
            )
        ) {
            emit WithdrawalFailed(message, 6);
            return;
        }

        // Finalize the withdrawals
        ERC20PermitUpgradeable transactionToken = ERC20PermitUpgradeable(
            requestedWithdrawals[message].token
        );

        transactionToken.safeTransfer(
            requestedWithdrawals[message].user,
            requestedWithdrawals[message].amount
        );
        finalizedWithdrawals[message] = true;
        emit FinalizedWithdrawal(requestedWithdrawals[message]);
    }

    /** End Withdrawal **/

    /** Validator Calls **/
    function proposeValidatorSet(
        ValidatorUpdateRequest calldata newValidatorSet,
        Signature[] calldata signatures
    ) external whenNotPaused {
        ValidatorLibrary.validateAddressIsValidator(
            msg.sender,
            validatorsColdWallets
        );
        // validate the request
        ValidatorLibrary.validateValidatorUpdateRequest(
            newValidatorSet,
            pendingValidatorSetUpdate
        );

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(
                abi.encode(
                    "proposeValidatorSet",
                    newValidatorSet.epochTimestampInSeconds,
                    newValidatorSet.hotValidatorSet,
                    newValidatorSet.coldValidatorSet,
                    newValidatorSet.powers
                )
            ),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsColdWallets
        );

        // add validator set to pending
        pendingValidatorSetUpdate = PendingValidatorSetUpdate({
            epochTimestampInSeconds: newValidatorSet.epochTimestampInSeconds,
            updateEpochTimestampInSeconds: uint64(block.timestamp),
            updateBlockNumber: Utils.getCurrentBlockNumber(),
            hotValidatorSet: newValidatorSet.hotValidatorSet,
            coldValidatorSet: newValidatorSet.coldValidatorSet,
            powers: newValidatorSet.powers
        });

        emit RequestedValidatorSetUpdate(
            pendingValidatorSetUpdate.epochTimestampInSeconds,
            pendingValidatorSetUpdate.hotValidatorSet,
            pendingValidatorSetUpdate.coldValidatorSet,
            newValidatorSet.powers
        );
    }

    function finalizeValidatorSetUpdate() external whenNotPaused {
        // validate if the sender is a validator
        address sender = msg.sender;
        ValidatorLibrary.validateAddressIsValidator(
            sender,
            validatorsColdWallets
        );

        // Check if the pending update is not already finalized
        if (pendingValidatorSetUpdate.updateEpochTimestampInSeconds == 0) {
            revert ValidatorSetUpdateAlreadyFinalized();
        }

        // Check for dispute period
        if (
            Utils.isTransactionInDisputeWindow(
                pendingValidatorSetUpdate.epochTimestampInSeconds,
                pendingValidatorSetUpdate.updateBlockNumber,
                validatorSetDisputePeriodSeconds,
                blockDurationMillis
            )
        ) {
            revert DisputePeriodNotSatisfied();
        }

        // finalize the validator set update
        _updateValidatorSet(
            pendingValidatorSetUpdate.coldValidatorSet,
            pendingValidatorSetUpdate.hotValidatorSet,
            pendingValidatorSetUpdate.powers
        );
    }

    function cancelValidatorSetUpdate(
        uint64 nonce,
        Signature[] calldata signatures
    ) external whenNotPaused {
        // validate the nonce
        _verifyAndIncrementNonce("cancelValidatorSetUpdate", nonce);

        // Check if the pending update is not already finalized
        if (pendingValidatorSetUpdate.updateEpochTimestampInSeconds == 0) {
            revert ValidatorSetUpdateAlreadyFinalized();
        }

        if (
            !Utils.isTransactionInDisputeWindow(
                pendingValidatorSetUpdate.epochTimestampInSeconds,
                pendingValidatorSetUpdate.updateBlockNumber,
                validatorSetDisputePeriodSeconds,
                blockDurationMillis
            )
        ) {
            revert ValidatorUpdateDisputePeriodElapsed();
        }

        // generate the message hash used to sign the request
        bytes32 messageHash = SignatureLibrary.generateUniqueMessageHash(
            keccak256(abi.encode("cancelValidatorSetUpdate", nonce)),
            address(this)
        );
        // verify the validator quorum
        ValidatorLibrary.verifyValidatorQuorom(
            messageHash,
            signatures,
            cumulativeValidatorPower,
            domainSeparator,
            validatorsColdWallets
        );

        // cancel the validator set update
        pendingValidatorSetUpdate.updateEpochTimestampInSeconds = 0;

        emit CanceledValidatorSetUpdate(
            pendingValidatorSetUpdate.epochTimestampInSeconds,
            pendingValidatorSetUpdate.hotValidatorSet,
            pendingValidatorSetUpdate.coldValidatorSet,
            pendingValidatorSetUpdate.powers
        );
    }
    /** End Validator Calls **/
}
