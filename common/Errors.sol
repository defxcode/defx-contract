// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

error DepositsEmpty();
error MoreThanTenDeposits();
error ZeroUserAddress();
error DepositAmountShouldBeGreaterThanZero();
error PermitDeadlineExpired();

error InvalidSignatureRecoveredZeroAddress();
error NotAValidator();

error TimestampShouldBeGreaterThanZero();
error RequestExpired();

error ValidatorSetLengthShouldBeGreaterThanZero();
error HotColdValidatorSetLengthMismatch();
error PowersLengthMismatch();
error InvalidValidatorAddress();
error ValidatorPowerShouldBeGreaterThanZero();
error InsufficientValidatorPower();

error ValidatorSetUpdateAlreadyFinalized();

error DisputePeriodNotSatisfied();

error MoreThanTenWithdrawals();
error WithdrawalsEmpty();
error WithdrawalAmountShouldBeGreaterThanZero();

error NotALocker();
error AlreadyVoted();
error NotVotedPreviously();

error ContractAlreadyPaused();
error ContractNotPaused();

error InvalidNonce();

error NotEnoughTokensToUpdate();
error InvalidTokenContract();
