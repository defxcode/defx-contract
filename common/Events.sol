// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {WithdrawalData} from "./Structs.sol";

event RequestedValidatorSetUpdate(
    uint64 timestamp,
    address[] hotValidatorSet,
    address[] coldValidatorSet,
    uint64[] powers
);

event FinalizedValidatorSetUpdate(
    uint64 timestamp,
    address[] hotValidatorSet,
    address[] coldValidatorSet,
    uint64[] powers
);

event CanceledValidatorSetUpdate(
    uint64 timestamp,
    address[] hotValidatorSet,
    address[] coldValidatorSet,
    uint64[] powers
);

event ChangedBlockDurationMillis(
    uint64 oldBlockDurationMillis,
    uint64 newBlockDurationMillis
);

event ChangedValidatorSetDisputePeriod(
    uint64 oldDisputePeriodSeconds,
    uint64 newDisputePeriodSeconds
);

event ChangedWithdrawalDisputePeriod(
    uint64 oldDisputePeriodSeconds,
    uint64 newDisputePeriodSeconds
);

event ChangedLockerThreshold(
    uint64 oldLockerThreshold,
    uint64 newLockerThreshold
);

event WithdrawalFailed(bytes32 message, uint256 reason);

event RequestedWithdrawal(WithdrawalData withdrawalData);

event InvalidatedWithdrawal(WithdrawalData withdrawalData);

event FinalizedWithdrawal(WithdrawalData withdrawalData);

event ContractPaused();

event ContractResumed();

event ModifiedLocker(address locker, bool isEnabled);
