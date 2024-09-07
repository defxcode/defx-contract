// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// TODO: move to a separate file
/** Request Structs */
struct DepositWithPermit {
    address user;
    uint64 amount;
    uint64 deadline;
    Signature signature;
}

struct RequestWithdrawal {
    address user;
    uint64 amount;
    uint64 nonce;
    Signature[] signatures;
}

struct ValidatorUpdateRequest {
    uint64 epochTimestamp;
    address[] hotValidatorSet;
    address[] coldValidatorSet;
    uint64[] powers;
}
/** End Request Structs */

struct Agent {
    string source;
    bytes32 connectionId;
}

struct Signature {
    uint256 r;
    uint256 s;
    uint8 v;
}
struct ValidatorSet {
    address[] validators;
    uint64[] powers;
}

struct PendingValidatorSetUpdate {
    uint64 epochTimestamp;
    uint64 updateTime;
    uint64 updateBlockNumber;
    address[] hotValidatorSet;
    address[] coldValidatorSet;
    uint64[] powers;
}

struct WithdrawalData {
    address user;
    uint64 amount;
    uint64 nonce;
    uint64 requestedTime;
    uint64 requestedBlockNumber;
    bytes32 message;
}
