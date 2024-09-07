// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import "../library/SignatureLibrary.sol";

import {ValidatorUpdateRequest, Signature, ValidatorSet} from "../common/Structs.sol";
import {HotColdValidatorSetLengthMismatch, PowersLengthMismatch, InvalidValidatorAddress, ValidatorPowerShouldBeGreaterThanZero, InsufficientValidatorPower, TimestampShouldBeGreaterThanZero, ValidatorSetLengthShouldBeGreaterThanZero, NotAValidator, RequestExpired} from "../common/Errors.sol";

library ValidatorLibrary {
    function validateAddressIsValidator(
        address addressToValidate,
        ValidatorSet memory validatorsForVerification
    ) internal pure {
        address[] memory validators = validatorsForVerification.validators;
        uint256 noOfValidators = validators.length;
        for (uint256 i = 0; i < noOfValidators; i++) {
            if (validatorsForVerification.validators[i] == addressToValidate) {
                if (validatorsForVerification.powers[i] > 0) {
                    return;
                } else {
                    revert InsufficientValidatorPower();
                }
            }
        }
        revert NotAValidator();
    }

    function validateValidatorUpdateRequest(
        ValidatorUpdateRequest calldata newValidatorSet
    ) internal view {
        if (
            newValidatorSet.hotValidatorSet.length == 0 ||
            newValidatorSet.coldValidatorSet.length == 0
        ) {
            revert ValidatorSetLengthShouldBeGreaterThanZero();
        }

        if (newValidatorSet.epochTimestamp <= 0) {
            revert TimestampShouldBeGreaterThanZero();
        }

        if (newValidatorSet.epochTimestamp < block.timestamp - 5 * 60) {
            // not within the 5 min window
            revert RequestExpired();
        }

        if (
            newValidatorSet.hotValidatorSet.length !=
            newValidatorSet.coldValidatorSet.length
        ) {
            revert HotColdValidatorSetLengthMismatch();
        }

        if (
            newValidatorSet.powers.length !=
            newValidatorSet.hotValidatorSet.length ||
            newValidatorSet.powers.length !=
            newValidatorSet.coldValidatorSet.length
        ) {
            revert PowersLengthMismatch();
        }

        uint256 noOfValidators = newValidatorSet.powers.length;

        for (uint8 i = 0; i < noOfValidators; i++) {
            if (
                newValidatorSet.hotValidatorSet[i] == address(0) ||
                newValidatorSet.coldValidatorSet[i] == address(0)
            ) {
                revert InvalidValidatorAddress();
            }

            if (newValidatorSet.powers[i] <= 0) {
                revert ValidatorPowerShouldBeGreaterThanZero();
            }
        }
    }

    function verifyValidatorQuorom(
        bytes32 messageHash,
        Signature[] calldata signatures,
        uint64 cumulativeValidatorPower,
        bytes32 domainSeparator,
        ValidatorSet memory validatorsForVerification
    ) internal pure {
        uint64 accumulatedPower;
        uint64 signatureCount = uint64(signatures.length);
        uint64 validatorSetLength = uint64(
            validatorsForVerification.validators.length
        );

        if (signatureCount == 0) {
            revert InsufficientValidatorPower();
        }

        address[] memory signers = new address[](signatureCount);
        for (uint64 i = 0; i < signatureCount; i++) {
            signers[i] = SignatureLibrary.recoverSigner(
                messageHash,
                signatures[i],
                domainSeparator
            );
        }

        bool[] memory validatorCounted = new bool[](validatorSetLength);

        for (uint64 i = 0; i < signatureCount; i++) {
            for (uint64 j = 0; j < validatorSetLength; j++) {
                if (
                    !validatorCounted[j] &&
                    signers[i] == validatorsForVerification.validators[j]
                ) {
                    validatorCounted[j] = true;
                    accumulatedPower += validatorsForVerification.powers[j];
                    if (
                        isThereAQuorum(
                            cumulativeValidatorPower,
                            accumulatedPower
                        )
                    ) {
                        return;
                    }
                    break; // Move to the next signer
                }
            }
        }

        if (!isThereAQuorum(cumulativeValidatorPower, accumulatedPower)) {
            revert InsufficientValidatorPower();
        }
    }

    function isThereAQuorum(
        uint64 cumulativeValidatorPower,
        uint64 accumulatedPower
    ) internal pure returns (bool) {
        return 3 * accumulatedPower > 2 * cumulativeValidatorPower;
    }
}
