// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "@arbitrum/nitro-contracts/src/precompiles/ArbSys.sol";
import {DisputePeriodNotSatisfied} from "../common/Errors.sol";

library Utils {
    function isArbitrum() private view returns (bool) {
        // Arbitrum One (42161), Arbitrum Sepolia (421614), or Arbitrum Nova (42170)
        return
            block.chainid == 42161 ||
            block.chainid == 421614 ||
            block.chainid == 42170;
    }

    function getCurrentBlockNumber() internal view returns (uint64) {
        if (isArbitrum()) {
            return uint64(ArbSys(address(100)).arbBlockNumber());
        } else {
            // For all other chains, including Ethereum, Base, Optimism, Polygon, etc.
            return uint64(block.number);
        }
    }

    function isTransactionInDisputeWindow(
        uint64 timeInSeconds,
        uint64 blockNumber,
        uint64 disputePeriodSeconds,
        uint64 blockDurationMillis
    ) internal view returns (bool) {
        bool enoughTimePassed = block.timestamp >
            timeInSeconds + disputePeriodSeconds;
        if (!enoughTimePassed) {
            return true;
        }

        uint64 curBlockNumber = getCurrentBlockNumber();

        bool enoughBlocksPassed = (curBlockNumber - blockNumber) *
            blockDurationMillis >
            1000 * disputePeriodSeconds;
        if (!enoughBlocksPassed) {
            return true;
        }

        return false;
    }
}
