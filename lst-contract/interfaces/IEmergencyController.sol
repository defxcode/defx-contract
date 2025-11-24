// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 * @title IEmergencyController
 * @notice Interface for the centralized emergency control module
 */
interface IEmergencyController {
    // Emergency state types
    enum EmergencyState {
        NORMAL,
        DEPOSITS_PAUSED,
        WITHDRAWALS_PAUSED,
        FULL_PAUSE
    }

    // Events
    event EmergencyStateChanged(EmergencyState state);
    event RecoveryModeScheduled(uint256 activationTime);
    event RecoveryModeActivated(uint256 activationTime);
    event RecoveryModeDeactivated(uint256 deactivationTime);
    event EmergencyCircuitBreakerTriggered(uint256 triggerTimestamp, string reason);

    function initialize(address _admin) external;

    function getEmergencyState() external view returns (EmergencyState);

    function isRecoveryModeActive() external view returns (bool);

    function pauseDeposits() external;

    function pauseWithdrawals() external;

    function pauseAll() external;

    function resumeOperations() external;

    function triggerCircuitBreaker(string calldata reason) external;

    function scheduleRecoveryMode() external;

    function activateRecoveryMode() external;

    function deactivateRecoveryMode() external;
}