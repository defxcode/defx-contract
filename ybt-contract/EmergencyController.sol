// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IEmergencyController.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

// --- Custom Errors ---
error EmergencyController_InvalidAdmin();
error EmergencyController_RecoveryModeActive();
error EmergencyController_RecoveryModeScheduled();
error EmergencyController_RecoveryNotScheduled();
error EmergencyController_TimelockNotExpired();
error EmergencyController_RecoveryAlreadyActive();
error EmergencyController_InvalidImplementation();
error EmergencyController_UpgradeNotRequested();
error EmergencyController_TimelockPending();
error EmergencyController_NoUpgradeToCancel();

/**
 * @title EmergencyController
 * @notice This is the global "kill switch" for the entire protocol. It acts as a single, centralized
 * point of control to pause or resume core functionalities across all vaults in response to a
 * threat or for system maintenance. Its state is checked by other contracts before executing
 * critical functions like deposits or withdrawals.
 * @dev Inherits from UUPSUpgradeable to allow for its own logic to be upgraded.
 */
contract EmergencyController is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    IEmergencyController
{
    // --- Roles ---
    /// @notice The ADMIN_ROLE has the highest level of authority, capable of managing roles and resuming normal operations.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    /// @notice The EMERGENCY_ROLE is a specialized role that can pause the system and trigger recovery mode.
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // --- State Variables ---

    /// @notice Stores the current operational state of the protocol (e.g., NORMAL, FULL_PAUSE).
    EmergencyState private _emergencyState;

    /// @notice A flag indicating if the protocol is in the highly restrictive Recovery Mode.
    bool public recoveryModeActive;
    /// @notice The timestamp when the 24-hour countdown to activate Recovery Mode began.
    uint256 public recoveryModeActivationTime;
    /// @notice A constant defining the mandatory 24-hour waiting period before Recovery Mode can be activated.
    uint256 public constant RECOVERY_DELAY = 24 hours;

    /// @notice The current version of this contract, used for tracking upgrades.
    uint256 public version;
    /// @notice The mandatory 2-day waiting period for a contract upgrade to be authorized.
    uint256 public constant UPGRADE_TIMELOCK = 2 days;
    /// @notice The timestamp when a contract upgrade was requested.
    uint256 public upgradeRequestTime;
    /// @notice A flag indicating if a contract upgrade has been requested and is pending.
    bool public upgradeRequested;

    // --- Events ---
    event VersionUpdated(string newVersion);
    event UpgradeRequested(uint256 requestTime);
    event UpgradeCancelled(uint256 requestTime);
    event UpgradeAuthorized(address indexed implementation, string currentVersion);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the Emergency Controller, setting the initial admin and default states.
     * @dev This function is called only once when the contract is first deployed as a proxy.
     * It grants all key roles to the initial admin for setup purposes.
     * @param _admin The address that will receive all administrative and emergency roles.
     */
    function initialize(address _admin) external initializer {
        if (_admin == address(0)) revert EmergencyController_InvalidAdmin();
        __AccessControl_init();
        __UUPSUpgradeable_init();

        // Grant all powerful roles to the initial admin.
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);

        // The system starts in a normal, fully operational state.
        _emergencyState = EmergencyState.NORMAL;
        recoveryModeActive = false;
        version = 1;
    }

    /**
     * @notice Returns the current emergency state of the protocol.
     * @dev Other contracts will call this view function to check if they are allowed to proceed with an action.
     * @return The current `EmergencyState` enum value.
     */
    function getEmergencyState() external view override returns (EmergencyState) {
        return _emergencyState;
    }

    /**
     * @notice Checks if the protocol is currently in Recovery Mode.
     * @return True if Recovery Mode is active, false otherwise.
     */
    function isRecoveryModeActive() external view override returns (bool) {
        return recoveryModeActive;
    }

    /**
     * @notice Pauses only the deposit functionality across the protocol.
     * @dev Sets the state to `DEPOSITS_PAUSED`. Withdrawals and other functions remain active.
     */
    function pauseDeposits() external override onlyRole(EMERGENCY_ROLE) {
        _emergencyState = EmergencyState.DEPOSITS_PAUSED;
        emit EmergencyStateChanged(EmergencyState.DEPOSITS_PAUSED);
    }

    /**
     * @notice Pauses only the withdrawal functionality across the protocol.
     * @dev Sets the state to `WITHDRAWALS_PAUSED`. Deposits may still be active.
     */
    function pauseWithdrawals() external override onlyRole(EMERGENCY_ROLE) {
        _emergencyState = EmergencyState.WITHDRAWALS_PAUSED;
        emit EmergencyStateChanged(EmergencyState.WITHDRAWALS_PAUSED);
    }

    /**
     * @notice Pauses all major functions (deposits and withdrawals).
     * @dev This is a quick way to halt the most critical parts of the protocol.
     */
    function pauseAll() external override onlyRole(EMERGENCY_ROLE) {
        _emergencyState = EmergencyState.FULL_PAUSE;
        emit EmergencyStateChanged(EmergencyState.FULL_PAUSE);
    }

    /**
     * @notice Returns the system to the `NORMAL` operational state.
     * @dev Can only be called by an `ADMIN_ROLE` and only if Recovery Mode is not active.
     * This prevents resuming operations while a major crisis is still being managed.
     */
    function resumeOperations() external override onlyRole(ADMIN_ROLE) {
        if (recoveryModeActive) revert EmergencyController_RecoveryModeActive();
        if (recoveryModeActivationTime != 0) revert EmergencyController_RecoveryModeScheduled();
        _emergencyState = EmergencyState.NORMAL;
        emit EmergencyStateChanged(EmergencyState.NORMAL);
    }

    /**
     * @notice The most severe emergency action. It immediately puts the system into a `FULL_PAUSE`
     * and simultaneously starts the 24-hour timelock for activating Recovery Mode.
     * @param reason A string explaining why the circuit breaker was triggered, for transparency.
     */
    function triggerCircuitBreaker(string calldata reason) external override onlyRole(EMERGENCY_ROLE) {
        _emergencyState = EmergencyState.FULL_PAUSE;
        emit EmergencyStateChanged(EmergencyState.FULL_PAUSE);

        // Start the countdown timer for Recovery Mode activation.
        recoveryModeActivationTime = block.timestamp;
        emit RecoveryModeScheduled(recoveryModeActivationTime);

        emit EmergencyCircuitBreakerTriggered(block.timestamp, reason);
    }

    /**
     * @notice Schedules Recovery Mode to be available for activation after a 24-hour delay.
     * @dev This is a less immediate action than `triggerCircuitBreaker`. It starts the timer
     * without immediately pausing the system, useful for preparing for a known future event.
     */
    function scheduleRecoveryMode() external override onlyRole(EMERGENCY_ROLE) {
        if (recoveryModeActive) revert EmergencyController_RecoveryAlreadyActive();
        recoveryModeActivationTime = block.timestamp;
        emit RecoveryModeScheduled(recoveryModeActivationTime);
    }

    /**
     * @notice Activates the highly restrictive Recovery Mode.
     * @dev Can only be called after the 24-hour timelock has passed. This mode freezes almost all
     * functions across the protocol to allow for a safe resolution of a critical issue.
     * It also sets the system state to `FULL_PAUSE` as a final measure.
     */
    function activateRecoveryMode() external override onlyRole(EMERGENCY_ROLE) {
        if (recoveryModeActivationTime == 0) revert EmergencyController_RecoveryNotScheduled();
        if (block.timestamp < recoveryModeActivationTime + RECOVERY_DELAY) revert EmergencyController_TimelockNotExpired();
        if (recoveryModeActive) revert EmergencyController_RecoveryAlreadyActive();

        recoveryModeActive = true;
        emit RecoveryModeActivated(block.timestamp);

        _emergencyState = EmergencyState.FULL_PAUSE;
        emit EmergencyStateChanged(EmergencyState.FULL_PAUSE);
    }

    /**
     * @notice Deactivates Recovery Mode, allowing the system to eventually return to normal.
     * @dev Only the `ADMIN_ROLE` can perform this action. After deactivation, an admin still
     * needs to call `resumeOperations()` to fully re-enable the protocol.
     */
    function deactivateRecoveryMode() external override onlyRole(ADMIN_ROLE) {
        recoveryModeActive = false;
        recoveryModeActivationTime = 0; // Reset the timer
        emit RecoveryModeDeactivated(block.timestamp);
    }

    // --- Upgrade Functions ---

    /**
     * @notice Begins the 2-day timelock for a contract upgrade.
     * @dev This prevents immediate, unforeseen upgrades. If a request was already pending
     * and its timelock expired, this will start a new one.
     */
    function requestUpgrade() external onlyRole(ADMIN_ROLE) {
        if (upgradeRequested) {
            if (block.timestamp < upgradeRequestTime + UPGRADE_TIMELOCK) revert EmergencyController_TimelockPending();
        }
        upgradeRequestTime = block.timestamp;
        upgradeRequested = true;
        emit UpgradeRequested(upgradeRequestTime);
    }

    /**
     * @notice Cancels a pending upgrade request.
     */
    function cancelUpgrade() external onlyRole(ADMIN_ROLE) {
        if (!upgradeRequested) revert EmergencyController_NoUpgradeToCancel();
        upgradeRequested = false;
        emit UpgradeCancelled(upgradeRequestTime);
        upgradeRequestTime = 0;
    }

    /**
     * @notice Authorizes the upgrade to a new implementation contract.
     * @param newImplementation The address of the new logic contract.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
        if (newImplementation == address(0)) revert EmergencyController_InvalidImplementation();
        if (!upgradeRequested) revert EmergencyController_UpgradeNotRequested();
        if (block.timestamp < upgradeRequestTime + UPGRADE_TIMELOCK) revert EmergencyController_TimelockNotExpired();

        upgradeRequested = false;

        version++;
        emit UpgradeAuthorized(newImplementation, Strings.toString(version - 1));
    }

    uint256[54] private __gap;
}