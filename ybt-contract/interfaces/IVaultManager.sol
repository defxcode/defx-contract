// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 * @title IVaultManager
 * @notice The interface for the central administrative control module of an LST vault.
 * @dev This interface defines all the externally callable functions on the VaultManager contract.
 */
interface IVaultManager {

    // --- Events ---
    event EmergencyControllerSet(address indexed controller);
    event UnstakeManagerSet(address indexed unstakeManager);
    event TokenSiloSet(address indexed silo);
    event CooldownPeriodSet(uint256 period);
    event MinUnstakeAmountSet(uint256 amount);
    event AdminTransfer(address indexed to, uint256 amount);

    // --- Contract Links Setup ---
    function setEmergencyController(address _emergencyController) external;

    function setUnstakeManager(address _unstakeManager) external;

    function setTokenSilo(address _silo) external;

    // --- Proxied Admin Functions ---

    // UnstakeManager Configuration
    function setCooldownPeriod(uint256 _cooldown) external;

    function setMinUnstakeAmount(uint256 _minUnstakeAmount) external;

    // LSTokenVault Configuration
    function setMaxTotalDeposit(uint256 _maxTotalDeposit) external;

    function setMaxUserDeposit(uint256 _maxUserDeposit) external;

    function setFeePercent(uint256 _feePercent) external;

    function setFeeReceiver(address _feeReceiver) external;

    function setStakeEnabled(bool _enabled) external;

    function setUnstakeEnabled(bool _enabled) external;

    function setFloatPercent(uint256 _floatPercent) external;

    function setMinDepositAmount(uint256 _minDepositAmount) external;

    function setVaultRateLimits(uint256 _maxDailyDeposit, uint256 _maxDailyWithdrawal) external;

    function setFlashLoanProtection(uint256 _maxPriceImpactPercentage) external;

    function recordCustodianFundsReturn(uint256 amount) external;

    function setYieldVestingDuration(uint256 _duration) external;

    // LSTokenVault Actions
    function withdrawFees() external;

    function transferCollateral(address to, uint256 amount) external;

    /**
     * @notice Allows a manager to trigger an early withdrawal on behalf of a user.
     */
    function managerEarlyWithdraw(address user) external;

    // TokenSilo Configuration
    function setSiloRateLimit(uint256 _maxDailyWithdrawalAmount) external;
}