// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IVaultManager.sol";
import "./interfaces/ITokenSilo.sol";
import "./interfaces/IEmergencyController.sol";
import "./interfaces/IUnstakeManager.sol";
import "./interfaces/ILSTokenVault.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

// --- Custom Errors ---
error VaultManager_InvalidVault();
error VaultManager_InvalidAdmin();
error VaultManager_InvalidController();
error VaultManager_InvalidUnstakeManager();
error VaultManager_InvalidSilo();
error VaultManager_UnstakeManagerNotSet();
error VaultManager_VaultNotSet();
error VaultManager_FeeTooHigh();
error VaultManager_InvalidFeeReceiver();
error VaultManager_SiloNotSet();
error VaultManager_TimelockPending();
error VaultManager_NoUpgradeToCancel();
error VaultManager_InvalidImplementation();
error VaultManager_UpgradeNotRequested();
error VaultManager_TimelockNotExpired();

/**
 * @title VaultManager
 * @notice A stateless administrative control module for an LSTokenVault.
 * @dev This contract is the single point of entry for admins to change parameters.
 * It holds no funds
 * or configuration state itself, but is granted a MANAGER_ROLE on the LSTokenVault to execute commands.
 */
contract VaultManager is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IVaultManager
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // --- Roles ---
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    uint256 public constant MAX_FEE_PERCENT = 30;

    // --- State Variables ---
    address public vault;
    IEmergencyController public emergencyController;
    IUnstakeManager public unstakeManager;
    ITokenSilo public tokenSilo;

    // --- Version and upgrade controls ---
    uint256 public version;
    uint256 public constant UPGRADE_TIMELOCK = 2 days;
    uint256 public upgradeRequestTime;
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
     * @notice Initializes the admin module.
     */
    function initialize(address _vault, address _admin) external initializer {
        if (_vault == address(0)) revert VaultManager_InvalidVault();
        if (_admin == address(0)) revert VaultManager_InvalidAdmin();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        vault = _vault;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(MANAGER_ROLE, _admin);
        version = 1;
    }

    // --- Contract Links Setup ---
    function setEmergencyController(address _emergencyController) external override onlyRole(ADMIN_ROLE) {
        if (_emergencyController == address(0)) revert VaultManager_InvalidController();
        emergencyController = IEmergencyController(_emergencyController);
        emit EmergencyControllerSet(_emergencyController);
    }

    function setUnstakeManager(address _unstakeManager) external override onlyRole(ADMIN_ROLE) {
        if (_unstakeManager == address(0)) revert VaultManager_InvalidUnstakeManager();
        unstakeManager = IUnstakeManager(_unstakeManager);
        emit UnstakeManagerSet(_unstakeManager);
    }

    function setTokenSilo(address _silo) external override onlyRole(ADMIN_ROLE) {
        if (_silo == address(0)) revert VaultManager_InvalidSilo();
        tokenSilo = ITokenSilo(_silo);
        emit TokenSiloSet(_silo);
    }

    // --- Proxied Admin Functions ---
    function setCooldownPeriod(uint256 _cooldown) external override onlyRole(ADMIN_ROLE) {
        if (address(unstakeManager) == address(0)) revert VaultManager_UnstakeManagerNotSet();
        IUnstakeManager(unstakeManager).setCooldownPeriod(_cooldown);
    }

    function setMinUnstakeAmount(uint256 _minUnstakeAmount) external override onlyRole(ADMIN_ROLE) {
        if (address(unstakeManager) == address(0)) revert VaultManager_UnstakeManagerNotSet();
        IUnstakeManager(unstakeManager).setMinUnstakeAmount(_minUnstakeAmount);
    }

    function setMaxTotalDeposit(uint256 _maxTotalDeposit) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setMaxTotalDeposit(_maxTotalDeposit);
    }

    function setMaxUserDeposit(uint256 _maxUserDeposit) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setMaxUserDeposit(_maxUserDeposit);
    }

    function setFeePercent(uint256 _feePercent) external override onlyRole(ADMIN_ROLE) {
        if (_feePercent > MAX_FEE_PERCENT) revert VaultManager_FeeTooHigh();
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setFeePercent(_feePercent);
    }

    function setFeeReceiver(address _feeReceiver) external override onlyRole(ADMIN_ROLE) {
        if (_feeReceiver == address(0)) revert VaultManager_InvalidFeeReceiver();
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setFeeReceiver(_feeReceiver);
    }

    function setStakeEnabled(bool _enabled) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setStakeEnabled(_enabled);
    }

    function setUnstakeEnabled(bool _enabled) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setUnstakeEnabled(_enabled);
    }

    function withdrawFees() external override onlyRole(MANAGER_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).withdrawFees();
    }

    function transferCollateral(address to, uint256 amount) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).transferUnderlying(to, amount);
        emit AdminTransfer(to, amount);
    }

    function setYieldVestingDuration(uint256 _duration) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setYieldVestingDuration(_duration);
    }

    /**
     * @notice Allows a manager to trigger an early withdrawal on behalf of a user.
     * @dev Calls the corresponding function on UnstakeManager.
     * @param user The user for whom to trigger the early withdrawal.
     */
    function managerEarlyWithdraw(address user) external override onlyRole(MANAGER_ROLE) {
        if (address(unstakeManager) == address(0)) revert VaultManager_UnstakeManagerNotSet();
        IUnstakeManager(unstakeManager).managerEarlyWithdraw(user);
    }

    /**
     * @notice Sets the float percentage for the associated vault.
     * @dev Calls the corresponding function on LSTokenVault.
     */
    function setFloatPercent(uint256 _floatPercent) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setFloatPercent(_floatPercent);
    }

    function setSiloRateLimit(uint256 _maxDailyWithdrawalAmount) external override onlyRole(ADMIN_ROLE) {
        if (address(tokenSilo) == address(0)) revert VaultManager_SiloNotSet();
        tokenSilo.setRateLimit(_maxDailyWithdrawalAmount);
    }

    function setMinDepositAmount(uint256 _minDepositAmount) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setMinDepositAmount(_minDepositAmount);
    }

    /**
     * @notice Sets the daily deposit and withdrawal rate limits for the LSTokenVault.
     */
    function setVaultRateLimits(uint256 _maxDailyDeposit, uint256 _maxDailyWithdrawal) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setRateLimits(_maxDailyDeposit, _maxDailyWithdrawal);
    }

    /**
     * @notice Sets the flash loan protection parameter for the LSTokenVault.
     */
    function setFlashLoanProtection(uint256 _maxPriceImpactPercentage) external override onlyRole(ADMIN_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).setFlashLoanProtection(_maxPriceImpactPercentage);
    }

    /**
     * @notice Records the return of funds from a custodian to the LSTokenVault.
     * @dev This is an accounting function to keep totalCustodianFunds accurate.
     */
    function recordCustodianFundsReturn(uint256 amount) external override onlyRole(MANAGER_ROLE) {
        if (vault == address(0)) revert VaultManager_VaultNotSet();
        ILSTokenVault(vault).recordCustodianFundsReturn(amount);
    }

    // --- Upgrade Functions ---
    function requestUpgrade() external onlyRole(ADMIN_ROLE) {
        if (upgradeRequested) {
            if (block.timestamp < upgradeRequestTime + UPGRADE_TIMELOCK) revert VaultManager_TimelockPending();
        }
        upgradeRequestTime = block.timestamp;
        upgradeRequested = true;
        emit UpgradeRequested(upgradeRequestTime);
    }

    function cancelUpgrade() external onlyRole(ADMIN_ROLE) {
        if (!upgradeRequested) revert VaultManager_NoUpgradeToCancel();
        upgradeRequested = false;
        emit UpgradeCancelled(upgradeRequestTime);
        upgradeRequestTime = 0;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
        if (newImplementation == address(0)) revert VaultManager_InvalidImplementation();
        if (!upgradeRequested) revert VaultManager_UpgradeNotRequested();
        if (block.timestamp < upgradeRequestTime + UPGRADE_TIMELOCK) revert VaultManager_TimelockNotExpired();
        upgradeRequested = false;
        version++;
        emit UpgradeAuthorized(newImplementation, Strings.toString(version - 1));
    }

    uint256[40] private __gap;
}