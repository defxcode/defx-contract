// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 * @title ILSTokenVault
 * @notice The complete and correct interface for the LSTokenVault contract.
 * @dev This interface defines all externally callable functions, ensuring that other
 * contracts like VaultFactory and VaultManager can interact with it without compilation errors.
 */
interface ILSTokenVault {

    // --- Events ---
    event Deposited(address indexed user, uint256 underlyingAmount, uint256 lsTokenAmount);
    event IndexUpdated(uint256 oldIndex, uint256 newIndex);
    event FeesCollected(uint256 amount);
    event FeesWithdrawn(address indexed receiver, uint256 amount);
    event CustodianTransfer(uint256 indexed custodianId, address indexed custodian, uint256 amount);
    event CustodianUpdated(uint256 indexed custodianId, address wallet, uint256 allocation);
    event UnstakeManagerSet(address indexed unstakeManager);
    event EmergencyControllerSet(address indexed emergencyController);

    // --- Initialization ---
    function initialize(
        address underlyingToken,
        address lsToken,
        string memory underlyingSymbol,
        string memory lsTokenSymbol,
        address admin
    ) external;

    // --- Contract Links Setup ---
    function setUnstakeManager(address unstakeManager) external;

    function setEmergencyController(address emergencyController) external;

    // --- Core User Functions ---
    function deposit(uint256 underlyingAmount) external;

    function deposit(uint256 underlyingAmount, uint256 minLSTokenAmount) external;

    function requestUnstake(uint256 lsTokenAmount) external;

    function requestUnstake(uint256 lsTokenAmount, uint256 minUnderlyingAmount) external;

    // --- Manager & Rewarder Functions ---
    function addYield(uint256 yieldAmount) external;

    function withdrawFees() external;

    // --- Custodian Management (ADMIN_ROLE) ---
    function addCustodian(address wallet, uint256 allocationPercent) external returns (uint256);

    function updateCustodian(uint256 custodianId, address wallet, uint256 allocationPercent) external;

    function removeCustodian(uint256 custodianId) external;

    function recordCustodianFundsReturn(uint256 amount) external;

    function setFloatPercent(uint256 floatPercent) external;

    // --- Security & Rate Limits (MANAGER_ROLE) ---
    function setRateLimits(uint256 _maxDailyDeposit, uint256 _maxDailyWithdrawal) external;

    function setFlashLoanProtection(uint256 _maxPriceImpactPercentage) external;

    function approveUnstakeManager(uint256 amount) external;

    function setYieldVestingDuration(uint256 _duration) external;

    // --- Proxied Admin Functions (MANAGER_ROLE) ---
    function setMaxTotalDeposit(uint256 maxTotal) external;

    function setMaxUserDeposit(uint256 maxUser) external;

    function setFeePercent(uint256 feePercent) external;

    function setFeeReceiver(address feeReceiver) external;

    function setStakeEnabled(bool enabled) external;

    function setUnstakeEnabled(bool enabled) external;

    function transferUnderlying(address to, uint256 amount) external;

    function setMinDepositAmount(uint256 minDeposit) external;

    // --- View Functions ---
    function isVestingActive() external view returns (bool);

    function getCurrentIndex() external view returns (uint256);

    function targetIndex() external view returns (uint256);

    function getStats() external view returns (uint256 currentIndex, uint256 totalDeposited, uint256 totalSupply);

    function getTokenInfo() external view returns (address underlyingAddr, address lsTokenAddr, string memory underlyingSym, string memory lsTokenSym);

    function getLiquidityStatus() external view returns (uint256 vaultBalance, uint256 custodianBalance, uint256 totalAvailableAssets, uint256 indexedLiabilities);

    function getCustodian(uint256 custodianId) external view returns (address wallet, uint256 allocationPercent);

    function getAllCustodians() external view returns (address[] memory wallets, uint256[] memory allocations);

    function maxTotalDeposit() external view returns (uint256);

    function maxUserDeposit() external view returns (uint256);

    function feePercent() external view returns (uint256);

    function floatPercent() external view returns (uint8);

    function maxPriceImpactPercentage() external view returns (uint16);

    function depositLimit() external view returns (uint128, uint128);

    function withdrawalLimit() external view returns (uint128, uint128);

    function getMinDepositAmount() external view returns (uint256);

    function yieldVestingDuration() external view returns (uint256);
}