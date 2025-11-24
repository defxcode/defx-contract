// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "./IEmergencyController.sol";

interface ITokenSilo {
    // Events
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event EarlyWithdrawn(address indexed user, uint256 amount, uint256 fee);
    event UnlockFeeSet(uint256 fee);
    event EarlyUnlockEnabledSet(bool enabled);
    event FeeCollectorSet(address collector);
    event RescuedTokens(address token, address to, uint256 amount);
    event ClaimsPausedSet(bool paused);
    event LiquidityThresholdSet(uint256 threshold);
    event LiquidityAlert(uint256 availableAmount, uint256 neededAmount);
    event EmergencyControllerSet(address indexed controller);
    event RateLimitUpdated(uint256 maxDailyWithdrawalAmount);
    event DailyLimitReset(uint256 timestamp);

    // Initialization
    function initialize(
        address underlyingToken,
        string memory tokenSymbol,
        address vault,
        address _feeCollector
    ) external;

    // Core functions
    function depositFor(address user, uint256 amount) external;

    function withdrawTo(address user, uint256 amount) external;

    function earlyWithdrawFor(address user, uint256 amount) external;

    // View functions
    function balanceOf(address user) external view returns (uint256);

    function getTotalDeposited() external view returns (uint256);

    function calculateEarlyWithdrawalFee(uint256 amount) external view returns (uint256 feeAmount, uint256 netAmount);

    function getLiquidityStatus() external view returns (
        uint256 liquidity,
        uint256 pendingClaims,
        uint256 ratio,
        bool isPaused,
        IEmergencyController.EmergencyState emergencyState
    );

    function upgradeRequested() external view returns (bool requested, uint256 requestTime);

    function getUnlockFee() external view returns (uint256);

    function getEarlyUnlockEnabled() external view returns (bool);

    function getFeeCollector() external view returns (address);

    function getClaimsPaused() external view returns (bool);

    function getLiquidityThreshold() external view returns (uint256);

    // Admin functions
    function setEmergencyController(address _emergencyController) external;

    function setClaimsPaused(bool paused) external;

    function setLiquidityThreshold(uint256 threshold) external;

    function setUnlockFee(uint256 _fee) external;

    function setEarlyUnlockEnabled(bool _enabled) external;

    function setFeeCollector(address _collector) external;

    function adjustPendingClaims(uint256 newTotalPendingClaims) external;

    function setRateLimit(uint256 _maxDailyWithdrawalAmount) external;

    function resetDailyLimit() external;

    function pause() external;

    function unpause() external;

    function rescueTokens(address token, address to, uint256 amount) external;

    function setVault(address _vault) external;

    function requestUpgrade() external;

    function cancelUpgrade() external;

    // Role management
    function grantRole(bytes32 role, address account) external;
}