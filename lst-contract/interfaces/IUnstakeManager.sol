// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 * @title IUnstakeManager
 * @notice Interface for the UnstakeManager contract that handles unstaking requests for any underlying token
 */
interface IUnstakeManager {
    // Request status enum
    enum RequestStatus {
        NONE,
        QUEUED,
        PROCESSING,
        PROCESSED,
        CANCELLED
    }

    // Events
    event UnstakeRequested(address indexed user, uint256 lsTokenAmount, uint256 underlyingAmount, uint256 unlockTimestamp, uint256 requestId);
    event UnstakeStatusChanged(address indexed user, RequestStatus status, uint256 requestId);
    event UnstakeProcessed(address indexed user, uint256 underlyingAmount, uint256 requestId);
    event UnstakeProcessingFailed(address indexed user, uint256 underlyingAmount, uint256 requestId);
    event Claimed(address indexed user, uint256 underlyingAmount, uint256 requestId);
    event EmergencyControllerSet(address indexed controller);
    event CooldownPeriodSet(uint256 period);
    event MinUnstakeAmountSet(uint256 amount);

    /**
     * @notice Initialize the Unstake Manager
     */
    function initialize(
        address vault,
        address underlyingToken,
        address lsToken,
        address silo
    ) external;

    /**
     * @notice Request to unstake LS tokens
     */
    function requestUnstake(
        address user,
        uint256 lsTokenAmount,
        uint256 minUnderlyingAmount,
        uint256 currentIndex
    ) external;

    /**
     * @notice Claim underlying tokens after cooldown period
     */
    function claim(address user) external;

    /**
     * @notice Mark specific requests for processing
     */
    function markRequestsForProcessing(uint256[] calldata requestIds) external returns (uint256 processedCount);

    /**
     * @notice Process unstake requests in batch
     */
    function processUnstakeQueue(uint256 batchSize) external returns (uint256 processed, uint256 remaining);

    /**
     * @notice Process a specific user's unstake request
     */
    function processUserUnstake(address user) external returns (bool processed);

    /**
     * @notice Withdraw underlying tokens early from the silo for a fee
     */
    function earlyWithdraw() external;

    /**
     * @notice Cancel an unstake request
     */
    function cancelUnstake(address user) external returns (bool success);

    /**
     * @notice Allows a manager to trigger an early withdrawal on behalf of a user
     */
    function managerEarlyWithdraw(address user) external;

    /**
     * @notice Get request status and details
     */
    function getRequestInfo(address user) external view returns (
        RequestStatus status,
        uint256 amount,
        uint256 requestTimestamp,
        uint256 unlockTimestamp
    );

    /**
     * @notice Get view of unstake queue
     */
    function viewUnstakeQueue(uint256 limit) external view returns (
        address[] memory users,
        uint256[] memory amounts,
        RequestStatus[] memory statuses,
        uint256[] memory requestIds
    );

    /**
     * @notice Get queue details
     */
    function getQueueDetails() external view returns (
        uint256 totalSize,
        uint256 totalUnderlying,
        uint256 queuedCount,
        uint256 processingCount
    );

    /**
     * @notice Set emergency controller
     */
    function setEmergencyController(address emergencyController) external;

    /**
     * @notice Set cooldown period
     */
    function setCooldownPeriod(uint256 period) external;

    /**
     * @notice Set minimum unstake amount
     */
    function setMinUnstakeAmount(uint256 amount) external;

    /**
     * @notice Get configuration values
     */
    function minUnstakeAmount() external view returns (uint256);

    function cooldownPeriod() external view returns (uint256);

    /**
     * @notice Grant role (for factory setup)
     */
    function grantRole(bytes32 role, address account) external;
}