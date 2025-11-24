// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// External libraries and contracts
import {UD60x18, wrap, unwrap} from "@prb/math/src/UD60x18.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/IERC20MetadataUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
// Internal interfaces
import "./interfaces/ILSToken.sol";
import "./interfaces/ITokenSilo.sol";
import "./interfaces/IUnstakeManager.sol";
import "./interfaces/IEmergencyController.sol";
import "./interfaces/ILSTokenVault.sol";

// --- Custom Errors ---
error UnstakeManager_InvalidVault();
error UnstakeManager_InvalidUnderlyingToken();
error UnstakeManager_InvalidLSToken();
error UnstakeManager_InvalidSilo();
error UnstakeManager_VaultRoleNotGranted();
error UnstakeManager_InvalidController();
error UnstakeManager_InvalidPeriod();
error UnstakeManager_AmountMustBePositive();
error UnstakeManager_BelowMinUnstake();
error UnstakeManager_InvalidUserAddress();
error UnstakeManager_ActiveUnstakePending();
error UnstakeManager_SlippageTooHigh();
error UnstakeManager_UnderlyingAmountIsZero();
error UnstakeManager_EmptyRequestList();
error UnstakeManager_SiloNotSet();
error UnstakeManager_EmergencyControllerNotSet();
error UnstakeManager_SystemDepositsPaused();
error UnstakeManager_InsufficientVaultBalance();
error UnstakeManager_RequestNotInQueueOrProcessing();
error UnstakeManager_NotAuthorized();
error UnstakeManager_WithdrawalsPaused();
error UnstakeManager_RecoveryModeActive();
error UnstakeManager_NoPendingUnstake();
error UnstakeManager_UnstakeNotProcessed();
error UnstakeManager_CooldownNotFinished();
error UnstakeManager_NoBalanceInSilo();
error UnstakeManager_CannotCancelDuringVesting();
error UnstakeManager_CannotCancelProcessedRequest();
error UnstakeManager_InvalidImplementation();
error UnstakeManager_UpgradeNotRequested();
error UnstakeManager_TimelockNotExpired();
error UnstakeManager_TimelockPending();
error UnstakeManager_NoUpgradeToCancel();
error UnstakeManager_ValueTooLarge();
error UnstakeManager_UnwrapUnderflow();
error UnstakeManager_UnsupportedDecimals();

/**
* @title UnstakeManager
* @notice This contract manages the entire asynchronous unstaking process.
* It handles user requests,
* manages a queue of pending unstakes, facilitates processing by an admin/manager, and allows users
* to claim their funds from the TokenSilo after a cooldown period.
*/
contract UnstakeManager is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IUnstakeManager
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // --- Roles ---
    /// @notice The VAULT_ROLE is granted to the LSTokenVault, allowing it to initiate unstake requests on behalf of users.
    bytes32 public constant VAULT_ROLE = keccak256("VAULT_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    /// @notice The MANAGER_ROLE is for off-chain operators who process the unstake queue.
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // --- State Variables ---
    uint256 internal decimalScaleFactor;

    // Core contract references
    address public vault;
    IERC20Upgradeable public underlyingToken;
    ILSToken public lsToken;
    ITokenSilo public silo;
    IEmergencyController public emergencyController;
    // Token metadata
    string public underlyingSymbol;
    string public lsTokenSymbol;
    uint8 public underlyingDecimals;
    /// @notice A struct representing a single user's unstake request.
    struct UnstakeRequest {
        uint256 lsTokenAmount;      // The original amount of LSTokens burned.
        uint256 requestTimestamp;   // The timestamp of the request.
        uint256 underlyingAmount;   // The calculated amount of underlying tokens owed.
        RequestStatus status;
        // The current status of the request (Queued, Processing, etc.).
        uint256 requestId;          // A unique ID for the request.
    }

    // --- Configuration ---
    uint256 public cooldownPeriod;
    // The mandatory waiting period before claiming.
    uint256 public maxCooldownPeriod;   // An upper bound for the cooldown period, for safety.
    uint256 public minUnstakeAmount;    // The minimum amount of LSTokens a user can unstake.
    // --- Queue Management ---
    uint256 private nextRequestId; // A counter to generate unique request IDs.
    /// @notice Maps a user's address to their single active unstake request.
    mapping(address => UnstakeRequest) public unstakeRequests;
    /// @notice Maps a unique request ID back to the user's address for quick lookups.
    mapping(uint256 => address) public requestIdToAddress;
    /// @notice An array of all request IDs currently in the queue (status QUEUED or PROCESSING).
    uint256[] public queuedRequestIds;
    uint256 public queueLength; // The total number of requests in the queue.
    uint256 public totalQueuedUnstakeAmount; // The total value of underlying tokens in the queue.

    // --- Upgrade Control ---
    uint256 public version;
    uint256 public constant UPGRADE_TIMELOCK = 2 days;
    uint256 public upgradeRequestTime;
    bool public upgradeRequested;

    /**
     * @notice Safe wrapper for UD60x18 with bounds checking
     */
    function safeWrap(uint256 value) internal pure returns (UD60x18) {
        if (value > type(uint256).max / 1e18) revert UnstakeManager_ValueTooLarge();
        return wrap(value);
    }

    /**
     * @notice Safe unwrapper for UD60x18 with bounds checking
     */
    function safeUnwrap(UD60x18 value) internal pure returns (uint256) {
        uint256 result = unwrap(value);
        return result;
    }

    /**
     * @notice Converts between two token amounts using a given exchange rate.
     * @dev This is used to calculate the amount of LST to mint on cancellation.
     * @param isDeposit If true, calculates `input * precision / rate`.
     */
    function _convertTokens(
        uint256 inputAmount,
        uint256 exchangeRate,
        uint256 precision,
        bool isDeposit
    ) internal pure returns (uint256) {
        if (inputAmount == 0) return 0;
        UD60x18 inputUD = safeWrap(inputAmount);
        UD60x18 rateUD = safeWrap(exchangeRate);
        UD60x18 precisionUD = safeWrap(precision);

        UD60x18 result;
        if (isDeposit) {
            // To get LSToken amount from underlying: (underlying * 1e18) / index
            result = inputUD.mul(precisionUD).div(rateUD);
        } else {
            // To get underlying amount from LSToken: (lsToken * index) / 1e18
            result = inputUD.mul(rateUD).div(precisionUD);
        }
        return safeUnwrap(result);
    }

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
     * @notice Initializes the UnstakeManager contract.
     * @dev Called by the VaultFactory during deployment.
     */
    function initialize(
        address _vault,
        address _underlyingToken,
        address _lsToken,
        address _silo
    ) external initializer {
        if (_vault == address(0)) revert UnstakeManager_InvalidVault();
        if (_underlyingToken == address(0)) revert UnstakeManager_InvalidUnderlyingToken();
        if (_lsToken == address(0)) revert UnstakeManager_InvalidLSToken();
        if (_silo == address(0)) revert UnstakeManager_InvalidSilo();
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        vault = _vault;
        underlyingToken = IERC20Upgradeable(_underlyingToken);
        lsToken = ILSToken(_lsToken);
        silo = ITokenSilo(_silo);

        underlyingSymbol = _getTokenSymbol(_underlyingToken);
        lsTokenSymbol = _getTokenSymbol(_lsToken);

        uint8 _underlyingDecimals = IERC20MetadataUpgradeable(_underlyingToken).decimals();
        if (_underlyingDecimals > 18) revert UnstakeManager_UnsupportedDecimals();
        underlyingDecimals = _underlyingDecimals;
        decimalScaleFactor = 10**(18 - _underlyingDecimals);
        nextRequestId = 1;

        cooldownPeriod = 7 days;
        maxCooldownPeriod = 30 days;
        minUnstakeAmount = 0.1 ether;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(VAULT_ROLE, _vault);
        _grantRole(MANAGER_ROLE, msg.sender);

        if (!hasRole(VAULT_ROLE, _vault)) revert UnstakeManager_VaultRoleNotGranted();
        version = 1;
    }

    /**
     * @notice Safely gets a token's symbol, returning "UNKNOWN" if the call fails.
     */
    function _getTokenSymbol(address token) internal view returns (string memory) {
        try IERC20MetadataUpgradeable(token).symbol() returns (string memory symbol) {
            return symbol;
        } catch {
            return "UNKNOWN";
        }
    }

    /**
     * @notice Internal function to transfer underlying tokens from the main LSTokenVault.
     * @dev This is a critical step in the processing flow, moving funds from the vault to this contract.
     */
    function _transferFromVault(uint256 amount) internal {
        if (underlyingToken.balanceOf(vault) < amount) revert UnstakeManager_InsufficientVaultBalance();
        underlyingToken.safeTransferFrom(vault, address(this), amount);
    }

    /**
     * @notice Sets the address of the global EmergencyController.
     */
    function setEmergencyController(address _emergencyController) external override onlyRole(ADMIN_ROLE) {
        if (_emergencyController == address(0)) revert UnstakeManager_InvalidController();
        emergencyController = IEmergencyController(_emergencyController);
        emit EmergencyControllerSet(_emergencyController);
    }

    /**
     * @notice Sets the cooldown period for unstaking.
     */
    function setCooldownPeriod(uint256 _period) external override onlyRole(ADMIN_ROLE) {
        if (_period == 0 || _period > maxCooldownPeriod) revert UnstakeManager_InvalidPeriod();
        cooldownPeriod = _period;
        emit CooldownPeriodSet(_period);
    }

    /**
     * @notice Sets the minimum amount for a single unstake request.
     */
    function setMinUnstakeAmount(uint256 _amount) external override onlyRole(ADMIN_ROLE) {
        if (_amount == 0) revert UnstakeManager_AmountMustBePositive();
        minUnstakeAmount = _amount;
        emit MinUnstakeAmountSet(_amount);
    }

    /**
     * @notice Creates an unstake request for a user.
     * @dev This function is the entry point for the unstaking flow. It can only be called by the LSTokenVault.
     * It burns the user's LSTokens, calculates the equivalent underlying amount, and adds a request to the queue.
     * @param user The user initiating the unstake.
     * @param lsTokenAmount The amount of LSTokens to burn.
     * @param minUnderlyingAmount The minimum underlying amount the user will accept (slippage protection).
     * @param currentIndex The current LSToken index, provided by the vault.
     */
    function requestUnstake(
        address user,
        uint256 lsTokenAmount,
        uint256 minUnderlyingAmount,
        uint256 currentIndex
    ) external override onlyRole(VAULT_ROLE) {
        if (lsTokenAmount < minUnstakeAmount) revert UnstakeManager_BelowMinUnstake();
        if (user == address(0)) revert UnstakeManager_InvalidUserAddress();
        if (unstakeRequests[user].lsTokenAmount != 0) revert UnstakeManager_ActiveUnstakePending();

        lsToken.burnFrom(user, lsTokenAmount);

        UD60x18 lsTokenUD = safeWrap(lsTokenAmount);
        UD60x18 currentIndexUD = safeWrap(currentIndex);
        UD60x18 precisionUD = safeWrap(1e18);

        uint256 amountIn18Decimal = safeUnwrap(lsTokenUD.mul(currentIndexUD).div(precisionUD));
        if (minUnderlyingAmount > 0) {
            if (amountIn18Decimal < minUnderlyingAmount) revert UnstakeManager_SlippageTooHigh();
        }
        uint256 amountInUnderlyingUnit = amountIn18Decimal / decimalScaleFactor;
        if (amountInUnderlyingUnit == 0) revert UnstakeManager_UnderlyingAmountIsZero();

        uint256 requestId = nextRequestId++;
        unstakeRequests[user] = UnstakeRequest({
            lsTokenAmount: lsTokenAmount,
            requestTimestamp: block.timestamp,
            underlyingAmount: amountInUnderlyingUnit,
            status: RequestStatus.QUEUED,
            requestId: requestId
        });
        requestIdToAddress[requestId] = user;
        queuedRequestIds.push(requestId);
        queueLength++;
        totalQueuedUnstakeAmount += amountInUnderlyingUnit;

        emit UnstakeRequested(user, lsTokenAmount, amountIn18Decimal, block.timestamp + cooldownPeriod, requestId);
        emit UnstakeStatusChanged(user, RequestStatus.QUEUED, requestId);
    }

    /**
     * @notice Allows a manager to flag specific requests as ready for processing.
     * @dev This is the first step of the two-step manual processing flow.
     * It changes the request
     * status from `QUEUED` to `PROCESSING`.
     * @param requestIds An array of request IDs to mark.
     * @return processedCount The number of requests successfully marked.
     */
    function markRequestsForProcessing(uint256[] calldata requestIds)
    external override onlyRole(MANAGER_ROLE) nonReentrant returns (uint256 processedCount)
    {
        if (requestIds.length == 0) revert UnstakeManager_EmptyRequestList();
        uint256 count = 0;

        for (uint256 i = 0; i < requestIds.length; i++) {
            uint256 requestId = requestIds[i];
            address user = requestIdToAddress[requestId];

            if (user == address(0)) continue;
            UnstakeRequest storage request = unstakeRequests[user];
            if (request.status != RequestStatus.QUEUED || request.requestId != requestId) continue;
            request.status = RequestStatus.PROCESSING;

            count++;
            emit UnstakeStatusChanged(user, RequestStatus.PROCESSING, requestId);
        }
        return count;
    }

    /**
     * @notice internal function to remove a request ID from the queue array.
     * @dev Uses the "swap with last and pop" method to avoid costly array shifting.
     */
    function _removeFromQueue(uint256 requestId) private {
        for (uint256 i = 0; i < queuedRequestIds.length; i++) {
            if (queuedRequestIds[i] == requestId) {
                if (i < queuedRequestIds.length - 1) {
                    queuedRequestIds[i] = queuedRequestIds[queuedRequestIds.length - 1];
                }
                queuedRequestIds.pop();
                break;
            }
        }
    }

    /**
     * @notice Processes a batch of unstake requests that have been marked for processing.
     * @dev This is the second step of the manual processing flow.
     * It pulls the required amount of
     * underlying tokens from the LSTokenVault and deposits them into the TokenSilo for the users.
     * @param batchSize The maximum number of requests to process in this transaction.
     * @return processed The number of requests successfully processed.
     * @return remaining The number of requests still left in the queue.
     */
    function processUnstakeQueue(uint256 batchSize)
    external override onlyRole(MANAGER_ROLE) nonReentrant returns (uint256 processed, uint256 remaining)
    {
        if (address(silo) == address(0)) revert UnstakeManager_SiloNotSet();
        if (address(emergencyController) == address(0)) revert UnstakeManager_EmergencyControllerNotSet();
        IEmergencyController.EmergencyState state = emergencyController.getEmergencyState();
        if (state == IEmergencyController.EmergencyState.FULL_PAUSE || state == IEmergencyController.EmergencyState.WITHDRAWALS_PAUSED) {
            revert UnstakeManager_SystemDepositsPaused();
        }
        uint256 vaultBalance = underlyingToken.balanceOf(vault);
        uint256 successCount = 0;
        uint256 totalAmountToProcess = 0;
        address[] memory usersToProcess = new address[](batchSize);
        uint256[] memory requestIdsToProcess = new uint256[](batchSize);
        uint256[] memory amountsToProcess = new uint256[](batchSize);

        uint256 batchIndex = 0;
        for (uint256 i = 0; i < queuedRequestIds.length && batchIndex < batchSize; i++) {
            uint256 requestId = queuedRequestIds[i];
            address user = requestIdToAddress[requestId];

            if (user == address(0)) continue;

            UnstakeRequest storage request = unstakeRequests[user];
            if (request.status != RequestStatus.PROCESSING || request.requestId != requestId) continue;

            if (totalAmountToProcess + request.underlyingAmount <= vaultBalance) {
                usersToProcess[batchIndex] = user;
                requestIdsToProcess[batchIndex] = requestId;
                amountsToProcess[batchIndex] = request.underlyingAmount;
                totalAmountToProcess += request.underlyingAmount;
                batchIndex++;
            }
        }

        if (batchIndex > 0 && totalAmountToProcess > 0) {
            _transferFromVault(totalAmountToProcess);
            underlyingToken.safeApprove(address(silo), 0);
            underlyingToken.safeApprove(address(silo), totalAmountToProcess);

            for (uint256 i = 0; i < batchIndex; i++) {
                address user = usersToProcess[i];
                uint256 requestId = requestIdsToProcess[i];
                uint256 amount = amountsToProcess[i];

                if (user == address(0) || amount == 0) continue;
                try silo.depositFor(user, amount) {
                    unstakeRequests[user].status = RequestStatus.PROCESSED;
                    _removeFromQueue(requestId);
                    queueLength--;
                    totalQueuedUnstakeAmount -= amount;
                    successCount++;
                    emit UnstakeProcessed(user, amount, requestId);
                    emit UnstakeStatusChanged(user, RequestStatus.PROCESSED, requestId);
                } catch {
                    underlyingToken.safeTransfer(vault, amount);
                    emit UnstakeProcessingFailed(user, amount, requestId);
                }
            }
            underlyingToken.safeApprove(address(silo), 0);
        }
        return (successCount, queueLength);
    }

    /**
     * @notice Allows a manager to process a single user's unstake request directly, bypassing the two-step flow.
     * @dev This is useful for handling specific or urgent requests.
     * It moves a request from `QUEUED`
     * directly to `PROCESSED`.
     * @param user The address of the user whose request should be processed.
     * @return processed True if the request was successfully processed.
     */
    function processUserUnstake(address user)
    external override onlyRole(MANAGER_ROLE) nonReentrant returns (bool processed)
    {
        if (address(silo) == address(0)) revert UnstakeManager_SiloNotSet();
        if (user == address(0)) revert UnstakeManager_InvalidUserAddress();
        if (address(emergencyController) == address(0)) revert UnstakeManager_EmergencyControllerNotSet();
        IEmergencyController.EmergencyState state = emergencyController.getEmergencyState();
        if (state == IEmergencyController.EmergencyState.FULL_PAUSE || state == IEmergencyController.EmergencyState.WITHDRAWALS_PAUSED) {
            revert UnstakeManager_SystemDepositsPaused();
        }
        UnstakeRequest storage request = unstakeRequests[user];
        if (request.status != RequestStatus.QUEUED) revert UnstakeManager_RequestNotInQueueOrProcessing();

        uint256 underlyingAmount = request.underlyingAmount;
        uint256 requestId = request.requestId;
        _transferFromVault(underlyingAmount);
        underlyingToken.safeApprove(address(silo), 0);
        underlyingToken.safeApprove(address(silo), underlyingAmount);
        try silo.depositFor(user, underlyingAmount) {
            request.status = RequestStatus.PROCESSED;
            emit UnstakeStatusChanged(user, RequestStatus.PROCESSED, requestId);
            _removeFromQueue(requestId);
            queueLength--;
            totalQueuedUnstakeAmount -= underlyingAmount;
            emit UnstakeProcessed(user, underlyingAmount, requestId);
        } catch {
            // Return funds to the vault on failure
            underlyingToken.safeTransfer(vault, underlyingAmount);
            emit UnstakeProcessingFailed(user, underlyingAmount, requestId);
            // Reset approval
            underlyingToken.safeApprove(address(silo), 0);
            return false; // Explicitly return false on failure
        }

        // Reset approval on success
        underlyingToken.safeApprove(address(silo), 0);
        return true;
    }

    /**
     * @notice Allows a user to claim their underlying tokens after the cooldown period has ended.
     * @dev This function is callable by the user themselves.
     * It commands the TokenSilo to transfer
     * the funds to the user and cleans up the completed request from storage.
     * @param user The user who is claiming their funds.
     */
    function claim(address user) external override nonReentrant {
        if (msg.sender != vault && msg.sender != user) revert UnstakeManager_NotAuthorized();
        if (address(emergencyController) == address(0)) revert UnstakeManager_EmergencyControllerNotSet();
        IEmergencyController.EmergencyState eState = emergencyController.getEmergencyState();
        if (eState == IEmergencyController.EmergencyState.WITHDRAWALS_PAUSED || eState == IEmergencyController.EmergencyState.FULL_PAUSE) {
            revert UnstakeManager_WithdrawalsPaused();
        }
        if (emergencyController.isRecoveryModeActive()) revert UnstakeManager_RecoveryModeActive();

        UnstakeRequest storage request = unstakeRequests[user];
        if (request.lsTokenAmount == 0) revert UnstakeManager_NoPendingUnstake();
        if (request.status != RequestStatus.PROCESSED) revert UnstakeManager_UnstakeNotProcessed();
        if (block.timestamp < request.requestTimestamp + cooldownPeriod) revert UnstakeManager_CooldownNotFinished();
        uint256 amountToClaim = silo.balanceOf(user);
        if (amountToClaim == 0) revert UnstakeManager_NoBalanceInSilo();

        uint256 requestId = request.requestId;

        delete unstakeRequests[user];
        delete requestIdToAddress[requestId];

        silo.withdrawTo(user, amountToClaim);

        emit Claimed(user, amountToClaim, requestId);
    }

    /**
     * @notice Internal logic to process an early withdrawal for a given user.
     * @dev This function contains the core checks and state changes for early withdrawals.
     * @param user The user who is withdrawing.
     */
    function _earlyWithdraw(address user) internal {
        if (address(silo) == address(0)) revert UnstakeManager_SiloNotSet();
        if (address(emergencyController) == address(0)) revert UnstakeManager_EmergencyControllerNotSet();
        IEmergencyController.EmergencyState eState = emergencyController.getEmergencyState();
        if (eState == IEmergencyController.EmergencyState.WITHDRAWALS_PAUSED || eState == IEmergencyController.EmergencyState.FULL_PAUSE) {
            revert UnstakeManager_WithdrawalsPaused();
        }
        if (emergencyController.isRecoveryModeActive()) revert UnstakeManager_RecoveryModeActive();

        UnstakeRequest storage request = unstakeRequests[user];
        if (request.lsTokenAmount == 0) revert UnstakeManager_NoPendingUnstake();
        if (request.status != RequestStatus.PROCESSED) revert UnstakeManager_UnstakeNotProcessed();

        uint256 amountToWithdraw = silo.balanceOf(user);
        if (amountToWithdraw == 0) revert UnstakeManager_NoBalanceInSilo();

        uint256 requestId = request.requestId;

        // Clean up the user's request state
        delete unstakeRequests[user];
        delete requestIdToAddress[requestId];

        // Call the silo to perform the early withdrawal
        ITokenSilo(silo).earlyWithdrawFor(user, amountToWithdraw);

        emit Claimed(user, amountToWithdraw, requestId);
    }

    /**
     * @notice Allows a user to withdraw their funds from the silo before the cooldown period ends, for a fee.
     * @dev This is a wrapper around the internal _earlyWithdraw function.
     */
    function earlyWithdraw() external override nonReentrant {
        _earlyWithdraw(msg.sender);
    }

    /**
     * @notice Allows a manager to cancel a user's pending unstake request.
     * @dev This function deletes the request and re-mints the user's LSTokens, effectively
     * reversing the `requestUnstake` action.
     * @param user The user whose request should be cancelled.
     * @return success True if the cancellation was successful.
     */
    function cancelUnstake(address user)
    external override onlyRole(MANAGER_ROLE) nonReentrant returns (bool success)
    {
        if (ILSTokenVault(vault).isVestingActive()) revert UnstakeManager_CannotCancelDuringVesting();
        UnstakeRequest storage request = unstakeRequests[user];
        if (request.lsTokenAmount == 0) revert UnstakeManager_NoPendingUnstake();
        if (user == address(0)) revert UnstakeManager_InvalidUserAddress();
        if (request.status != RequestStatus.QUEUED && request.status != RequestStatus.PROCESSING) {
            revert UnstakeManager_CannotCancelProcessedRequest();
        }
        uint256 amountInUnderlyingUnit = request.underlyingAmount;
        uint256 requestId = request.requestId;

        uint256 targetIndex = ILSTokenVault(vault).targetIndex();
        uint256 amountIn18Decimal = amountInUnderlyingUnit * decimalScaleFactor;
        uint256 lsTokenAmount = _convertTokens(amountIn18Decimal, targetIndex, 1e18, true);
        delete unstakeRequests[user];
        delete requestIdToAddress[requestId];

        _removeFromQueue(requestId);
        queueLength--;
        totalQueuedUnstakeAmount -= amountInUnderlyingUnit;
        lsToken.mint(user, lsTokenAmount);

        emit UnstakeStatusChanged(user, RequestStatus.CANCELLED, requestId);
        return true;
    }

    /**
     * @notice Allows a manager to trigger an early withdrawal on behalf of a user.
     * @dev This function is protected by the MANAGER_ROLE.
     * @param user The user for whom to trigger the early withdrawal.
     */
    function managerEarlyWithdraw(address user) external override onlyRole(MANAGER_ROLE) nonReentrant
    {
        if (user == address(0)) revert UnstakeManager_InvalidUserAddress();
        _earlyWithdraw(user);
    }

    /**
     * @notice A view function to get the status and details of a specific user's unstake request.
     */
    function getRequestInfo(address user)
    external view override returns (
        RequestStatus status,
        uint256 amount,
        uint256 requestTimestamp,
        uint256 unlockTimestamp
    )
    {
        UnstakeRequest storage request = unstakeRequests[user];
        if (request.lsTokenAmount == 0) {
            return (RequestStatus.NONE, 0, 0, 0);
        }

        return (
            request.status,
            request.underlyingAmount,
            request.requestTimestamp,
            request.requestTimestamp + cooldownPeriod
        );
    }

    /**
     * @notice A view function to get a paginated list of all active requests in the queue.
     */
    function viewUnstakeQueue(uint256 limit)
    external view override returns (
        address[] memory users,
        uint256[] memory amounts,
        RequestStatus[] memory statuses,
        uint256[] memory requestIds
    )
    {
        uint256 activeCount = 0;
        for (uint256 i = 0; i < queuedRequestIds.length; i++) {
            address user = requestIdToAddress[queuedRequestIds[i]];
            if (user == address(0)) continue;

            UnstakeRequest storage request = unstakeRequests[user];
            if (request.status != RequestStatus.PROCESSED && request.status != RequestStatus.CANCELLED) {
                activeCount++;
            }
        }

        uint256 size = limit < activeCount ?
            limit : activeCount;

        users = new address[](size);
        amounts = new uint256[](size);
        statuses = new RequestStatus[](size);
        requestIds = new uint256[](size);
        uint256 index = 0;
        for (uint256 i = 0; i < queuedRequestIds.length && index < size; i++) {
            uint256 requestId = queuedRequestIds[i];
            address user = requestIdToAddress[requestId];

            if (user == address(0)) continue;

            UnstakeRequest storage request = unstakeRequests[user];
            if (request.status != RequestStatus.PROCESSED && request.status != RequestStatus.CANCELLED) {
                users[index] = user;
                amounts[index] = request.underlyingAmount;
                statuses[index] = request.status;
                requestIds[index] = requestId;
                index++;
            }
        }

        return (users, amounts, statuses, requestIds);
    }

    /**
     * @notice A view function to get high-level metrics about the state of the unstake queue.
     */
    function getQueueDetails()
    external view override returns (
        uint256 totalSize,
        uint256 totalUnderlying,
        uint256 queuedCount,
        uint256 processingCount
    )
    {
        uint256 _queuedCount = 0;
        uint256 _processingCount = 0;

        for (uint256 i = 0; i < queuedRequestIds.length; i++) {
            address user = requestIdToAddress[queuedRequestIds[i]];
            if (user == address(0)) continue;

            UnstakeRequest storage request = unstakeRequests[user];
            if (request.status == RequestStatus.QUEUED) {
                _queuedCount++;
            } else if (request.status == RequestStatus.PROCESSING) {
                _processingCount++;
            }
        }

        return (
            queueLength,
            totalQueuedUnstakeAmount,
            _queuedCount,
            _processingCount
        );
    }

    // --- Role and Upgrade Functions ---
    function grantRole(bytes32 role, address account) public override(AccessControlUpgradeable, IUnstakeManager) onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    function requestUpgrade() external onlyRole(ADMIN_ROLE) {
        if (upgradeRequested) {
            if (block.timestamp < upgradeRequestTime + UPGRADE_TIMELOCK) revert UnstakeManager_TimelockPending();
        }
        upgradeRequestTime = block.timestamp;
        upgradeRequested = true;
        emit UpgradeRequested(upgradeRequestTime);
    }

    function cancelUpgrade() external onlyRole(ADMIN_ROLE) {
        if (!upgradeRequested) revert UnstakeManager_NoUpgradeToCancel();
        upgradeRequested = false;
        emit UpgradeCancelled(upgradeRequestTime);
        upgradeRequestTime = 0;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
        if (newImplementation == address(0)) revert UnstakeManager_InvalidImplementation();
        if (!upgradeRequested) revert UnstakeManager_UpgradeNotRequested();
        if (block.timestamp < upgradeRequestTime + UPGRADE_TIMELOCK) revert UnstakeManager_TimelockNotExpired();

        upgradeRequested = false;

        version++;
        emit UpgradeAuthorized(newImplementation, Strings.toString(version - 1));
    }

    uint256[40] private __gap;
}