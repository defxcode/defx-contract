// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// External libraries and contracts
import {UD60x18, wrap, unwrap} from "@prb/math/src/UD60x18.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/IERC20MetadataUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IEmergencyController.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

// --- Custom Errors ---
error Silo_InvalidUnderlyingToken();
error Silo_InvalidVault();
error Silo_InvalidFeeCollector();
error Silo_InvalidController();
error Silo_CannotDepositToZero();
error Silo_AmountIsZero();
error Silo_DepositsPaused();
error Silo_WithdrawalsPaused();
error Silo_RecoveryModeActive();
error Silo_CannotWithdrawToZero();
error Silo_ClaimsPausedDueToLiquidity();
error Silo_InsufficientUserBalance();
error Silo_InsufficientLiquidityForClaim();
error Silo_EarlyUnlockDisabled();
error Silo_InsufficientBalance();
error Silo_DailyWithdrawalLimitReached();
error Silo_InvalidThreshold();
error Silo_FeeTooHigh();
error Silo_ZeroAddress();
error Silo_ZeroAmount();
error Silo_InsufficientBalanceForRescue();
error Silo_InvalidImplementation();
error Silo_UpgradeNotRequested();
error Silo_TimelockNotExpired();
error Silo_TimelockPending();
error Silo_NoUpgradeToCancel();
error Silo_ValueTooLarge();
error Silo_UnwrapUnderflow();
error Silo_UnsupportedDecimals();

/**
* @title TokenSilo
* @notice A temporary holding contract for underlying tokens during the unstaking cooldown period.
* It ensures that funds designated for withdrawal are segregated from the main vault's liquidity.
* @dev This contract receives funds from the UnstakeManager and holds them until a user claims them
* after the cooldown or withdraws them early (if enabled).
*/
contract TokenSilo is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // --- Roles ---
    /// @notice The VAULT_ROLE is granted to contracts that are allowed to deposit into and withdraw from the silo.
    /// @dev This is typically the UnstakeManager, which moves funds on behalf of users.
    bytes32 public constant VAULT_ROLE = keccak256("VAULT_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // --- State Variables ---
    uint256 internal decimalScaleFactor;
    IERC20Upgradeable public underlyingToken;
    string public tokenSymbol;
    IEmergencyController public emergencyController;
    uint8 public underlyingDecimals;
    /// @notice Tracks the amount of underlying tokens each user has waiting in the silo.
    mapping(address => uint256) public userDeposits;
    /// @notice Aggregates the overall state of the silo for accounting and health checks.
    struct SiloState {
        uint256 totalWithdrawn; // Total amount ever withdrawn (regular + early).
        uint256 totalPendingClaims; // Total amount currently held in the silo waiting for user claims.
        uint256 totalCollectedFees;
        // Total fees collected from early withdrawals.
        uint256 lastActivityTimestamp; // Timestamp of the last deposit or withdrawal.
    }

    SiloState public state;

    /// @notice Configuration for the early withdrawal feature.
    struct CooldownConfig {
        uint256 unlockFee;
        // The fee (in basis points) for early withdrawal.
        bool earlyUnlockEnabled; // Flag to enable/disable the early withdrawal feature.
        address feeCollector; // The address that receives early withdrawal fees.
        bool claimsPaused;
        // A flag automatically triggered if liquidity drops below the threshold.
        uint256 liquidityThreshold;
        // The minimum liquidity ratio (balance / pending claims) required.
    }

    CooldownConfig public config;
    /// @notice Configuration for withdrawal rate limiting.
    struct RateLimit {
        uint256 maxDailyAmount;
        // Max total amount that can be withdrawn in a 24h period.
        uint256 currentAmount;
        // The amount withdrawn in the current 24h window.
        uint256 windowStartTime; // Start time of the current 24h window.
    }

    RateLimit public withdrawalLimit;

    // --- Upgrade Control ---
    struct UpgradeControl {
        uint256 version;
        uint256 requestTime;
        bool requested;
    }

    UpgradeControl public upgradeControl;
    uint256 public constant UPGRADE_TIMELOCK = 2 days;
    /**
     * @notice Safe wrapper for UD60x18 with bounds checking
    */
    function safeWrap(uint256 value) internal pure returns (UD60x18) {
        if (value > type(uint256).max / 1e18) revert Silo_ValueTooLarge();
        return wrap(value);
    }

    /**
     * @notice Safe unwrapper for UD60x18 with bounds checking
    */
    function safeUnwrap(UD60x18 value) internal pure returns (uint256) {
        uint256 result = unwrap(value);
        return result;
    }

    // --- Events ---
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
    event VersionUpdated(string newVersion);
    event UpgradeRequested(uint256 requestTime);
    event UpgradeAuthorized(address indexed implementation, string currentVersion);
    event UpgradeCancelled(uint256 requestTime);
    event EmergencyControllerSet(address indexed controller);
    event RateLimitUpdated(uint256 maxDailyWithdrawalAmount);
    event DailyLimitReset(uint256 timestamp);
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the silo contract with its core parameters.
     * @dev Called by the VaultFactory during deployment.
    * @param _underlyingToken The underlying token address.
    * @param _tokenSymbol The token symbol.
    * @param vault The address that will be granted VAULT_ROLE (typically the UnstakeManager).
     */
    function initialize(
        address _underlyingToken,
        string memory _tokenSymbol,
        address vault,
        address _feeCollector
    ) public initializer {
        if (_underlyingToken == address(0)) revert Silo_InvalidUnderlyingToken();
        if (vault == address(0)) revert Silo_InvalidVault();

        __ReentrancyGuard_init();
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();

        underlyingToken = IERC20Upgradeable(_underlyingToken);
        tokenSymbol = _tokenSymbol;

        uint8 _underlyingDecimals = IERC20MetadataUpgradeable(_underlyingToken).decimals();
        if (_underlyingDecimals > 18) revert Silo_UnsupportedDecimals();
        underlyingDecimals = _underlyingDecimals;
        decimalScaleFactor = 10**(18 - _underlyingDecimals);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(VAULT_ROLE, vault);
        _grantRole(EMERGENCY_ROLE, msg.sender);

        config.unlockFee = 50;
        config.earlyUnlockEnabled = false;
        if (_feeCollector == address(0)) revert Silo_InvalidFeeCollector();
        config.feeCollector = _feeCollector;
        config.claimsPaused = false;
        config.liquidityThreshold = 8000;

        withdrawalLimit.maxDailyAmount = 50_000 * (10 ** _underlyingDecimals);
        withdrawalLimit.windowStartTime = block.timestamp;

        upgradeControl.version = 1;
    }

    /**
     * @notice Sets the address of the global EmergencyController.
     */
    function setEmergencyController(address _emergencyController) external onlyRole(ADMIN_ROLE) {
        if (_emergencyController == address(0)) revert Silo_InvalidController();
        emergencyController = IEmergencyController(_emergencyController);
        emit EmergencyControllerSet(_emergencyController);
    }

    /**
     * @notice Receives funds from the UnstakeManager for a user who has processed an unstake request.
     * @dev This function is protected by `VAULT_ROLE`.
    * @param user The end user for whom the funds are being deposited.
    * @param amount The amount of underlying tokens to deposit.
     */
    function depositFor(address user, uint256 amount) external onlyRole(VAULT_ROLE) whenNotPaused nonReentrant {
        if (user == address(0)) revert Silo_CannotDepositToZero();
        if (amount == 0) revert Silo_AmountIsZero();

        if (address(emergencyController) != address(0)) {
            IEmergencyController.EmergencyState eState = emergencyController.getEmergencyState();
            if (eState == IEmergencyController.EmergencyState.WITHDRAWALS_PAUSED || eState == IEmergencyController.EmergencyState.FULL_PAUSE) {
                revert Silo_DepositsPaused();
            }
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }

        underlyingToken.safeTransferFrom(msg.sender, address(this), amount);

        userDeposits[user] += amount;
        state.totalPendingClaims += amount;
        state.lastActivityTimestamp = block.timestamp;

        _checkLiquidity();

        emit Deposited(user, amount);
    }

    /**
     * @notice Sends funds to a user who is claiming their unstaked tokens after the cooldown period.
     * @dev This function is protected by `VAULT_ROLE` and is called by the UnstakeManager.
    * @param user The user who is claiming their funds.
    * @param amount The amount of underlying tokens to withdraw.
     */
    function withdrawTo(address user, uint256 amount) external onlyRole(VAULT_ROLE) whenNotPaused nonReentrant {
        if (user == address(0)) revert Silo_CannotWithdrawToZero();
        if (amount == 0) revert Silo_AmountIsZero();
        if (config.claimsPaused) revert Silo_ClaimsPausedDueToLiquidity();
        if (userDeposits[user] < amount) revert Silo_InsufficientUserBalance();

        if (address(emergencyController) != address(0)) {
            IEmergencyController.EmergencyState eState = emergencyController.getEmergencyState();
            if (eState == IEmergencyController.EmergencyState.WITHDRAWALS_PAUSED || eState == IEmergencyController.EmergencyState.FULL_PAUSE) {
                revert Silo_WithdrawalsPaused();
            }
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }

        uint256 siloBalance = underlyingToken.balanceOf(address(this));
        if (siloBalance < amount) {
            emit LiquidityAlert(siloBalance, amount);
            revert Silo_InsufficientLiquidityForClaim();
        }

        userDeposits[user] -= amount;
        state.totalPendingClaims -= amount;
        state.totalWithdrawn += amount;
        state.lastActivityTimestamp = block.timestamp;

        underlyingToken.safeTransfer(user, amount);

        _checkLiquidity();

        emit Withdrawn(user, amount);
    }

    /**
     * @notice Allows a user to withdraw their funds from the silo before the cooldown period ends, for a fee.
     * @dev This function is subject to rate limiting.
    * @param amount The amount the user wishes to withdraw early.
    * @param user The user who on behalf the call is called
     */
    function earlyWithdrawFor(address user, uint256 amount) external onlyRole(VAULT_ROLE) whenNotPaused nonReentrant {
        if (!config.earlyUnlockEnabled) revert Silo_EarlyUnlockDisabled();
        if (config.claimsPaused) revert Silo_ClaimsPausedDueToLiquidity();
        if (amount == 0) revert Silo_AmountIsZero();
        if (userDeposits[user] < amount) revert Silo_InsufficientBalance();

        if (address(emergencyController) != address(0)) {
            IEmergencyController.EmergencyState eState = emergencyController.getEmergencyState();
            if (eState == IEmergencyController.EmergencyState.WITHDRAWALS_PAUSED || eState == IEmergencyController.EmergencyState.FULL_PAUSE) {
                revert Silo_WithdrawalsPaused();
            }
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }

        _validateRateLimit(amount);

        uint256 amountIn18Decimal = amount * decimalScaleFactor;
        UD60x18 amountUD = safeWrap(amountIn18Decimal);
        UD60x18 feeUD = safeWrap(config.unlockFee);
        UD60x18 basisPointsUD = safeWrap(10000);

        uint256 feeAmountIn18Decimal = safeUnwrap(amountUD.mul(feeUD).div(basisPointsUD));
        uint256 amountAfterFeeIn18Decimal = amountIn18Decimal - feeAmountIn18Decimal;
        uint256 feeAmount = feeAmountIn18Decimal / decimalScaleFactor;
        uint256 amountAfterFee = amountAfterFeeIn18Decimal / decimalScaleFactor;

        uint256 siloBalance = underlyingToken.balanceOf(address(this));
        if (siloBalance < amount) {
            emit LiquidityAlert(siloBalance, amount);
            revert Silo_InsufficientLiquidityForClaim();
        }

        userDeposits[user] -= amount;
        state.totalPendingClaims -= amount;
        state.totalWithdrawn += amount;
        state.totalCollectedFees += feeAmount;
        state.lastActivityTimestamp = block.timestamp;
        if (feeAmount > 0 && config.feeCollector != address(0)) {
            underlyingToken.safeTransfer(config.feeCollector, feeAmount);
        }
        underlyingToken.safeTransfer(user, amountAfterFee);

        _checkLiquidity();

        emit EarlyWithdrawn(user, amount, feeAmount);
    }

    /**
     * @notice Internal function to check if the silo has enough funds to cover all pending claims.
     * @dev If the ratio of `balance / totalPendingClaims` falls below `liquidityThreshold`, it automatically
    * pauses all claims to prevent a bank run on an under-funded silo.
     */
    function _checkLiquidity() internal {
        if (state.totalPendingClaims == 0) {
            if (config.claimsPaused) {
                config.claimsPaused = false;
                emit ClaimsPausedSet(false);
            }
            return;
        }

        uint256 siloBalance = underlyingToken.balanceOf(address(this));
        uint256 siloBalanceIn18Decimal = siloBalance * decimalScaleFactor;
        uint256 pendingClaimsIn18Decimal = state.totalPendingClaims * decimalScaleFactor;
        UD60x18 siloBalanceUD = safeWrap(siloBalanceIn18Decimal);
        UD60x18 pendingClaimsUD = safeWrap(pendingClaimsIn18Decimal);
        UD60x18 basisPointsUD = safeWrap(10000);

        uint256 liquidityRatio = safeUnwrap(
            siloBalanceUD.mul(basisPointsUD).div(pendingClaimsUD)
        );
        if (liquidityRatio < config.liquidityThreshold && !config.claimsPaused) {
            config.claimsPaused = true;
            emit ClaimsPausedSet(true);
            emit LiquidityAlert(siloBalance, state.totalPendingClaims);
        }
        else if (liquidityRatio >= config.liquidityThreshold && config.claimsPaused) {
            config.claimsPaused = false;
            emit ClaimsPausedSet(false);
        }
    }

    /**
     * @notice Internal function to validate a withdrawal against daily rate limits.
     */
    function _validateRateLimit(uint256 amount) internal {
        if (address(emergencyController) != address(0) && emergencyController.isRecoveryModeActive()) return;
        if (block.timestamp >= withdrawalLimit.windowStartTime + 1 days) {
            withdrawalLimit.currentAmount = 0;
            withdrawalLimit.windowStartTime = block.timestamp;
            emit DailyLimitReset(block.timestamp);
        }

        if (withdrawalLimit.currentAmount + amount > withdrawalLimit.maxDailyAmount) revert Silo_DailyWithdrawalLimitReached();
        withdrawalLimit.currentAmount += amount;
    }

    /**
     * @notice Gets the amount of underlying tokens a specific user has in the silo.
     */
    function balanceOf(address user) external view returns (uint256) {
        return userDeposits[user];
    }

    /**
     * @notice Gets the total amount of underlying tokens currently held in the silo for all users.
     */
    function getTotalDeposited() external view returns (uint256) {
        return state.totalPendingClaims;
    }

    /**
     * @notice A view function to calculate the fee for an early withdrawal without executing it.
    * @param amount The amount to calculate the fee for.
    * @return feeAmount The calculated fee.
    * @return netAmount The amount the user would receive after the fee.
     */
    function calculateEarlyWithdrawalFee(uint256 amount) external view returns (uint256 feeAmount, uint256 netAmount) {
        uint256 amountIn18Decimal = amount * decimalScaleFactor;
        UD60x18 amountUD = safeWrap(amountIn18Decimal);
        UD60x18 feeUD = safeWrap(config.unlockFee);
        UD60x18 basisPointsUD = safeWrap(10000);

        uint256 feeAmountIn18Decimal = safeUnwrap(amountUD.mul(feeUD).div(basisPointsUD));
        uint256 netAmountIn18Decimal = amountIn18Decimal - feeAmountIn18Decimal;

        feeAmount = feeAmountIn18Decimal / decimalScaleFactor;
        netAmount = netAmountIn18Decimal / decimalScaleFactor;
        return (feeAmount, netAmount);
    }

    /**
     * @notice A view function that returns a comprehensive status of the silo's liquidity.
     */
    function getLiquidityStatus() external view returns (
        uint256 liquidity,
        uint256 pendingClaims,
        uint256 ratio,
        bool isPaused,
        IEmergencyController.EmergencyState emergencyState
    ) {
        uint256 siloBalance = underlyingToken.balanceOf(address(this));
        uint256 liquidityRatio;
        if (state.totalPendingClaims > 0) {
            uint256 siloBalanceIn18Decimal = siloBalance * decimalScaleFactor;
            uint256 pendingClaimsIn18Decimal = state.totalPendingClaims * decimalScaleFactor;
            UD60x18 siloBalanceUD = safeWrap(siloBalanceIn18Decimal);
            UD60x18 pendingClaimsUD = safeWrap(pendingClaimsIn18Decimal);
            UD60x18 basisPointsUD = safeWrap(10000);

            liquidityRatio = safeUnwrap(
                siloBalanceUD.mul(basisPointsUD).div(pendingClaimsUD)
            );
        } else {
            liquidityRatio = 10000;
            // 100% if no pending claims
        }

        IEmergencyController.EmergencyState eState = address(emergencyController) != address(0) ?
            emergencyController.getEmergencyState() : IEmergencyController.EmergencyState.NORMAL;

        return (siloBalance, state.totalPendingClaims, liquidityRatio, config.claimsPaused, eState);
    }

    // --- Admin functions ---
    function setClaimsPaused(bool paused) external onlyRole(ADMIN_ROLE) {
        if (address(emergencyController) != address(0)) {
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }
        config.claimsPaused = paused;
        emit ClaimsPausedSet(paused);
    }

    function setLiquidityThreshold(uint256 threshold) external onlyRole(ADMIN_ROLE) {
        if (address(emergencyController) != address(0)) {
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }
        if (threshold == 0 || threshold > 10000) revert Silo_InvalidThreshold();
        config.liquidityThreshold = threshold;
        emit LiquidityThresholdSet(threshold);
    }

    function setUnlockFee(uint256 _fee) external onlyRole(ADMIN_ROLE) {
        if (address(emergencyController) != address(0)) {
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }
        if (_fee > 1000) revert Silo_FeeTooHigh();
        config.unlockFee = _fee;
        emit UnlockFeeSet(_fee);
    }

    function setEarlyUnlockEnabled(bool _enabled) external onlyRole(ADMIN_ROLE) {
        if (address(emergencyController) != address(0)) {
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }
        config.earlyUnlockEnabled = _enabled;
        emit EarlyUnlockEnabledSet(_enabled);
    }

    function setFeeCollector(address _collector) external onlyRole(ADMIN_ROLE) {
        if (address(emergencyController) != address(0)) {
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }
        if (_collector == address(0)) revert Silo_ZeroAddress();
        config.feeCollector = _collector;
        emit FeeCollectorSet(_collector);
    }

    function adjustPendingClaims(uint256 newTotalPendingClaims) external onlyRole(ADMIN_ROLE) {
        state.totalPendingClaims = newTotalPendingClaims;
        _checkLiquidity();
    }

    function setRateLimit(uint256 _maxDailyWithdrawalAmount) external onlyRole(ADMIN_ROLE) {
        if (address(emergencyController) != address(0)) {
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }
        withdrawalLimit.maxDailyAmount = _maxDailyWithdrawalAmount;
        emit RateLimitUpdated(_maxDailyWithdrawalAmount);
    }

    function resetDailyLimit() external onlyRole(ADMIN_ROLE) {
        withdrawalLimit.currentAmount = 0;
        withdrawalLimit.windowStartTime = block.timestamp;
        emit DailyLimitReset(block.timestamp);
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(EMERGENCY_ROLE) {
        if (address(emergencyController) != address(0)) {
            if (emergencyController.isRecoveryModeActive()) revert Silo_RecoveryModeActive();
        }
        _unpause();
    }

    function rescueTokens(address token, address to, uint256 amount) external onlyRole(ADMIN_ROLE) {
        if (to == address(0)) revert Silo_ZeroAddress();
        if (amount == 0) revert Silo_ZeroAmount();

        if (token == address(underlyingToken)) {
            if (amount > underlyingToken.balanceOf(address(this))) revert Silo_InsufficientBalanceForRescue();
            state.totalPendingClaims = state.totalPendingClaims > amount ? state.totalPendingClaims - amount : 0;
            _checkLiquidity();
        }

        IERC20Upgradeable(token).safeTransfer(to, amount);
        emit RescuedTokens(token, to, amount);
    }

    function setVault(address _vault) external onlyRole(ADMIN_ROLE) {
        if (_vault == address(0)) revert Silo_InvalidVault();
        _grantRole(VAULT_ROLE, _vault);
    }

    // --- Upgrade Functions ---
    function requestUpgrade() external onlyRole(ADMIN_ROLE) {
        if (upgradeControl.requested) {
            if (block.timestamp < upgradeControl.requestTime + UPGRADE_TIMELOCK) revert Silo_TimelockPending();
        }
        upgradeControl.requestTime = block.timestamp;
        upgradeControl.requested = true;
        emit UpgradeRequested(upgradeControl.requestTime);
    }

    function cancelUpgrade() external onlyRole(ADMIN_ROLE) {
        if (!upgradeControl.requested) revert Silo_NoUpgradeToCancel();
        upgradeControl.requested = false;
        emit UpgradeCancelled(upgradeControl.requestTime);
        upgradeControl.requestTime = 0;
    }

    function upgradeRequested() external view returns (bool requested, uint256 requestTime) {
        return (upgradeControl.requested, upgradeControl.requestTime);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
        if (newImplementation == address(0)) revert Silo_InvalidImplementation();
        if (!upgradeControl.requested) revert Silo_UpgradeNotRequested();
        if (block.timestamp < upgradeControl.requestTime + UPGRADE_TIMELOCK) revert Silo_TimelockNotExpired();

        upgradeControl.requested = false;
        uint256 oldVersion = upgradeControl.version;
        upgradeControl.version++;

        emit UpgradeAuthorized(newImplementation, Strings.toString(oldVersion));
    }

    function getUnlockFee() external view returns (uint256) {
        return config.unlockFee;
    }

    function getEarlyUnlockEnabled() external view returns (bool) {
        return config.earlyUnlockEnabled;
    }

    function getFeeCollector() external view returns (address) {
        return config.feeCollector;
    }

    function getClaimsPaused() external view returns (bool) {
        return config.claimsPaused;
    }

    function getLiquidityThreshold() external view returns (uint256) {
        return config.liquidityThreshold;
    }

    uint256[41] private __gap;
}