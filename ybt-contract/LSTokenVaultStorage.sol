// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {UD60x18, wrap, unwrap} from "@prb/math/src/UD60x18.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "./interfaces/ILSToken.sol";
import "./interfaces/IUnstakeManager.sol";
import "./interfaces/IEmergencyController.sol";

// --- Custom Errors for PrecisionMath ---
error PrecisionMath_ValueTooLarge();
error PrecisionMath_UnwrapUnderflow();
error PrecisionMath_PercentageOutOfBounds();
error PrecisionMath_AllocationOverflow();
error Vault_InvalidUnderlyingToken();
error Vault_InvalidLSToken();
error Vault_InvalidAdmin();
error Vault_InvalidUnstakeManager();
error Vault_InvalidEmergencyController();
error Vault_EmergencyControllerNotSet();
error Vault_DepositsPaused();
error Vault_WithdrawalsPaused();
error Vault_RecoveryModeActive();
error Vault_StakingDisabled();
error Vault_UnstakingDisabled();
error Vault_AmountBelowMinimum();
error Vault_InvalidUser();
error Vault_GlobalDepositLimitReached();
error Vault_UserDepositLimitReached();
error Vault_SlippageTooHigh();
error Vault_LSTokenAmountIsZero();
error Vault_YieldMustBePositive();
error Vault_EmergencyModeActive();
error Vault_PreviousYieldVesting();
error Vault_NoLSTokenSupply();
error Vault_YieldTooLow();
error Vault_YieldTooHigh();
error Vault_IndexChangeTooHigh();
error Vault_UnstakeManagerNotSet();
error Vault_WithdrawalLockActive();
error Vault_InvalidRecipient();
error Vault_AmountMustBePositive();
error Vault_InsufficientVaultBalance();
error Vault_FeeReceiverNotSet();
error Vault_NoFeesToWithdraw();
error Vault_InsufficientBalanceForFees();
error Vault_InvalidImplementation();
error Vault_UpgradeNotRequested();
error Vault_TimelockNotExpired();
error Vault_PreviousUpgradePending();
error Vault_InvalidWallet();
error Vault_InvalidAllocation();
error Vault_TooManyCustodians();
error Vault_CustodianExists();
error Vault_InvalidCustodianId();
error Vault_CannotRemoveLastCustodian();
error Vault_DailyDepositLimit();
error Vault_DailyWithdrawalLimit();
error Vault_MaxTotalBelowCurrent();
error Vault_InvalidFloatPercentage();
error Vault_AllocationExceeds100();
error Vault_ReturnAmountExceedsCustodianFunds();
error Vault_FlashLoanImpactTooHigh(); // For setFlashLoanProtection
error Vault_FeeTooHigh();
error Vault_InvalidFeeReceiver();
error Vault_InvalidDuration();
error Vault_UnsupportedDecimals();

/**
 * @title PrecisionMath
 * @notice An abstract contract that provides safe, high-precision mathematical functions.
 * @dev It is built as a wrapper around the PRBMath UD60x18 library to handle common calculations
 * like percentages and token conversions with 18 decimals of precision, preventing overflow/underflow.
 */
abstract contract PrecisionMath {

    /**
     * @notice Safely converts a standard uint256 into the high-precision UD60x18 format.
     */
    function safeWrap(uint256 value) internal pure returns (UD60x18) {
        if (value > type(uint256).max / 1e18) revert PrecisionMath_ValueTooLarge();
        return wrap(value);
    }

    /**
     * @notice Safely converts a high-precision UD60x18 value back to a standard uint256.
     */
    function safeUnwrap(UD60x18 value) internal pure returns (uint256) {
        uint256 result = unwrap(value);
        return result;
    }

    /**
     * @notice Calculates `(amount * percentage) / precision` using high-precision math.
     */
    function calculatePercentage(
        uint256 amount,
        uint256 percentage,
        uint256 precision
    ) internal pure returns (uint256) {
        if (amount == 0 || percentage == 0) return 0;
        return Math.mulDiv(amount, percentage, precision);
    }

    /**
     * @notice Converts between two token amounts using a given exchange rate.
     * @dev Handles both deposit (underlying to LSToken) and withdrawal (LSToken to underlying) conversions.
     * @param isDeposit If true, calculates `input * precision / rate`. If false, calculates `input * rate / precision`.
     */
    function convertTokens(
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

    /**
     * @notice Converts a percentage (0-100) into a compact uint96 format for efficient storage.
     * @dev Stores the percentage with 16 decimals of precision (percent * 1e16).
     */
    function percentToAllocation(uint256 percent) internal pure returns (uint96) {
        if (percent > 100) revert PrecisionMath_PercentageOutOfBounds();
        uint256 allocation = percent * 1e16;
        if (allocation > type(uint96).max) revert PrecisionMath_AllocationOverflow();
        return uint96(allocation);
    }

    /**
     * @notice Converts a stored allocation value back into a standard percentage (0-100).
     */
    function allocationToPercent(uint96 allocation) internal pure returns (uint256) {
        return uint256(allocation) / 1e16;
    }
}

/**
 * @title LSTokenVaultStorage
 * @notice This abstract contract holds all the state variables and internal logic for the LSTokenVault.
 * @dev By separating storage from the main logic contract (LSTokenVault), we can upgrade the logic
 * without needing to migrate the data.
 */
abstract contract LSTokenVaultStorage is Initializable, PrecisionMath {

    // --- Constants ---
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant REWARDER_ROLE = keccak256("REWARDER_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    uint256 public constant INDEX_PRECISION = 1e18; // The precision factor for the index (18 decimals).
    uint256 public constant INITIAL_INDEX = 1e18; // The index starts at 1.0.
    uint256 public yieldVestingDuration; // Duration over which yield is vested.
    uint256 public constant MAX_INDEX_INCREASE_PERCENT = 10; // Max percentage the index can increase from a single yield deposit.
    uint256 public constant MAX_FEE_PERCENT = 30; // Max protocol fee percentage.
    uint256 public constant PERCENT_PRECISION = 100; // The precision factor for percentages.
    uint256 public constant MAX_CUSTODIANS = 10; // The maximum number of custodian wallets.

    // --- Token References ---
    IERC20Upgradeable public underlyingToken;
    ILSToken public lsToken;

    // --- Token Metadata ---
    string public underlyingSymbol;
    string public lsTokenSymbol;
    uint8 public underlyingDecimals;
    uint256 internal decimalScaleFactor;
    uint256 public minDepositAmount; // Minimum deposit size.

    // --- Index Tracking ---
    uint256 public lastIndex; // The index value at the start of the current vesting period.
    uint256 public targetIndex; // The target index value to be reached at the end of the vesting period.
    uint256 public lastUpdateTime; // Timestamp of the last time the index was updated.
    uint256 public vestingEndTime; // Timestamp when the current yield vesting period ends.

    // --- Fee Configuration ---
    uint256 public feePercent; // The percentage of yield taken as a protocol fee.
    address public feeReceiver; // The address that receives protocol fees.
    uint256 public totalFeeCollected; // The running total of collected fees waiting for withdrawal.

    // --- DYNAMIC Multi-Custodian ---
    struct CustodianData {
        address wallet;
        uint96 allocation; // The percentage of funds allocated to this custodian, stored efficiently.
    }

    CustodianData[] public custodians; // The dynamic array of custodian wallets.
    uint8 public floatPercent; // The percentage of deposits kept in the vault for liquidity.
    uint256 public totalCustodianFunds; // An accounting variable tracking the total funds sent to custodians.

    // --- Core State Variables ---
    bool public stakeEnabled; // A flag to enable/disable deposits.
    bool public unstakeEnabled; // A flag to enable/disable unstaking.
    uint256 public maxTotalDeposit; // The maximum total amount of underlying tokens allowed in the vault.
    uint256 public maxUserDeposit; // The maximum total amount a single user can deposit.
    uint256 public lastStateUpdate; // Timestamp of the last major state change.
    uint256 public totalDepositedAmount; // The total amount of underlying tokens ever deposited.
    mapping(address => uint256) public lastDepositTime; // Timestamp of the last deposit for each user.

    // --- Rate Limiting ---
    struct DailyLimit {
        uint128 maxAmount;
        uint128 currentAmount;
    }

    DailyLimit public depositLimit;
    DailyLimit public withdrawalLimit;
    uint256 public limitWindowStart; // The timestamp when the current 24-hour rate limit window started.

    // --- Flash Loan Protection ---
    uint16 public maxPriceImpactPercentage; // The max percentage the index can change in a single transaction.

    // --- Contract Links ---
    IUnstakeManager public unstakeManager;
    IEmergencyController public emergencyController;

    // --- Upgrade Control ---
    uint256 public version;
    uint256 public constant UPGRADE_TIMELOCK = 2 days;
    uint256 public upgradeRequestTime;
    bool public upgradeRequested;

    // --- Events ---
    event IndexUpdated(uint256 oldIndex, uint256 newIndex);
    event FeesCollected(uint256 amount);
    event CustodianTransfer(uint256 indexed custodianId, address indexed custodian, uint256 amount);
    event CustodianUpdated(uint256 indexed custodianId, address wallet, uint256 allocation);
    event CustodianAdded(uint256 indexed custodianId, address wallet, uint256 allocation);
    event CustodianRemoved(uint256 indexed custodianId, address wallet);
    event UnstakeManagerSet(address indexed unstakeManager);
    event EmergencyControllerSet(address indexed emergencyController);
    event Deposited(address indexed user, uint256 underlyingAmount, uint256 lsTokenAmount);
    event FeesWithdrawn(address indexed receiver, uint256 amount);

    /**
     * @notice Sets the initial default values for the vault's configuration upon initialization.
     * @param admin The address to be set as the initial fee receiver.
     */
    function _setupDefaults(address admin, uint8 _underlyingDecimals) internal {
        uint256 decimalsFactor = 10 ** _underlyingDecimals;

        minDepositAmount = (1 * decimalsFactor) / 10; // This is 0.1 tokens

        feePercent = 10;
        maxTotalDeposit = 1_000_000 * decimalsFactor;
        maxUserDeposit = 10_000 * decimalsFactor;
        floatPercent = 20;
        stakeEnabled = true;
        unstakeEnabled = true;
        yieldVestingDuration = 8 hours;
        feeReceiver = admin;

        depositLimit = DailyLimit({
            maxAmount: uint128(100_000 * decimalsFactor),
            currentAmount: 0
        });

        withdrawalLimit = DailyLimit({
            maxAmount: uint128(50_000 * decimalsFactor),
            currentAmount: 0
        });

        limitWindowStart = block.timestamp;
        maxPriceImpactPercentage = 300; // 3.00% represented as 300
        lastStateUpdate = block.timestamp;
    }

    /**
     * @notice Internal function to add a new custodian.
     */
    function _addCustodian(address wallet, uint256 allocationPercent) internal returns (uint256 custodianId) {
        if (wallet == address(0)) revert Vault_InvalidWallet();
        if (allocationPercent > 100) revert Vault_InvalidAllocation();
        if (custodians.length >= MAX_CUSTODIANS) revert Vault_TooManyCustodians();
        for (uint256 i = 0; i < custodians.length; i++) {
            if (custodians[i].wallet == wallet) revert Vault_CustodianExists();
        }

        uint256 totalAllocation = allocationPercent;
        for (uint256 i = 0; i < custodians.length; i++) {
            totalAllocation += allocationToPercent(custodians[i].allocation);
        }
        if (uint256(floatPercent) + totalAllocation > 100) revert Vault_AllocationExceeds100();
        custodianId = custodians.length;
        custodians.push(CustodianData({
            wallet: wallet,
            allocation: percentToAllocation(allocationPercent)
        }));
        emit CustodianAdded(custodianId, wallet, allocationPercent);
        return custodianId;
    }

    /**
     * @notice Internal function to update an existing custodian.
     */
    function _updateCustodian(uint256 custodianId, address wallet, uint256 allocationPercent) internal {
        if (custodianId >= custodians.length) revert Vault_InvalidCustodianId();
        if (wallet == address(0)) revert Vault_InvalidWallet();
        if (allocationPercent > 100) revert Vault_InvalidAllocation();

        uint256 totalAllocation = allocationPercent;
        for (uint256 i = 0; i < custodians.length; i++) {
            if (i != custodianId) {
                totalAllocation += allocationToPercent(custodians[i].allocation);
            }
        }
        if (uint256(floatPercent) + totalAllocation > 100) revert Vault_AllocationExceeds100();
        custodians[custodianId] = CustodianData({
            wallet: wallet,
            allocation: percentToAllocation(allocationPercent)
        });
        emit CustodianUpdated(custodianId, wallet, allocationPercent);
    }

    /**
     * @notice Internal function to remove a custodian efficiently.
     * @dev Uses the "swap with last and pop" method to save gas.
     */
    function _removeCustodian(uint256 custodianId) internal {
        if (custodianId >= custodians.length) revert Vault_InvalidCustodianId();
        if (custodians.length <= 1) revert Vault_CannotRemoveLastCustodian();

        address removedWallet = custodians[custodianId].wallet;
        if (custodianId < custodians.length - 1) {
            custodians[custodianId] = custodians[custodians.length - 1];
        }
        custodians.pop();

        emit CustodianRemoved(custodianId, removedWallet);
    }

    /**
     * @notice A view function to get the current number of custodians.
     */
    function getCustodianCount() public view virtual returns (uint256) {
        return custodians.length;
    }

    /**
     * @notice Internal view function to get a single custodian's allocation.
     */
    function _getCustodianAllocation(uint256 custodianId) internal view returns (uint256) {
        if (custodianId >= custodians.length) return 0;
        return allocationToPercent(custodians[custodianId].allocation);
    }

    /**
     * @notice Internal view function to get all custodians and their allocations.
     */
    function _getAllCustodians() internal view returns (
        address[] memory wallets,
        uint256[] memory allocations
    ) {
        uint256 length = custodians.length;
        wallets = new address[](length);
        allocations = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            wallets[i] = custodians[i].wallet;
            allocations[i] = allocationToPercent(custodians[i].allocation);
        }
    }

    /**
     * @notice Internal function to validate transactions against daily rate limits.
     * @dev Resets the daily limit window if 24 hours have passed.
     */
    function _validateRateLimit(uint256 amount, bool isDeposit) internal {
        if (block.timestamp >= limitWindowStart + 1 days) {
            depositLimit.currentAmount = 0;
            withdrawalLimit.currentAmount = 0;
            limitWindowStart = block.timestamp;
        }

        if (isDeposit) {
            if (depositLimit.currentAmount + amount > depositLimit.maxAmount) revert Vault_DailyDepositLimit();
            depositLimit.currentAmount += uint128(amount);
        } else {
            if (withdrawalLimit.currentAmount + amount > withdrawalLimit.maxAmount) revert Vault_DailyWithdrawalLimit();
            withdrawalLimit.currentAmount += uint128(amount);
        }
    }

    // --- Internal Setter Functions ---
    // These functions contain the core logic for changing state variables. They are called by the
    // permissioned external functions in the LSTokenVault contract.

    function _setFeePercent(uint256 _feePercent) internal {
        if (_feePercent > MAX_FEE_PERCENT) revert Vault_FeeTooHigh();
        feePercent = _feePercent;
    }

    function _setYieldVestingDuration(uint256 _duration) internal {
        if (_duration > 7 days) revert Vault_InvalidDuration();
        yieldVestingDuration = _duration;
    }

    function _setFeeReceiver(address _feeReceiver) internal {
        if (_feeReceiver == address(0)) revert Vault_InvalidFeeReceiver();
        feeReceiver = _feeReceiver;
    }

    function _setMaxTotalDeposit(uint256 _maxTotalDeposit) internal {
        if (_maxTotalDeposit < totalDepositedAmount) revert Vault_MaxTotalBelowCurrent();
        maxTotalDeposit = _maxTotalDeposit;
    }

    function _setMaxUserDeposit(uint256 _maxUserDeposit) internal {
        maxUserDeposit = _maxUserDeposit;
    }

    function _setStakeEnabled(bool _enabled) internal {
        stakeEnabled = _enabled;
    }

    function _setUnstakeEnabled(bool _enabled) internal {
        unstakeEnabled = _enabled;
    }

    function _setMinDepositAmount(uint256 _minDeposit) internal {
        minDepositAmount = _minDeposit;
    }

    uint256[35] private __gap;
}