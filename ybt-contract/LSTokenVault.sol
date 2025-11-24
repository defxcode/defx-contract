// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// External libraries and contracts
import {UD60x18, wrap, unwrap} from "@prb/math/src/UD60x18.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/IERC20MetadataUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/ILSToken.sol";
import "./interfaces/IUnderlyingToken.sol";
import "./interfaces/ITokenSilo.sol";
import "./interfaces/IUnstakeManager.sol";
import "./interfaces/IEmergencyController.sol";
import "./LSTokenVaultStorage.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/**
* @title LSTokenVault
* @notice The core contract of the protocol, managing user deposits, yield distribution, and custodian fund transfers.
* @dev Inherits its state from LSTokenVaultStorage to separate logic and storage for upgradeability.
*/
contract LSTokenVault is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    LSTokenVaultStorage
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the LSTokenVault with its core parameters and roles.
     * @dev Called only once by the VaultFactory upon deployment.
     */
    function initialize(
        address _underlyingToken,
        address _lsToken,
        string memory _underlyingSymbol,
        string memory _lsTokenSymbol,
        address _admin
    ) external initializer {
        if (_underlyingToken == address(0)) revert Vault_InvalidUnderlyingToken();
        if (_lsToken == address(0)) revert Vault_InvalidLSToken();
        if (_admin == address(0)) revert Vault_InvalidAdmin();

        __Pausable_init();
        __ReentrancyGuard_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();

        underlyingToken = IERC20Upgradeable(_underlyingToken);
        lsToken = ILSToken(_lsToken);
        underlyingSymbol = _underlyingSymbol;
        lsTokenSymbol = _lsTokenSymbol;

        // The index represents the exchange rate, starting at 1:1.
        lastIndex = INITIAL_INDEX;
        targetIndex = INITIAL_INDEX;
        lastUpdateTime = block.timestamp;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(REWARDER_ROLE, _admin);
        _grantRole(MANAGER_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
        uint8 _underlyingDecimals = IERC20MetadataUpgradeable(_underlyingToken).decimals();
        if (_underlyingDecimals > 18) revert Vault_UnsupportedDecimals();
        underlyingDecimals = _underlyingDecimals;
        decimalScaleFactor = 10**(18 - _underlyingDecimals);
        _setupDefaults(_admin, _underlyingDecimals);
        version = 1;
    }

    // --- Contract Links Setup ---

    /**
     * @notice Sets the address of the UnstakeManager contract.
     * @dev A critical setup function to enable the unstaking process. Can only be called by an admin.
     * @param _unstakeManager The address of the deployed UnstakeManager.
    */
    function setUnstakeManager(address _unstakeManager) external onlyRole(ADMIN_ROLE) {
        if (_unstakeManager == address(0)) revert Vault_InvalidUnstakeManager();
        unstakeManager = IUnstakeManager(_unstakeManager);
        emit UnstakeManagerSet(_unstakeManager);
    }

    /**
     * @notice Sets the address of the global EmergencyController contract.
     * @dev Links the vault to the system's central kill switch. Can only be called by an admin.
     * @param _emergencyController The address of the deployed EmergencyController.
    */
    function setEmergencyController(address _emergencyController) external onlyRole(ADMIN_ROLE) {
        if (_emergencyController == address(0)) revert Vault_InvalidEmergencyController();
        emergencyController = IEmergencyController(_emergencyController);
        emit EmergencyControllerSet(_emergencyController);
    }

    // --- Core Logic ---

    /**
     * @notice Calculates the current value of the LSToken index, accounting for linear vesting of yield.
     * @dev To prevent flash loan manipulation, yield is vested over `yieldVestingDuration`.
     * This function smoothly interpolates the index value between `lastIndex` and `targetIndex`.
     * @return The current, time-vested index representing the LSToken's value.
     */
    function getCurrentIndex() public view returns (uint256) {
        if (!isVestingActive()) return targetIndex;
        if (vestingEndTime <= lastUpdateTime) return targetIndex;

        uint256 elapsed = block.timestamp - lastUpdateTime;
        uint256 duration = vestingEndTime - lastUpdateTime;
        uint256 delta = targetIndex - lastIndex;

        uint256 indexIncrease = calculatePercentage(delta, elapsed, duration);
        if (indexIncrease > delta) {
            indexIncrease = delta;
        }
        return lastIndex + indexIncrease;
    }

    /**
     * @notice Adds staking rewards (yield) to the vault, increasing the value of the LSToken for all holders.
     * @dev Can only be called by a `REWARDER_ROLE`. Takes a protocol fee and sets a new `targetIndex`.
     * This increase in value is then vested over 8 hours via the `getCurrentIndex` logic.
     * @param yieldAmount The amount of underlying tokens being added as rewards.
     */
    function addYield(uint256 yieldAmount) external onlyRole(REWARDER_ROLE) {
        if (yieldAmount == 0) revert Vault_YieldMustBePositive();
        if (address(emergencyController) == address(0)) revert Vault_EmergencyControllerNotSet();
        if (emergencyController.getEmergencyState() != IEmergencyController.EmergencyState.NORMAL) revert Vault_EmergencyModeActive();
        if (emergencyController.isRecoveryModeActive()) revert Vault_RecoveryModeActive();
        if (isVestingActive()) revert Vault_PreviousYieldVesting();

        uint256 supply = lsToken.totalSupply();
        if (supply == 0) revert Vault_NoLSTokenSupply();

        uint256 yieldIn18Decimal = yieldAmount * decimalScaleFactor;
        uint256 feeAmount = calculatePercentage(yieldIn18Decimal, feePercent, PERCENT_PRECISION);
        uint256 distributableYield = yieldIn18Decimal;
        if (feeAmount > 0 && feeReceiver != address(0)) {
            totalFeeCollected += feeAmount;
            distributableYield -= feeAmount;
            emit FeesCollected(feeAmount);
        }

        totalCustodianFunds += yieldAmount;

        uint256 current = getCurrentIndex();
        uint256 deltaIndex = calculatePercentage(distributableYield, INDEX_PRECISION, supply);

        if (deltaIndex == 0) revert Vault_YieldTooLow();

        uint256 maxIndexIncrease = calculatePercentage(current, MAX_INDEX_INCREASE_PERCENT, PERCENT_PRECISION);
        if (deltaIndex > maxIndexIncrease) revert Vault_YieldTooHigh();

        uint256 newTarget = current + deltaIndex;

        uint256 indexChangePercent = calculatePercentage(deltaIndex, 100, current);
        if (indexChangePercent > maxPriceImpactPercentage) revert Vault_IndexChangeTooHigh();
        uint256 oldIndex = lastIndex;
        lastIndex = current;
        targetIndex = newTarget;
        lastUpdateTime = block.timestamp;
        vestingEndTime = block.timestamp + yieldVestingDuration;
        lastStateUpdate = block.timestamp;

        emit IndexUpdated(oldIndex, newTarget);
    }

    /**
     * @notice The main function for users to deposit underlying assets and mint LSTokens.
     * @param underlyingAmount The amount of the underlying token the user wants to stake.
     */
    function deposit(uint256 underlyingAmount) external whenNotPaused nonReentrant {
        _deposit(msg.sender, underlyingAmount, 0);
    }

    /**
     * @notice Overloaded deposit function with slippage protection.
     * @param underlyingAmount The amount of the underlying token to stake.
     * @param minLSTokenAmount The minimum amount of LSTokens the user will accept.
     */
    function deposit(uint256 underlyingAmount, uint256 minLSTokenAmount) external whenNotPaused nonReentrant {
        _deposit(msg.sender, underlyingAmount, minLSTokenAmount);
    }

    /**
     * @notice Internal logic for handling all deposits.
     * @dev Performs all security checks, calculates the LSToken amount, mints tokens, and triggers custodian transfers.
     */
    function _deposit(address user, uint256 underlyingAmount, uint256 minLSTokenAmount) internal {
        if (address(emergencyController) == address(0)) revert Vault_EmergencyControllerNotSet();
        IEmergencyController.EmergencyState state = emergencyController.getEmergencyState();
        if (state == IEmergencyController.EmergencyState.DEPOSITS_PAUSED || state == IEmergencyController.EmergencyState.FULL_PAUSE) revert Vault_DepositsPaused();
        if (emergencyController.isRecoveryModeActive()) revert Vault_RecoveryModeActive();
        if (!stakeEnabled) revert Vault_StakingDisabled();
        if (underlyingAmount < minDepositAmount) revert Vault_AmountBelowMinimum();
        if (user == address(0)) revert Vault_InvalidUser();
        if (totalDepositedAmount + underlyingAmount > maxTotalDeposit) revert Vault_GlobalDepositLimitReached();

        uint256 userBalance = lsToken.balanceOf(user);
        uint256 currentIndex = getCurrentIndex();
        uint256 existingValueIn18Decimal = convertTokens(userBalance, currentIndex, INDEX_PRECISION, false);
        uint256 existingValueInUnderlyingUnit = existingValueIn18Decimal / decimalScaleFactor;

        if (existingValueInUnderlyingUnit + underlyingAmount > maxUserDeposit) revert Vault_UserDepositLimitReached();

        _validateRateLimit(underlyingAmount, true);

        // using targetIndex for deposits to prevent new depositors from
        // unfairly benefiting from yield generated by previous stakers.
        uint256 depositIndex = targetIndex;
        uint256 amountIn18Decimal = underlyingAmount * decimalScaleFactor;
        uint256 lsTokenAmount = convertTokens(amountIn18Decimal, depositIndex, INDEX_PRECISION, true);
        if (minLSTokenAmount > 0) {
            if (lsTokenAmount < minLSTokenAmount) revert Vault_SlippageTooHigh();
        }
        if (lsTokenAmount == 0) revert Vault_LSTokenAmountIsZero();

        totalDepositedAmount += underlyingAmount;
        lastStateUpdate = block.timestamp;

        // Recording the user's deposit time to enforce the withdrawal lock.
        lastDepositTime[user] = block.timestamp;

        underlyingToken.safeTransferFrom(msg.sender, address(this), underlyingAmount);
        lsToken.mint(user, lsTokenAmount);

        _handleCustodianTransfer(underlyingAmount);

        emit Deposited(user, underlyingAmount, lsTokenAmount);
    }

    /**
     * @notice Internal function to distribute a portion of new deposits to the custodian wallets.
     * @dev Iterates through custodians and transfers funds based on their configured allocation percentage.
     * The remainder is kept in the vault as a "float" for liquidity.
     * @param underlyingAmount The amount to be distributed.
    */
    function _handleCustodianTransfer(uint256 underlyingAmount) internal {
        if (custodians.length == 0 || (address(emergencyController) != address(0) && emergencyController.isRecoveryModeActive())) return;
        for (uint256 i = 0; i < custodians.length; i++) {
            if (custodians[i].wallet == address(0)) continue;
            uint256 allocation = allocationToPercent(custodians[i].allocation);

            uint256 custodianAmount = calculatePercentage(underlyingAmount, allocation, 100);
            if (custodianAmount > 0) {
                totalCustodianFunds += custodianAmount;
                underlyingToken.safeTransfer(custodians[i].wallet, custodianAmount);
                emit CustodianTransfer(i, custodians[i].wallet, custodianAmount);
            }
        }
    }

    /**
     * @notice Initiates the unstaking process for the user.
     * @dev Delegates the request to the `UnstakeManager`.
    * @param lsTokenAmount The amount of LSTokens the user wishes to redeem.
     */
    function requestUnstake(uint256 lsTokenAmount) external nonReentrant {
        _requestUnstake(lsTokenAmount, 0);
    }

    /**
     * @notice Overloaded `requestUnstake` with slippage protection.
     * @param lsTokenAmount The amount of LSTokens to redeem.
    * @param minUnderlyingAmount The minimum amount of underlying tokens the user will accept.
     */
    function requestUnstake(uint256 lsTokenAmount, uint256 minUnderlyingAmount) external nonReentrant {
        _requestUnstake(lsTokenAmount, minUnderlyingAmount);
    }

    /**
     * @notice Internal logic for handling all unstake requests.
     */
    function _requestUnstake(uint256 lsTokenAmount, uint256 minUnderlyingAmount) internal {
        if (address(unstakeManager) == address(0)) revert Vault_UnstakeManagerNotSet();
        if (address(emergencyController) == address(0)) revert Vault_EmergencyControllerNotSet();

        IEmergencyController.EmergencyState state = emergencyController.getEmergencyState();
        if (state == IEmergencyController.EmergencyState.WITHDRAWALS_PAUSED || state == IEmergencyController.EmergencyState.FULL_PAUSE) revert Vault_WithdrawalsPaused();
        if (emergencyController.isRecoveryModeActive()) revert Vault_RecoveryModeActive();
        if (!unstakeEnabled) revert Vault_UnstakingDisabled();

        uint256 currentIndex = getCurrentIndex();
        uint256 amountIn18Decimal = convertTokens(lsTokenAmount, currentIndex, INDEX_PRECISION, false);
        uint256 rawUnderlyingAmount = amountIn18Decimal / decimalScaleFactor;
        _validateRateLimit(rawUnderlyingAmount, false);
        if (block.timestamp < lastDepositTime[msg.sender] + yieldVestingDuration) revert Vault_WithdrawalLockActive();
        if (currentIndex < targetIndex) {
            uint256 targetValue = convertTokens(lsTokenAmount, targetIndex, INDEX_PRECISION, false);

            if (targetValue > amountIn18Decimal) {
                uint256 forfeitedAmount = targetValue - amountIn18Decimal;
                totalFeeCollected += forfeitedAmount;
                emit FeesCollected(forfeitedAmount);
            }
        }
        uint256 minAmountIn18Decimal = minUnderlyingAmount * decimalScaleFactor;
        unstakeManager.requestUnstake(msg.sender, lsTokenAmount, minAmountIn18Decimal, currentIndex);
    }

    // --- Custodian Management (ADMIN_ROLE) ---
    function addCustodian(address wallet, uint256 allocationPercent) external onlyRole(ADMIN_ROLE) returns (uint256 custodianId) {
        if (address(emergencyController) != address(0) && emergencyController.isRecoveryModeActive()) revert Vault_RecoveryModeActive();
        return _addCustodian(wallet, allocationPercent);
    }

    function updateCustodian(uint256 custodianId, address wallet, uint256 allocationPercent) external onlyRole(ADMIN_ROLE) {
        if (address(emergencyController) != address(0) && emergencyController.isRecoveryModeActive()) revert Vault_RecoveryModeActive();
        _updateCustodian(custodianId, wallet, allocationPercent);
    }

    function removeCustodian(uint256 custodianId) external onlyRole(ADMIN_ROLE) {
        if (address(emergencyController) != address(0) && emergencyController.isRecoveryModeActive()) revert Vault_RecoveryModeActive();
        _removeCustodian(custodianId);
    }

    function getCustodian(uint256 custodianId) external view returns (address wallet, uint256 allocationPercent) {
        if (custodianId >= custodians.length) return (address(0), 0);
        return (custodians[custodianId].wallet, _getCustodianAllocation(custodianId));
    }

    function getAllCustodians() external view returns (address[] memory wallets, uint256[] memory allocations) {
        return _getAllCustodians();
    }

    // --- Admin & Manager Functions ---

    /**
     * @notice Sets the percentage of new deposits to be kept in the vault for liquidity.
     */
    function setYieldVestingDuration(uint256 _duration) external onlyRole(MANAGER_ROLE) {
        // This check prevents changing the duration while one is already active
        if (isVestingActive()) revert Vault_PreviousYieldVesting();
        _setYieldVestingDuration(_duration);
    }

    function setFloatPercent(uint256 _floatPercent) external onlyRole(MANAGER_ROLE) {
        if (_floatPercent > 100) revert Vault_InvalidFloatPercentage();
        uint256 totalCustodianAllocation = 0;
        for (uint256 i = 0; i < custodians.length; i++) {
            totalCustodianAllocation += allocationToPercent(custodians[i].allocation);
        }
        if (_floatPercent + totalCustodianAllocation > 100) revert Vault_AllocationExceeds100();
        floatPercent = uint8(_floatPercent);
    }

    /**
     * @notice Allows an admin to correct the on-chain accounting when custodians return funds to the vault.
     */
    function recordCustodianFundsReturn(uint256 amount) external onlyRole(MANAGER_ROLE) {
        if (amount > totalCustodianFunds) revert Vault_ReturnAmountExceedsCustodianFunds();
        totalCustodianFunds -= amount;
    }

    /**
     * @notice Sets the daily deposit and withdrawal rate limits.
     */
    function setRateLimits(uint256 _maxDailyDeposit, uint256 _maxDailyWithdrawal) external onlyRole(MANAGER_ROLE) {
        depositLimit.maxAmount = uint128(_maxDailyDeposit);
        withdrawalLimit.maxAmount = uint128(_maxDailyWithdrawal);
    }

    /**
     * @notice Configures the parameters for flash loan protection.
     */
    function setFlashLoanProtection(uint256 _maxPriceImpactPercentage) external onlyRole(MANAGER_ROLE) {
        if (_maxPriceImpactPercentage > 2000) revert Vault_FlashLoanImpactTooHigh();
        maxPriceImpactPercentage = uint16(_maxPriceImpactPercentage);
    }

    /**
     * @notice Allows an admin to approve the UnstakeManager to spend the vault's underlying tokens.
     */
    function approveUnstakeManager(uint256 amount) external onlyRole(ADMIN_ROLE) {
        if (address(unstakeManager) == address(0)) revert Vault_UnstakeManagerNotSet();
        underlyingToken.safeApprove(address(unstakeManager), 0);
        underlyingToken.safeApprove(address(unstakeManager), amount);
    }

    /**
     * @notice Allows a `MANAGER_ROLE` to withdraw all accrued protocol fees.
     */
    function withdrawFees() external nonReentrant onlyRole(MANAGER_ROLE) {
        if (feeReceiver == address(0)) revert Vault_FeeReceiverNotSet();
        uint256 amountToWithdraw = totalFeeCollected;
        if (amountToWithdraw == 0) revert Vault_NoFeesToWithdraw();

        uint256 amountInUnderlyingUnit = amountToWithdraw / decimalScaleFactor;
        if (underlyingToken.balanceOf(address(this)) < amountInUnderlyingUnit) revert Vault_InsufficientBalanceForFees();

        totalFeeCollected = 0;

        underlyingToken.safeTransfer(feeReceiver, amountInUnderlyingUnit);
        emit FeesWithdrawn(feeReceiver, amountInUnderlyingUnit);
    }

    /**
    * @notice Allows an admin/manager to transfer underlying collateral out of the vault.
     * @dev This is a privileged function for emergency or operational fund movements.
     */
    function transferUnderlying(address to, uint256 amount) external nonReentrant onlyRole(MANAGER_ROLE) {
        if (to == address(0)) revert Vault_InvalidRecipient();
        if (amount == 0) revert Vault_AmountMustBePositive();
        if (underlyingToken.balanceOf(address(this)) < amount) revert Vault_InsufficientVaultBalance();

        underlyingToken.safeTransfer(to, amount);
    }

    // --- View Functions ---

    function isVestingActive() public view returns (bool) {
        return block.timestamp < vestingEndTime && vestingEndTime != 0;
    }

    function getMinDepositAmount() external view returns (uint256) {
        return minDepositAmount;
    }

    function previewDeposit(uint256 underlyingAmount) external view returns (uint256 lsTokenAmount) {
        uint256 currentIndex = getCurrentIndex();
        uint256 scaledAmount = underlyingAmount * decimalScaleFactor;
        return convertTokens(scaledAmount, currentIndex, INDEX_PRECISION, true);
    }

    function previewRedeem(uint256 lsTokenAmount) external view returns (uint256 underlyingAmount) {
        uint256 currentIndex = getCurrentIndex();
        uint256 amountIn18Decimal = convertTokens(lsTokenAmount, currentIndex, INDEX_PRECISION, false);
        uint256 amountInUnderlyingUnit = amountIn18Decimal / decimalScaleFactor;
        return amountInUnderlyingUnit;
    }

    function getStats() external view returns (uint256 currentIndex, uint256 totalDeposited, uint256 totalSupply) {
        return (getCurrentIndex(), totalDepositedAmount, lsToken.totalSupply());
    }

    function getLiquidityStatus() external view returns (uint256, uint256, uint256, uint256) {
        uint256 vaultBalance = underlyingToken.balanceOf(address(this));
        uint256 custodianBalance = totalCustodianFunds;
        uint256 totalAvailableAssets = vaultBalance + custodianBalance;
        uint256 lsTokenSupply = lsToken.totalSupply();
        uint256 currentIndex = getCurrentIndex();
        uint256 indexedLiabilitiesIn18Dec = convertTokens(lsTokenSupply, currentIndex, INDEX_PRECISION, false);
        uint256 indexedLiabilitiesInNative = indexedLiabilitiesIn18Dec / decimalScaleFactor;
        return (vaultBalance, custodianBalance, totalAvailableAssets, indexedLiabilitiesInNative);
    }

    function getTokenInfo() external view returns (address, address, string memory, string memory) {
        return (address(underlyingToken), address(lsToken), underlyingSymbol, lsTokenSymbol);
    }

    // --- Admin Functions (Controlled by VaultManager) ---

    /**
     * @notice Sets the maximum total deposit amount for the vault.
     * @dev Can only be called by the VaultManager contract, which has the MANAGER_ROLE.
     */
    function setMaxTotalDeposit(uint256 _maxTotal) external onlyRole(MANAGER_ROLE) {
        _setMaxTotalDeposit(_maxTotal);
    }

    /**
     * @notice Sets the minimum deposit amount for the vault.
     * @dev Can only be called by the VaultManager.
    */
    function setMinDepositAmount(uint256 _minDeposit) external onlyRole(MANAGER_ROLE) {
        _setMinDepositAmount(_minDeposit);
    }

    /**
     * @notice Sets the maximum deposit amount for a single user.
     * @dev Can only be called by the VaultManager.
    */
    function setMaxUserDeposit(uint256 _maxUser) external onlyRole(MANAGER_ROLE) {
        _setMaxUserDeposit(_maxUser);
    }

    /**
     * @notice Sets the protocol fee percentage taken from yield.
     * @dev Can only be called by the VaultManager.
    */
    function setFeePercent(uint256 _feePercent) external onlyRole(MANAGER_ROLE) {
        _setFeePercent(_feePercent);
    }

    /**
     * @notice Sets the address that receives protocol fees.
     * @dev Can only be called by the VaultManager.
    */
    function setFeeReceiver(address _feeReceiver) external onlyRole(MANAGER_ROLE) {
        _setFeeReceiver(_feeReceiver);
    }

    /**
     * @notice Enables or disables depositing.
     * @dev Can only be called by the VaultManager.
    */
    function setStakeEnabled(bool _enabled) external onlyRole(MANAGER_ROLE) {
        _setStakeEnabled(_enabled);
    }

    /**
     * @notice Enables or disables unstaking.
     * @dev Can only be called by the VaultManager.
    */
    function setUnstakeEnabled(bool _enabled) external onlyRole(MANAGER_ROLE) {
        _setUnstakeEnabled(_enabled);
    }

    // --- Upgrade Functions ---
    function requestUpgrade() external onlyRole(ADMIN_ROLE) {
        if (upgradeRequested) {
            if (block.timestamp < upgradeRequestTime + UPGRADE_TIMELOCK) revert Vault_PreviousUpgradePending();
        }
        upgradeRequestTime = block.timestamp;
        upgradeRequested = true;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
        if (newImplementation == address(0)) revert Vault_InvalidImplementation();
        if (!upgradeRequested) revert Vault_UpgradeNotRequested();
        if (block.timestamp < upgradeRequestTime + UPGRADE_TIMELOCK) revert Vault_TimelockNotExpired();
        upgradeRequested = false;
        version++;
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(EMERGENCY_ROLE) {
        if (address(emergencyController) != address(0)) {
            if (emergencyController.isRecoveryModeActive()) revert Vault_RecoveryModeActive();
        }
        _unpause();
    }

    uint256[31] private __gap;
}