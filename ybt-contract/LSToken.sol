// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/draft-ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

// --- Custom Errors ---
error LSToken_CannotMintToZeroAddress();
error LSToken_CannotBurnFromZeroAddress();
error LSToken_TimelockPending();
error LSToken_NoUpgradeToCancel();
error LSToken_InvalidImplementation();
error LSToken_UpgradeNotRequested();
error LSToken_TimelockNotExpired();

/**
 * @title LSToken - Liquid Staking Token
 * @notice This is the yield-bearing token that represents a user's share of the staked assets in the
 * LSTokenVault. It is a standard ERC20 token with additional features like EIP-2612 permits,
 * role-based minting/burning, and upgradeability.
 * @dev Inherits from OpenZeppelin's upgradeable contracts for ERC20, Permit, AccessControl, and UUPS.
 */
contract LSToken is
    Initializable,
    ERC20PermitUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    // --- Roles ---
    /// @notice The MINTER_ROLE is the only role that can create (mint) or destroy (burn) tokens.
    /// @dev This role is granted to the LSTokenVault and UnstakeManager contracts.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    /// @notice The ADMIN_ROLE has administrative control over this contract, such as granting roles and managing upgrades.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // --- State Variables ---

    /// @notice The current version of this contract, used for off-chain tracking of upgrades.
    uint256 public version;

    /// @notice A struct to manage the state of the upgrade timelock mechanism.
    struct UpgradeControl {
        uint256 requestTime; // Timestamp of the upgrade request.
        bool requested;      // Flag indicating if an upgrade is pending.
    }

    /// @notice The state variable for the upgrade control struct.
    UpgradeControl public upgradeControl;
    /// @notice The mandatory 2-day waiting period for a contract upgrade to be authorized.
    uint256 public constant UPGRADE_TIMELOCK = 2 days;

    // --- Events ---
    event VersionUpdated(string newVersion);
    event UpgradeRequested(uint256 requestTime);
    event UpgradeAuthorized(address indexed implementation, string currentVersion);
    event UpgradeCancelled(uint256 requestTime);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the LSToken contract, setting its name, symbol, and initial admin.
     * @dev This function is called only once by the VaultFactory when the token proxy is deployed.
     * It also initializes all the inherited OpenZeppelin contracts.
     * @param name The full name of the token (e.g., "Liquid Staked XYZ").
     * @param symbol The symbol of the token (e.g., "lsXYZ").
     */
    function initialize(string memory name, string memory symbol) external initializer {
        __ERC20_init(name, symbol);
        __ERC20Permit_init(name); // Enables gasless approvals via signatures.
        __AccessControl_init();
        __UUPSUpgradeable_init();

        // The deployer (VaultFactory) initially gets admin rights to set up roles.
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        version = 1;
    }

    /**
     * @notice Returns the number of decimals used to display token amounts.
     * @dev Overrides the standard ERC20 decimals function to hardcode it to 18, which is the
     * standard for most tokens in the Ethereum ecosystem.
     * @return A fixed value of 18.
     */
    function decimals() public pure override returns (uint8) {
        return 18;
    }

    /**
     * @notice Creates a specified `amount` of new tokens and assigns them to the `to` address.
     * @dev This function is protected and can only be called by an address with the `MINTER_ROLE`.
     * This is typically the LSTokenVault, which mints tokens upon user deposits.
     * @param to The address that will receive the newly minted tokens.
     * @param amount The quantity of tokens to mint.
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (to == address(0)) revert LSToken_CannotMintToZeroAddress();
        _mint(to, amount);
    }

    /**
     * @notice Destroys a specified `amount` of tokens from the `from` address.
     * @dev This function is protected and can only be called by an address with the `MINTER_ROLE`.
     * This is typically the UnstakeManager, which burns tokens when a user requests to unstake.
     * It requires the `from` address to have approved the caller to spend its tokens.
     * @param from The address whose tokens will be burned.
     * @param amount The quantity of tokens to burn.
     */
    function burnFrom(address from, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (from == address(0)) revert LSToken_CannotBurnFromZeroAddress();
        _spendAllowance(from, _msgSender(), amount); // Handles allowance check internally
        _burn(from, amount);
    }

    /**
     * @notice Begins the 2-day timelock for a contract logic upgrade.
     * @dev This function prevents immediate, potentially malicious upgrades by enforcing a waiting period.
     */
    function requestUpgrade() external onlyRole(ADMIN_ROLE) {
        if (upgradeControl.requested) {
            if (block.timestamp < upgradeControl.requestTime + UPGRADE_TIMELOCK) revert LSToken_TimelockPending();
        }
        upgradeControl.requestTime = block.timestamp;
        upgradeControl.requested = true;
        emit UpgradeRequested(upgradeControl.requestTime);
    }

    /**
     * @notice Cancels a pending upgrade request.
     * @dev Allows an admin to abort an upgrade if an issue is discovered before it's authorized.
     */
    function cancelUpgrade() external onlyRole(ADMIN_ROLE) {
        if (!upgradeControl.requested) revert LSToken_NoUpgradeToCancel();
        upgradeControl.requested = false;
        emit UpgradeCancelled(upgradeControl.requestTime);
        upgradeControl.requestTime = 0;
    }

    /**
     * @notice A view function to check the status of a pending upgrade.
     * @dev Useful for off-chain clients and monitoring tools to see if an upgrade is coming.
     * @return requested True if an upgrade is pending, false otherwise.
     * @return requestTime The timestamp when the current upgrade was requested.
     */
    function upgradeRequested() external view returns (bool requested, uint256 requestTime) {
        return (upgradeControl.requested, upgradeControl.requestTime);
    }

    /**
     * @notice Authorizes the upgrade to a new implementation contract.
     * @dev This is an internal function required by OpenZeppelin's UUPS pattern. It is called by the
     * proxy contract during the `upgradeTo` call. It enforces the upgrade request and timelock.
     * @param newImplementation The address of the new logic contract.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
        if (newImplementation == address(0)) revert LSToken_InvalidImplementation();
        if (!upgradeControl.requested) revert LSToken_UpgradeNotRequested();
        if (block.timestamp < upgradeControl.requestTime + UPGRADE_TIMELOCK) revert LSToken_TimelockNotExpired();
        upgradeControl.requested = false;
        version++;
        emit UpgradeAuthorized(newImplementation, Strings.toString(version - 1));
    }

    /**
     * @notice Overrides the default EIP-712 version to use the contract's own stateful version.
     * @dev This ensures that permit signatures remain valid after contract upgrades.
     */
    function _EIP712Version() internal view override returns (string memory) {
        return Strings.toString(version);
    }

    uint256[40] private __gap;
}