
// ILSToken.sol (already correct)
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

interface ILSToken {
    // Standard ERC20 functions
    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    // Minting/Burning
    function mint(address to, uint256 amount) external;

    function burnFrom(address from, uint256 amount) external;

    // Initialization
    function initialize(string memory name, string memory symbol) external;

    // Role management
    function MINTER_ROLE() external pure returns (bytes32);

    function grantRole(bytes32 role, address account) external;

    function hasRole(bytes32 role, address account) external view returns (bool);
}