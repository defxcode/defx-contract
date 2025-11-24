// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

// ===== IUnderlyingToken.sol =====
/**
 * @title IUnderlyingToken
 * @notice Interface for underlying tokens that may support shares (like stETH)
 */
interface IUnderlyingToken {
    // Standard ERC20
    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    // Optional rebasing token functions (like stETH)
    function getTotalShares() external view returns (uint256);

    function getTotalPooledEther() external view returns (uint256);

    function getSharesByPooledEth(uint256 _ethAmount) external view returns (uint256);

    function getPooledEthByShares(uint256 _sharesAmount) external view returns (uint256);

    function sharesOf(address _account) external view returns (uint256);
}