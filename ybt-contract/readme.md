# Liquid Staking Protocol

## Overview
This is a decentralized liquid staking protocol that allows users to stake an underlying asset (e.g., rETH) in exchange for a yield-bearing Liquid Staking Token (LST). The value of the LST increases over time as staking rewards are added to the system, distributed through a time-vested index mechanism.

The protocol is designed to be modular, secure, and highly configurable through administrative roles with a strong emphasis on segregation of duties.

## Core Contracts
* **LSTokenVault**: The central vault where users deposit underlying assets to mint LSTokens. It manages the core accounting, yield distribution, and custodian fund transfers.
* **LSToken**: The ERC20 liquid staking token that represents a user's share in the vault. Its value appreciates as yield is added to the system.
* **VaultManager**: A stateless administrative control module for a specific `LSTokenVault`. It serves as the single point of entry for admins to configure vault parameters.
* **UnstakeManager**: Manages the entire withdrawal process, which includes a user-initiated request, a cooldown period, and the final claim for both regular and early withdrawals.
* **TokenSilo**: A temporary holding contract where funds are placed during the unstaking cooldown period before they can be claimed by the user.
* **EmergencyController**: A global, system-wide contract that provides powerful tools to pause activity and manage the protocol during emergencies.

## Architecture & Design
The system's modular architecture separates key functionalities into distinct, upgradeable contracts. This enhances security, simplifies maintenance, and allows for granular control over the protocol.

* **Yield Mechanism**: Yield is added to the vault through an `addYield` function. To prevent price manipulation, the resulting increase in the LSToken's value (the "index") is vested linearly over a period of 8 hours. Any yield forfeited by users who unstake early is captured and redistributed to the remaining stakers in the next cycle.
* **Fund Management**: The protocol is designed to work with off-chain custodians. A configurable `floatPercent` determines what portion of new deposits is kept in the vault for liquidity, with the remainder being distributed to custodian wallets based on their individual allocation percentages.
* **Asynchronous Unstaking**: The unstaking process is asynchronous. An administrator processes requests, which moves the funds from the vault to the silo.
* **Emergency Safeguards**: The system includes a multi-tiered emergency response system, from operational toggles and vault-specific pauses to a global, time-locked Recovery Mode for severe incidents. The roles are segregated to ensure no single entity has unilateral control.

## Complete User Flows

### Staking Flow
1.  A user calls `deposit()` on the `LSTokenVault`, sending their underlying tokens.
2.  The vault calculates and mints LSTokens based on the post-yield `targetIndex` to ensure fair pricing for all stakers.
3.  A **withdrawal lock** equal to the yield vesting period (8 hours) is activated for the user.
4.  The underlying tokens are then distributed between the vault's float and the designated custodians.

### Unstaking Flow
1.  After their withdrawal lock has expired, a user calls `requestUnstake()` on the `LSTokenVault`, which burns their LSTokens.
2.  The request is sent to the `UnstakeManager`, which adds it to a queue and calculates the amount of underlying tokens owed based on the index at that moment.
3.  An administrator calls `processUnstakeQueue()`, which moves the owed funds from the vault to the `TokenSilo`.
4.  After a mandatory cooldown period ends, the user calls `claim()` on the `UnstakeManager` to receive their underlying tokens from the `TokenSilo`.

### Early Withdrawal Flow
1.  A user whose request has been processed and has funds in the `TokenSilo` can choose to bypass the remaining cooldown.
2.  They call `earlyWithdraw()` on the **`UnstakeManager`**, which is the central point for all withdrawals.
3.  The `UnstakeManager` commands the `TokenSilo` to release the funds. A percentage-based fee is deducted, and the user immediately receives the remaining amount of their underlying tokens.

## Manager & Admin Flows

### Operational Management (`MANAGER_ROLE`)
* **Process Unstake Queue**: A manager calls `markRequestsForProcessing` and `processUnstakeQueue` on the `UnstakeManager` to move funds from the vault to the silo for users waiting to claim.
* **Add Yield**: A manager (or designated `REWARDER_ROLE`) calls `addYield` on the `LSTokenVault` to distribute staking rewards to all LSToken holders. A protocol fee is taken from the yield.
* **Withdraw Protocol Fees**: A manager calls `withdrawFees` on the `VaultManager` to transfer all accrued fees to the designated `feeReceiver` wallet.

### Parameter Configuration (`ADMIN_ROLE` via `VaultManager`)
* **Vault Parameters**: Admins use the `VaultManager` to set all core financial parameters on the `LSTokenVault`, including `setMaxTotalDeposit`, `setMaxUserDeposit`, `setFeePercent`, and `setFloatPercent`.
* **Unstake/Silo Parameters**: Admins use the `VaultManager` to control the `cooldownPeriod` on the `UnstakeManager` and all `TokenSilo` settings, such as the `unlockFee` for early withdrawals and the address of the `feeCollector`.

### Security & Risk Management (`ADMIN_ROLE` / `EMERGENCY_ROLE`)
* **Vault-Specific Pause**: An `EMERGENCY_ROLE` can call `pause()` and `unpause()` on a specific `LSTokenVault` to handle isolated incidents without affecting the whole protocol.
* **Flash Loan Protection**: Admins can configure the `maxPriceImpactPercentage` on the `LSTokenVault` to protect against manipulation.
* **Silo Security**: Admins can set the `LiquidityThreshold` on the `TokenSilo`, which automatically pauses withdrawals if liquidity is low.

### Emergency Management (`ADMIN_ROLE` / `EMERGENCY_ROLE`)
* **Operational Toggles**: For routine maintenance, an admin can use `setStakeEnabled` and `setUnstakeEnabled` on the `LSTokenVault` to gracefully pause specific functions.
* **Emergency Pause**: For a potential threat, the `EMERGENCY_ROLE` can use the `EmergencyController` to instantly call `pauseDeposits`, `pauseWithdrawals`, or `pauseAll`.
* **Circuit Breaker**: For a severe exploit, the `EMERGENCY_ROLE` can `triggerCircuitBreaker`, which instantly puts the system in `FULL_PAUSE` and simultaneously starts the 24-hour timelock for the more restrictive Recovery Mode.
* **Recovery Mode**: After the 24-hour timelock, `activateRecoveryMode` can be called. This mode freezes almost all functions. To exit this state, the `ADMIN_ROLE` must follow a deliberate two-step process: first calling `deactivateRecoveryMode` to cancel the timer, and only then `resumeOperations`.

### Manual Overrides (`ADMIN_ROLE`)
* **Rescue Tokens**: An admin can call `rescueTokens` on the `TokenSilo` to withdraw any accidentally sent tokens to a safe address.
* **Adjust Claims**: If the silo's internal accounting ever becomes inaccurate, an admin can use `adjustPendingClaims` to manually correct the value of total pending withdrawals.
* **Transfer Collateral**: Admins can use the `VaultManager` to call `transferCollateral`, allowing for the direct movement of underlying assets from the `LSTokenVault` for emergencies or operational needs.