// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "./Std.sol";
import {TokenMint} from "../src/TokenMint.sol";

/// Tests for the ETH-paid ecash-token mint rail (the leaner architecture's
/// payment, `docs/ARCHITECTURE.md`). Covers the purchase ledger, the
/// blind-issue/redeem double-issue guard, proceeds accounting + withdrawal, and
/// access control.
contract TokenMintTest is Test {
    TokenMint mint;
    uint256 constant PRICE = 0.01 ether;
    address issuer = address(0x155);
    address buyer = address(0xB0B);

    function setUp() public {
        mint = new TokenMint(issuer, PRICE);
        vm.deal(buyer, 100 ether);
        vm.deal(issuer, 0);
    }

    // ----- construction ---------------------------------------------------

    function test_RevertWhen_ZeroIssuer() public {
        vm.expectRevert(bytes("ZERO_ISSUER"));
        new TokenMint(address(0), PRICE);
    }

    function test_RevertWhen_ZeroPrice() public {
        vm.expectRevert(bytes("ZERO_PRICE"));
        new TokenMint(issuer, 0);
    }

    // ----- purchase -------------------------------------------------------

    function testPurchaseCreditsEntitlementAndProceeds() public {
        vm.prank(buyer);
        mint.purchase{value: 5 * PRICE}();
        assertEq(mint.entitled(buyer), 5, "5 tokens entitled");
        assertEq(mint.proceeds(), 5 * PRICE, "proceeds = 5*price");
        assertEq(address(mint).balance, 5 * PRICE, "contract holds proceeds");
    }

    function testPurchaseRefundsDust() public {
        uint256 before = buyer.balance;
        vm.prank(buyer);
        mint.purchase{value: 3 * PRICE + 0.003 ether}(); // 3 tokens + dust
        assertEq(mint.entitled(buyer), 3, "floor(value/price) tokens");
        assertEq(mint.proceeds(), 3 * PRICE, "only the token cost is kept");
        // The dust (0.003 ether) is refunded → net spend is exactly 3*price.
        assertEq(before - buyer.balance, 3 * PRICE, "dust refunded");
    }

    function test_RevertWhen_PurchaseBelowPrice() public {
        vm.prank(buyer);
        vm.expectRevert(bytes("BELOW_PRICE"));
        mint.purchase{value: PRICE - 1}();
    }

    function testPurchasesAccumulate() public {
        vm.startPrank(buyer);
        mint.purchase{value: 2 * PRICE}();
        mint.purchase{value: 3 * PRICE}();
        vm.stopPrank();
        assertEq(mint.entitled(buyer), 5, "entitlements accumulate");
    }

    // ----- redeem (the double-issue guard) --------------------------------

    function testIssuerRedeemsEntitlement() public {
        vm.prank(buyer);
        mint.purchase{value: 5 * PRICE}();
        vm.prank(issuer);
        mint.redeem(buyer, 3);
        assertEq(mint.entitled(buyer), 2, "redeemed 3, 2 remain");
    }

    function test_RevertWhen_RedeemByNonIssuer() public {
        vm.prank(buyer);
        mint.purchase{value: 5 * PRICE}();
        vm.prank(buyer); // not the issuer
        vm.expectRevert(bytes("NOT_ISSUER"));
        mint.redeem(buyer, 1);
    }

    function test_RevertWhen_RedeemOverEntitlement() public {
        vm.prank(buyer);
        mint.purchase{value: 2 * PRICE}();
        vm.prank(issuer);
        vm.expectRevert(bytes("INSUFFICIENT_ENTITLEMENT"));
        mint.redeem(buyer, 3); // only 2 entitled — can't over-issue
    }

    /// The guard prevents turning one purchase into more tokens than paid for,
    /// even across multiple redeems.
    function testCannotRedeemMoreThanPurchasedAcrossCalls() public {
        vm.prank(buyer);
        mint.purchase{value: 3 * PRICE}();
        vm.startPrank(issuer);
        mint.redeem(buyer, 2);
        mint.redeem(buyer, 1);
        vm.expectRevert(bytes("INSUFFICIENT_ENTITLEMENT"));
        mint.redeem(buyer, 1); // 0 left
        vm.stopPrank();
        assertEq(mint.entitled(buyer), 0, "all entitlements consumed");
    }

    // ----- withdraw -------------------------------------------------------

    function testIssuerWithdrawsProceeds() public {
        vm.prank(buyer);
        mint.purchase{value: 7 * PRICE}();
        address sink = address(0x5151);
        vm.prank(issuer);
        mint.withdraw(sink);
        assertEq(sink.balance, 7 * PRICE, "proceeds paid to sink");
        assertEq(mint.proceeds(), 0, "proceeds zeroed");
        assertEq(address(mint).balance, 0, "contract drained");
    }

    function test_RevertWhen_WithdrawByNonIssuer() public {
        vm.prank(buyer);
        mint.purchase{value: PRICE}();
        vm.prank(buyer);
        vm.expectRevert(bytes("NOT_ISSUER"));
        mint.withdraw(buyer);
    }

    /// Redeeming an entitlement does NOT touch proceeds — the tokens are paid
    /// for; redeem only consumes the right to be issued them.
    function testRedeemDoesNotAffectProceeds() public {
        vm.prank(buyer);
        mint.purchase{value: 4 * PRICE}();
        vm.prank(issuer);
        mint.redeem(buyer, 4);
        assertEq(mint.proceeds(), 4 * PRICE, "proceeds unchanged by redeem");
    }
}
