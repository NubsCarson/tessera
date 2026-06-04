// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "./Std.sol";
import {ChannelRegistry, IRDecVerifier} from "../src/ChannelRegistry.sol";

/// A malicious "user" contract that, on receiving its refund, tries to reenter
/// the registry to drain it a second time. The registry's `nonReentrant` guard
/// must make the reentrant call revert, which (because `_pay` bubbles the
/// failure) makes the whole outer call revert — funds stay put.
contract ReentrantUser {
    ChannelRegistry public reg;
    bytes32 public chan;
    bool public reentered;

    function setTarget(ChannelRegistry _reg, bytes32 _chan) external {
        reg = _reg;
        chan = _chan;
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            // Attempt to reenter the same terminal path. The guard should revert.
            reg.refundOnTimeout(chan);
        }
    }
}

contract ReentrancyTest is Test {
    ChannelRegistry reg;
    ReentrantUser attacker;

    uint256 constant RELAYER_PK = 0xB0B;
    address relayer;

    bytes32 constant CHAN = bytes32(uint256(0xBEEF));
    uint256 constant B0 = 5 ether;

    function setUp() public {
        reg = new ChannelRegistry(IRDecVerifier(address(0)));
        relayer = vm.addr(RELAYER_PK);
        attacker = new ReentrantUser();
        vm.deal(address(this), 100 ether);
    }

    /// The attacker contract is the channel user. On its timeout refund it
    /// reenters `refundOnTimeout`; the guard makes the reentrant call revert,
    /// which bubbles up and reverts the whole refund. (We assert the attack does
    /// not succeed in draining more than B0 — the registry never pays twice.)
    function test_RevertWhen_ReentrantRefundIsBlocked() public {
        attacker.setTarget(reg, CHAN);
        reg.open{value: B0}(CHAN, address(attacker), relayer, block.timestamp + 1 days);
        vm.warp(block.timestamp + 1 days + 1);

        // The reentrant receive() makes `_pay` fail, so the outer call reverts.
        vm.expectRevert(bytes("PAY_FAILED"));
        reg.refundOnTimeout(CHAN);

        // Nothing was paid out; the escrow is intact and the channel still open.
        assertEq(address(reg).balance, B0, "escrow untouched after blocked reentry");
        assertEq(address(attacker).balance, 0, "attacker received nothing");
        (,,,,, ChannelRegistry.Status status,,,) = reg.channels(CHAN);
        assertEq(uint256(uint8(status)), uint256(uint8(ChannelRegistry.Status.Open)), "still open");
    }

    /// Control: a benign user (an EOA-like contract that doesn't reenter) refunds
    /// fine, proving the guard only blocks the malicious path.
    function test_BenignRefundSucceeds() public {
        // `address(this)` accepts ETH without reentering.
        reg.open{value: B0}(CHAN, address(this), relayer, block.timestamp + 1 days);
        vm.warp(block.timestamp + 1 days + 1);
        uint256 before = address(this).balance;
        reg.refundOnTimeout(CHAN);
        assertEq(address(this).balance - before, B0, "benign refund paid");
    }

    receive() external payable {}
}
