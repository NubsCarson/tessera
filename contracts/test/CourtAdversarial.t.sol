// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "./Std.sol";
import {ChannelRegistry, IRDecVerifier} from "../src/ChannelRegistry.sol";

/// Adversarial-caller + cross-contract tests for the on-chain court. Where
/// `ChannelRegistry.t.sol` proves the HAPPY paths, this file proves the court is
/// safe under an ACTIVE attacker (`mallory`): it cannot spend the issuer-only
/// (relayer-only) bond path, cannot close/dispute/slash a channel it is not a
/// party to, cannot replay or forge a signature, cannot double-close an
/// already-terminal channel, cannot refund before the deadline, and cannot
/// re-enter a terminal payout to drain the escrow twice (CEI + nonReentrant).
///
/// States are signed in-test with `vm.sign` over the contract's OWN
/// `stateDigest` so the test and contract agree on the encoding by construction.
/// The asserted revert strings are the EXACT `require(...)` reasons in
/// `ChannelRegistry.sol`, so any regression that changes the guard (or removes
/// it) flips a test from pass to fail.
contract CourtAdversarialTest is Test {
    ChannelRegistry reg;

    // Local test keys. mallory is the active attacker: a registered NON-party
    // to the channel under test.
    uint256 constant USER_PK = 0xA11CE;
    uint256 constant RELAYER_PK = 0xB0B;
    uint256 constant MALLORY_PK = 0xBAD;
    address user;
    address relayer;
    address mallory;

    bytes32 constant CHAN = bytes32(uint256(0xC0FFEE));
    bytes32 constant SALT = bytes32(uint256(0x5A17));
    uint256 constant B0 = 10 ether;
    uint256 constant BOND = 2 ether;

    function setUp() public {
        reg = new ChannelRegistry(IRDecVerifier(address(0)));
        user = vm.addr(USER_PK);
        relayer = vm.addr(RELAYER_PK);
        mallory = vm.addr(MALLORY_PK);
        vm.deal(address(this), 1000 ether);
    }

    // ----- helpers --------------------------------------------------------

    function _state(uint64 balance, uint64 seq)
        internal
        pure
        returns (ChannelRegistry.State memory)
    {
        return ChannelRegistry.State({chanId: CHAN, balance: balance, seq: seq, salt: SALT});
    }

    function _sign(uint256 pk, ChannelRegistry.State memory s)
        internal
        view
        returns (bytes32 r, bytes32 sigS, uint8 v)
    {
        (v, r, sigS) = vm.sign(pk, reg.stateDigest(s));
    }

    function _open() internal {
        reg.open{value: B0}(CHAN, user, relayer, block.timestamp + 7 days);
    }

    // Capture only the status field (index 5) of the channel record.
    function _status(bytes32 id) internal view returns (ChannelRegistry.Status st) {
        (,,,,, st,,,) = reg.channels(id);
    }

    // =====================================================================
    // (A) Non-relayer CANNOT call the relayer-only (issuer-only) bond path.
    // =====================================================================

    /// `fundRelayerBond` is the only `msg.sender`-gated path; an attacker who is
    /// not the registered relayer is rejected with `NOT_RELAYER` even though it
    /// supplies real value — so it cannot inject collateral it could later try
    /// to recover, nor grief the bond accounting.
    function test_RevertWhen_MalloryFundsRelayerBond() public {
        _open();
        vm.deal(mallory, BOND);
        vm.prank(mallory);
        vm.expectRevert(bytes("NOT_RELAYER"));
        reg.fundRelayerBond{value: BOND}(CHAN);
        // The bond stayed unfunded; only the escrow is held.
        assertEq(address(reg).balance, B0, "no attacker value entered the bond");
    }

    /// Even the USER (a real party, but the wrong one) cannot fund the bond:
    /// the bond is the relayer's collateral exclusively.
    function test_RevertWhen_UserFundsRelayerBond() public {
        _open();
        vm.deal(user, BOND);
        vm.prank(user);
        vm.expectRevert(bytes("NOT_RELAYER"));
        reg.fundRelayerBond{value: BOND}(CHAN);
    }

    // =====================================================================
    // (B) A non-participant CANNOT close / dispute / slash someone else's
    //     channel. The court authorizes by the REGISTERED parties' sigs, so an
    //     outsider's own signatures (even from the caller) fail recovery.
    // =====================================================================

    /// mallory tries to cooperatively close the channel using HER OWN key in
    /// the user slot. Recovery yields mallory's address, not the channel user.
    function test_RevertWhen_NonParticipantCooperativeCloses() public {
        _open();
        ChannelRegistry.State memory s = _state(6 ether, 5);
        // user slot signed by mallory (the attacker), relayer slot by the relayer.
        (bytes32 mr, bytes32 ms, uint8 mv) = _sign(MALLORY_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        vm.prank(mallory);
        vm.expectRevert(bytes("BAD_USER_SIG"));
        reg.cooperativeClose(s, mr, ms, mv, rr, rs, rv);
        // Channel untouched.
        assertEq(uint256(uint8(_status(CHAN))), uint256(uint8(ChannelRegistry.Status.Open)), "open");
        assertEq(address(reg).balance, B0, "escrow intact");
    }

    /// mallory tries to OPEN a unilateral dispute on a channel it is not part of.
    /// Both sig slots are mallory's → the relayer-sig check rejects it.
    function test_RevertWhen_NonParticipantUnilateralCloses() public {
        _open();
        ChannelRegistry.State memory s = _state(4 ether, 3);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s); // real user sig
        (bytes32 mr, bytes32 ms, uint8 mv) = _sign(MALLORY_PK, s); // attacker in relayer slot
        vm.prank(mallory);
        vm.expectRevert(bytes("BAD_RELAYER_SIG"));
        reg.unilateralClose(s, ur, us, uv, mr, ms, mv);
        assertEq(
            uint256(uint8(_status(CHAN))), uint256(uint8(ChannelRegistry.Status.Open)), "still open"
        );
    }

    /// mallory cannot slash the user with states mallory signed: equivocation is
    /// attributable only via the registered USER's key, which mallory lacks.
    function test_RevertWhen_NonParticipantSlashesUser() public {
        _open();
        ChannelRegistry.State memory a = _state(5 ether, 4);
        ChannelRegistry.State memory b = _state(7 ether, 4); // same seq, conflicting
        (bytes32 ar, bytes32 as_, uint8 av) = _sign(MALLORY_PK, a);
        (bytes32 br, bytes32 bs, uint8 bv) = _sign(MALLORY_PK, b);
        vm.prank(mallory);
        vm.expectRevert(bytes("BAD_USER_SIG_A"));
        reg.slashEquivocation(a, b, ar, as_, av, br, bs, bv);
        assertEq(address(reg).balance, B0, "no slash payout");
    }

    /// A malicious USER cannot fabricate relayer equivocation: it can only ever
    /// present states the relayer truly signed, and it cannot produce the
    /// relayer's signature, so substituting its own key fails recovery.
    function test_RevertWhen_UserFabricatesRelayerEquivocation() public {
        _open();
        ChannelRegistry.State memory a = _state(5 ether, 4);
        ChannelRegistry.State memory b = _state(7 ether, 4);
        // Attacker signs BOTH with the user key, pretending they are relayer sigs.
        (bytes32 ar, bytes32 as_, uint8 av) = _sign(USER_PK, a);
        (bytes32 br, bytes32 bs, uint8 bv) = _sign(USER_PK, b);
        vm.prank(user);
        vm.expectRevert(bytes("BAD_RELAYER_SIG_A"));
        reg.slashRelayerEquivocation(a, b, ar, as_, av, br, bs, bv);
        assertEq(uint256(uint8(_status(CHAN))), uint256(uint8(ChannelRegistry.Status.Open)), "open");
    }

    // =====================================================================
    // (C) Forged / tampered / cross-channel signatures revert.
    // =====================================================================

    /// A valid signature over a DIFFERENT state (the attacker flips the balance
    /// after signing) does not recover to the user — the digest binds balance.
    function test_RevertWhen_ForgedStateAfterSigning() public {
        _open();
        ChannelRegistry.State memory signed = _state(6 ether, 5);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, signed);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, signed);
        // Submit a forged state (balance bumped to 9) with sigs over the 6-ether one.
        ChannelRegistry.State memory forged = _state(9 ether, 5);
        vm.expectRevert(bytes("BAD_USER_SIG"));
        reg.cooperativeClose(forged, ur, us, uv, rr, rs, rv);
    }

    /// A signature with a mangled `r` component cannot recover to either party;
    /// ecrecover yields some other / zero address → BAD_USER_SIG.
    function test_RevertWhen_TamperedSignatureRComponent() public {
        _open();
        ChannelRegistry.State memory s = _state(6 ether, 5);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        bytes32 badR = bytes32(uint256(ur) ^ 1); // flip one bit of r
        vm.expectRevert(bytes("BAD_USER_SIG"));
        reg.cooperativeClose(s, badR, us, uv, rr, rs, rv);
    }

    /// A wholly zero signature (r=s=0, v=27) makes ecrecover return address(0),
    /// which never equals a registered party → BAD_USER_SIG. Confirms the court
    /// never treats the recovery-failure sentinel address(0) as authorized.
    function test_RevertWhen_ZeroSignature() public {
        _open();
        ChannelRegistry.State memory s = _state(6 ether, 5);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        vm.expectRevert(bytes("BAD_USER_SIG"));
        reg.cooperativeClose(s, bytes32(0), bytes32(0), 27, rr, rs, rv);
    }

    /// A signature with an out-of-range `v` (neither 27 nor 28) is rejected by
    /// recoverSigner's explicit guard, recovering to address(0) → BAD_USER_SIG.
    function test_RevertWhen_BadVRecoveryId() public {
        _open();
        ChannelRegistry.State memory s = _state(6 ether, 5);
        (bytes32 ur, bytes32 us,) = _sign(USER_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        vm.expectRevert(bytes("BAD_USER_SIG"));
        reg.cooperativeClose(s, ur, us, 29, rr, rs, rv); // v = 29 invalid
    }

    // =====================================================================
    // (D) Double-close / closing an already-terminal channel reverts.
    // =====================================================================

    /// Once cooperatively closed (terminal), a SECOND cooperative close with the
    /// same valid sigs reverts NOT_OPEN — no second payout is possible.
    function test_RevertWhen_DoubleCooperativeClose() public {
        _open();
        ChannelRegistry.State memory s = _state(6 ether, 5);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        reg.cooperativeClose(s, ur, us, uv, rr, rs, rv);
        assertEq(address(reg).balance, 0, "escrow drained by first close");

        // Second close on the now-Closed channel must revert; no extra payout.
        vm.expectRevert(bytes("NOT_OPEN"));
        reg.cooperativeClose(s, ur, us, uv, rr, rs, rv);
    }

    /// After a timeout refund (terminal), refunding again reverts NOT_OPEN — the
    /// escrow cannot be drained twice via the refund branch.
    function test_RevertWhen_DoubleRefundOnTimeout() public {
        _open();
        vm.warp(block.timestamp + 7 days + 1);
        reg.refundOnTimeout(CHAN);
        assertEq(address(reg).balance, 0, "escrow drained by first refund");
        vm.expectRevert(bytes("NOT_OPEN"));
        reg.refundOnTimeout(CHAN);
    }

    /// A settled dispute is terminal: re-settling reverts NOT_DISPUTING, and a
    /// late cooperative close on the settled channel reverts NOT_OPEN.
    function test_RevertWhen_SettleDisputeTwice() public {
        _open();
        ChannelRegistry.State memory s = _state(3 ether, 9);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        reg.unilateralClose(s, ur, us, uv, rr, rs, rv);
        vm.warp(block.timestamp + reg.CHALLENGE_WINDOW() + 1);
        reg.settleDispute(CHAN);
        assertEq(address(reg).balance, 0, "escrow drained by settle");

        vm.expectRevert(bytes("NOT_DISPUTING"));
        reg.settleDispute(CHAN);

        vm.expectRevert(bytes("NOT_OPEN"));
        reg.cooperativeClose(s, ur, us, uv, rr, rs, rv);
    }

    /// A unilateral close cannot be started on a channel already cooperatively
    /// closed — the dispute machinery can't reopen a terminal channel.
    function test_RevertWhen_DisputeAfterCooperativeClose() public {
        _open();
        ChannelRegistry.State memory s = _state(6 ether, 5);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        reg.cooperativeClose(s, ur, us, uv, rr, rs, rv);
        vm.expectRevert(bytes("NOT_OPEN"));
        reg.unilateralClose(s, ur, us, uv, rr, rs, rv);
    }

    // =====================================================================
    // (E) refundOnTimeout before the deadline reverts.
    // =====================================================================

    /// One second before `timeout` the refund branch must still be closed.
    function test_RevertWhen_RefundOneSecondBeforeTimeout() public {
        _open();
        // open used `block.timestamp + 7 days`; warp to exactly one second short.
        vm.warp(block.timestamp + 7 days - 1);
        vm.expectRevert(bytes("BEFORE_TIMEOUT"));
        reg.refundOnTimeout(CHAN);
        assertEq(address(reg).balance, B0, "escrow not refunded early");
    }

    // =====================================================================
    // (F) Reentrancy: a malicious recipient that re-enters on ETH receive
    //     cannot double-withdraw / double-refund. CEI + nonReentrant hold, and
    //     because `_pay` bubbles the failure the whole call reverts atomically.
    // =====================================================================

    /// The malicious user re-enters `refundOnTimeout` from its `receive()`. The
    /// guard makes the reentrant call revert; `_pay` bubbles PAY_FAILED, the
    /// outer refund reverts, and NOTHING is paid — the escrow is never withdrawn
    /// even once, let alone twice. (CEI + nonReentrant.)
    function test_RevertWhen_ReentrantRefundBlocked() public {
        ReentrantParty attacker = new ReentrantParty();
        bytes32 chan = bytes32(uint256(0xBEEF1));
        attacker.armRefund(reg, chan);
        reg.open{value: B0}(chan, address(attacker), relayer, block.timestamp + 1 days);
        vm.warp(block.timestamp + 1 days + 1);

        vm.expectRevert(bytes("PAY_FAILED"));
        reg.refundOnTimeout(chan);

        assertEq(address(reg).balance, B0, "escrow intact after blocked reentry");
        assertEq(address(attacker).balance, 0, "attacker received nothing");
        assertEq(
            uint256(uint8(_status(chan))), uint256(uint8(ChannelRegistry.Status.Open)), "still open"
        );
    }

    /// The attacker re-enters from a benign-looking control too: a NON-reentrant
    /// recipient (this test contract) refunds cleanly, proving the guard blocks
    /// only the malicious path and the PAY_FAILED revert above is caused by the
    /// reentry, not by some unrelated rejection of contract recipients.
    function test_BenignContractRecipientRefundSucceeds() public {
        bytes32 chan = bytes32(uint256(0xBEEF2));
        // `address(this)` accepts ETH without reentering (its receive is a no-op).
        reg.open{value: B0}(chan, address(this), relayer, block.timestamp + 1 days);
        vm.warp(block.timestamp + 1 days + 1);
        uint256 before = address(this).balance;
        reg.refundOnTimeout(chan);
        assertEq(address(this).balance - before, B0, "benign contract recipient refunded once");
        assertEq(
            uint256(uint8(_status(chan))),
            uint256(uint8(ChannelRegistry.Status.Closed)),
            "closed once"
        );
    }

    receive() external payable {}
}

/// A malicious channel party (user) that, on receiving ETH, tries to re-enter
/// the registry's terminal refund path to drain the escrow a second time. The
/// `nonReentrant` guard must make the reentrant call revert, which `_pay`
/// bubbles, reverting the whole outer call.
contract ReentrantParty {
    ChannelRegistry public reg;
    bytes32 public chan;
    bool public fired;

    function armRefund(ChannelRegistry _reg, bytes32 _chan) external {
        reg = _reg;
        chan = _chan;
    }

    receive() external payable {
        if (!fired) {
            fired = true;
            // Re-enter the same terminal payout path. The guard must revert.
            reg.refundOnTimeout(chan);
        }
    }
}
