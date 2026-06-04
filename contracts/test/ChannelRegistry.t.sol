// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "./Std.sol";
import {ChannelRegistry, IRDecVerifier} from "../src/ChannelRegistry.sol";

/// Functional tests for the on-chain court, each mirroring a `settlement.rs`
/// verdict. States are signed in-test with `vm.sign` over the contract's OWN
/// `stateDigest` (so the test and contract agree on the encoding by construction;
/// the *cross-language* match with Rust is proven separately in
/// `CrossLanguageVector.t.sol`).
contract ChannelRegistryTest is Test {
    ChannelRegistry reg;

    // Local test keys.
    uint256 constant USER_PK = 0xA11CE;
    uint256 constant RELAYER_PK = 0xB0B;
    uint256 constant MALLORY_PK = 0xBAD;
    address user;
    address relayer;
    address mallory;

    bytes32 constant CHAN = bytes32(uint256(0xC0FFEE));
    bytes32 constant SALT = bytes32(uint256(0x5A17));
    uint256 constant B0 = 10 ether;

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

    function _stateOn(bytes32 chanId, uint64 balance, uint64 seq)
        internal
        pure
        returns (ChannelRegistry.State memory)
    {
        return ChannelRegistry.State({chanId: chanId, balance: balance, seq: seq, salt: SALT});
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

    // ----- open -----------------------------------------------------------

    function testOpenEscrowsAndStores() public {
        _open();
        (
            address u,
            address rl,
            uint128 b0,
            uint128 bond,
            uint64 timeout,
            ChannelRegistry.Status status,,,
        ) = reg.channels(CHAN);
        assertEq(u, user, "user");
        assertEq(rl, relayer, "relayer");
        assertEq(uint256(b0), B0, "b0");
        assertEq(uint256(bond), B0, "bond == b0");
        assertTrue(timeout > block.timestamp, "timeout future");
        assertEq(uint256(uint8(status)), uint256(uint8(ChannelRegistry.Status.Open)), "open");
        assertEq(address(reg).balance, B0, "escrow held");
    }

    function test_RevertWhen_OpenTwice() public {
        _open();
        vm.expectRevert(bytes("ALREADY_OPEN"));
        reg.open{value: B0}(CHAN, user, relayer, block.timestamp + 7 days);
    }

    // ----- cooperativeClose ----------------------------------------------

    function testCooperativeClosePaysCorrectly() public {
        _open();
        // user keeps 6 ether, relayer owed 4 ether.
        ChannelRegistry.State memory s = _state(6 ether, 5);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);

        uint256 u0 = user.balance;
        uint256 r0 = relayer.balance;
        reg.cooperativeClose(s, ur, us, uv, rr, rs, rv);

        assertEq(relayer.balance - r0, 4 ether, "relayer paid B0-balance");
        assertEq(user.balance - u0, 6 ether, "user refunded balance");
        assertEq(address(reg).balance, 0, "escrow drained");
    }

    /// Reject a state that carries only the user's signature (relayer slot is a
    /// SECOND user signature) — a doubly-"signed" forgery by one party fails.
    function test_RevertWhen_SingleSignedClose() public {
        _open();
        ChannelRegistry.State memory s = _state(6 ether, 5);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        // relayer slot filled with the USER's signature → bad relayer sig.
        vm.expectRevert(bytes("BAD_RELAYER_SIG"));
        reg.cooperativeClose(s, ur, us, uv, ur, us, uv);
    }

    /// A relayer signature from the WRONG key (mallory) is rejected.
    function test_RevertWhen_WrongRelayerKey() public {
        _open();
        ChannelRegistry.State memory s = _state(6 ether, 5);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        (bytes32 mr, bytes32 ms, uint8 mv) = _sign(MALLORY_PK, s);
        vm.expectRevert(bytes("BAD_RELAYER_SIG"));
        reg.cooperativeClose(s, ur, us, uv, mr, ms, mv);
    }

    // ----- unilateralClose + challenge + settleDispute -------------------

    function testUnilateralCloseThenChallengeSettlesAtHighestSeq() public {
        _open();
        // Relayer starts a unilateral close at an OLD low-seq state (balance 8).
        ChannelRegistry.State memory old = _state(8 ether, 2);
        (bytes32 our, bytes32 ous, uint8 ouv) = _sign(USER_PK, old);
        (bytes32 orr, bytes32 ors, uint8 orv) = _sign(RELAYER_PK, old);
        reg.unilateralClose(old, our, ous, ouv, orr, ors, orv);

        // Counterparty challenges with a strictly-higher-seq state (balance 3).
        ChannelRegistry.State memory newer = _state(3 ether, 9);
        (bytes32 nur, bytes32 nus, uint8 nuv) = _sign(USER_PK, newer);
        (bytes32 nrr, bytes32 nrs, uint8 nrv) = _sign(RELAYER_PK, newer);
        reg.challenge(newer, nur, nus, nuv, nrr, nrs, nrv);

        // After the window, settle at the highest (seq 9, balance 3).
        vm.warp(block.timestamp + reg.CHALLENGE_WINDOW() + 1);
        uint256 u0 = user.balance;
        uint256 r0 = relayer.balance;
        reg.settleDispute(CHAN);

        assertEq(relayer.balance - r0, 7 ether, "relayer paid B0-3");
        assertEq(user.balance - u0, 3 ether, "user refunded 3");
    }

    function test_RevertWhen_ChallengeWithLowerSeq() public {
        _open();
        ChannelRegistry.State memory hi = _state(3 ether, 9);
        (bytes32 hur, bytes32 hus, uint8 huv) = _sign(USER_PK, hi);
        (bytes32 hrr, bytes32 hrs, uint8 hrv) = _sign(RELAYER_PK, hi);
        reg.unilateralClose(hi, hur, hus, huv, hrr, hrs, hrv);

        ChannelRegistry.State memory lo = _state(8 ether, 2);
        (bytes32 lur, bytes32 lus, uint8 luv) = _sign(USER_PK, lo);
        (bytes32 lrr, bytes32 lrs, uint8 lrv) = _sign(RELAYER_PK, lo);
        vm.expectRevert(bytes("NOT_HIGHER_SEQ"));
        reg.challenge(lo, lur, lus, luv, lrr, lrs, lrv);
    }

    function test_RevertWhen_SettleBeforeWindowCloses() public {
        _open();
        ChannelRegistry.State memory s = _state(8 ether, 2);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        reg.unilateralClose(s, ur, us, uv, rr, rs, rv);
        vm.expectRevert(bytes("WINDOW_OPEN"));
        reg.settleDispute(CHAN);
    }

    // ----- slashEquivocation ---------------------------------------------

    function testSlashEquivocationOnConflictingDoublySignedStates() public {
        _open();
        // Two DIFFERENT states at the SAME seq, both validly signed by the user.
        ChannelRegistry.State memory a = _state(5 ether, 4);
        ChannelRegistry.State memory b = _state(7 ether, 4); // same seq, different balance
        (bytes32 ar, bytes32 as_, uint8 av) = _sign(USER_PK, a);
        (bytes32 br, bytes32 bs, uint8 bv) = _sign(USER_PK, b);

        uint256 r0 = relayer.balance;
        reg.slashEquivocation(a, b, ar, as_, av, br, bs, bv);

        // The user's bond (== B0) is forfeited to the relayer.
        assertEq(relayer.balance - r0, B0, "relayer gets slashed bond");
        assertEq(address(reg).balance, 0, "escrow drained on slash");
    }

    /// Same seq but IDENTICAL state is not equivocation.
    function test_RevertWhen_SlashSameCommitment() public {
        _open();
        ChannelRegistry.State memory a = _state(5 ether, 4);
        (bytes32 ar, bytes32 as_, uint8 av) = _sign(USER_PK, a);
        vm.expectRevert(bytes("SAME_COMMITMENT"));
        reg.slashEquivocation(a, a, ar, as_, av, ar, as_, av);
    }

    /// Different seqs is not equivocation (linear advance, not a fork).
    function test_RevertWhen_SlashDifferentSeq() public {
        _open();
        ChannelRegistry.State memory a = _state(5 ether, 4);
        ChannelRegistry.State memory b = _state(5 ether, 5);
        (bytes32 ar, bytes32 as_, uint8 av) = _sign(USER_PK, a);
        (bytes32 br, bytes32 bs, uint8 bv) = _sign(USER_PK, b);
        vm.expectRevert(bytes("SEQ_MISMATCH"));
        reg.slashEquivocation(a, b, ar, as_, av, br, bs, bv);
    }

    /// A conflicting pair where one state is NOT signed by the user can't slash.
    function test_RevertWhen_SlashWithoutUserSig() public {
        _open();
        ChannelRegistry.State memory a = _state(5 ether, 4);
        ChannelRegistry.State memory b = _state(7 ether, 4);
        (bytes32 ar, bytes32 as_, uint8 av) = _sign(USER_PK, a);
        // second "user" sig is actually mallory's → BAD_USER_SIG_B.
        (bytes32 br, bytes32 bs, uint8 bv) = _sign(MALLORY_PK, b);
        vm.expectRevert(bytes("BAD_USER_SIG_B"));
        reg.slashEquivocation(a, b, ar, as_, av, br, bs, bv);
    }

    // ----- refundOnTimeout ------------------------------------------------

    function testRefundOnTimeoutReturnsB0ToUser() public {
        _open();
        vm.warp(block.timestamp + 7 days + 1);
        uint256 u0 = user.balance;
        reg.refundOnTimeout(CHAN);
        assertEq(user.balance - u0, B0, "user refunded full B0");
        assertEq(address(reg).balance, 0, "escrow drained");
    }

    function test_RevertWhen_RefundBeforeTimeout() public {
        _open();
        vm.expectRevert(bytes("BEFORE_TIMEOUT"));
        reg.refundOnTimeout(CHAN);
    }

    // ----- channel isolation ---------------------------------------------

    /// A state for a DIFFERENT channel id can't close this channel (the digest
    /// folds in chanId, and the contract looks up by `state.chanId`).
    function test_RevertWhen_CloseWithForeignChannelState() public {
        _open();
        bytes32 other = bytes32(uint256(0xDEAD));
        ChannelRegistry.State memory s = _stateOn(other, 6 ether, 5);
        (bytes32 ur, bytes32 us, uint8 uv) = _sign(USER_PK, s);
        (bytes32 rr, bytes32 rs, uint8 rv) = _sign(RELAYER_PK, s);
        // Looked up under `other`, which was never opened → NOT_OPEN.
        vm.expectRevert(bytes("NOT_OPEN"));
        reg.cooperativeClose(s, ur, us, uv, rr, rs, rv);
    }
}
