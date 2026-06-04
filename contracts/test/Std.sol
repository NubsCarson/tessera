// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

/// Minimal Foundry cheatcode interface — vendored so the suite needs no
/// `forge-std` dependency (and therefore no `forge install` / network in CI).
/// Only the cheatcodes the tests actually use are declared. The address is the
/// canonical hevm cheatcode address `address(keccak256("hevm cheat code"))`.
interface Vm {
    /// Derive the address for a given private key (secp256k1).
    function addr(uint256 privateKey) external pure returns (address);
    /// Sign `digest` with `privateKey`, returning `(v, r, s)`.
    function sign(uint256 privateKey, bytes32 digest)
        external
        pure
        returns (uint8 v, bytes32 r, bytes32 s);
    /// Set an account's ETH balance.
    function deal(address who, uint256 newBalance) external;
    /// Set `msg.sender` for the next call.
    function prank(address sender) external;
    /// Set `msg.sender` for all subsequent calls until `stopPrank`.
    function startPrank(address sender) external;
    function stopPrank() external;
    /// Fast-forward `block.timestamp` to `newTimestamp`.
    function warp(uint256 newTimestamp) external;
    /// Expect the next call to revert (any reason).
    function expectRevert() external;
    /// Expect the next call to revert with this exact reason string/bytes.
    function expectRevert(bytes calldata revertData) external;
    /// Label an address for nicer traces.
    function label(address account, string calldata newLabel) external;
}

/// Tiny `Test` base: the cheatcode handle plus a few assertion helpers. A test
/// contract `is Test` and exposes `testXxx()` / `test_RevertXxx()` functions
/// that `forge test` discovers. Failed assertions `revert`, which Foundry
/// reports as a failing test.
contract Test {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool cond, string memory err) internal pure {
        require(cond, err);
    }

    function assertEq(uint256 a, uint256 b, string memory err) internal pure {
        require(a == b, err);
    }

    function assertEq(address a, address b, string memory err) internal pure {
        require(a == b, err);
    }

    function assertEq(bytes32 a, bytes32 b, string memory err) internal pure {
        require(a == b, err);
    }

    function fail(string memory err) internal pure {
        revert(err);
    }
}
