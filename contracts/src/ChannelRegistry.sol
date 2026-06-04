// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

/// @title ChannelRegistry — the EVM on-chain court for Tessera's ZK Spilman channel
/// @notice Phase 2c of `docs/DESIGN.md` §2/§6. This is the on-chain analogue of
///         the off-chain verdict logic in `crates/tessera-channel/src/settlement.rs`:
///         it escrows the channel balance, settles cooperatively or after a
///         unilateral-close dispute window at the highest doubly-signed state,
///         slashes provable user equivocation, and refunds the user on timeout.
///
///         It verifies channel states with the EVM-native `ecrecover` precompile
///         over the SAME recoverable secp256k1 signatures that
///         `tessera-channel` (Rust) produces — see {stateDigest}. The Rust↔Solidity
///         match is pinned by `test/CrossLanguageVector.t.sol`.
///
/// @dev    UNAUDITED, testnet-only research code. Not for mainnet / real funds.
///
///         Spilman model: the escrow is spendable by *(relayer countersignature
///         on the latest state)* OR *(the user alone after `timeout`)* — the
///         refund-on-timeout branch is load-bearing for payer safety. The channel
///         is unidirectional and monotone-decrementing: `balance` is what still
///         belongs to the USER; the relayer is owed `B0 - balance`.
contract ChannelRegistry {
    // ---------------------------------------------------------------------
    // Domain separation — MUST byte-match crates/tessera-channel.
    // ---------------------------------------------------------------------

    /// SHA-256 domain for the state commitment S_i (state.rs STATE_DOMAIN).
    bytes constant STATE_DOMAIN = "tessera-channel/state/v1";
    /// keccak256 domain for the chain-facing signed digest (state.rs STATE_SIG_DOMAIN).
    bytes constant STATE_SIG_DOMAIN = "tessera-channel/state-sig/v1";

    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    /// A channel state `(chanId, balance, seq, salt)` — mirrors `ChannelState`.
    struct State {
        bytes32 chanId;
        uint64 balance;
        uint64 seq;
        bytes32 salt;
    }

    enum Status {
        None, // never opened
        Open, // escrow funded, no dispute
        Disputing, // unilateral close started; challenge window open
        Closed // settled / slashed / refunded — terminal
    }

    /// Per-channel on-chain record.
    struct Channel {
        address user; // the payer; equivocation is attributed to this address
        address relayer; // the single payee / counterparty
        uint128 b0; // funded escrow B0 (== msg.value at open)
        uint128 bond; // slashable user stake (this model: == B0)
        uint64 timeout; // refund-on-timeout deadline (unix seconds)
        Status status;
        // dispute bookkeeping (only meaningful while Disputing):
        uint64 bestSeq; // highest doubly-signed seq submitted so far
        uint64 bestBalance; // the user balance at that state
        uint64 challengeEnd; // unix second the challenge window closes
    }

    /// channelId => record.
    mapping(bytes32 => Channel) public channels;

    /// Length of the unilateral-close challenge window, in seconds.
    uint64 public constant CHALLENGE_WINDOW = 1 days;

    // ---------------------------------------------------------------------
    // Reentrancy guard (minimal, no external dep).
    // ---------------------------------------------------------------------
    uint256 private _locked = 1;

    modifier nonReentrant() {
        require(_locked == 1, "REENTRANCY");
        _locked = 2;
        _;
        _locked = 1;
    }

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------
    event Opened(
        bytes32 indexed channelId, address user, address relayer, uint256 b0, uint64 timeout
    );
    event CooperativeClosed(
        bytes32 indexed channelId, uint64 seq, uint256 relayerPayout, uint256 userRefund
    );
    event DisputeStarted(bytes32 indexed channelId, uint64 seq, uint64 challengeEnd);
    event Challenged(bytes32 indexed channelId, uint64 newSeq);
    event DisputeSettled(
        bytes32 indexed channelId, uint64 seq, uint256 relayerPayout, uint256 userRefund
    );
    event Slashed(bytes32 indexed channelId, uint64 seq, uint256 toRelayer);
    event RefundedOnTimeout(bytes32 indexed channelId, uint256 userRefund);

    // ---------------------------------------------------------------------
    // Digest / verification (the cross-language crypto surface)
    // ---------------------------------------------------------------------

    /// @notice The SHA-256 state commitment S_i — byte-identical to
    ///         `ChannelState::commitment()` in Rust:
    ///         `sha256( be64(len(STATE_DOMAIN)) || STATE_DOMAIN ||
    ///                  chanId || be64(balance) || be64(seq) || salt )`.
    /// @dev    `tessera-channel` length-prefixes the domain with a big-endian
    ///         u64; `uint64(STATE_DOMAIN.length)` encodes to the same 8 BE bytes.
    function commitment(State memory s) public pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                uint64(STATE_DOMAIN.length),
                STATE_DOMAIN,
                s.chanId,
                uint64(s.balance),
                uint64(s.seq),
                s.salt
            )
        );
    }

    /// @notice The chain-facing keccak256 digest that is actually signed and fed
    ///         to `ecrecover` — byte-identical to `ChannelState::state_digest()`:
    ///         `keccak256( be64(len(STATE_SIG_DOMAIN)) || STATE_SIG_DOMAIN || commitment )`.
    function stateDigest(State memory s) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(uint64(STATE_SIG_DOMAIN.length), STATE_SIG_DOMAIN, commitment(s))
        );
    }

    /// @notice Recover the signer of a state from a 65-byte-equivalent `(r,s,v)`
    ///         recoverable secp256k1 signature — exactly what Rust's
    ///         `VerifyingKey::recover_from_digest` does.
    /// @return The recovered address, or `address(0)` if recovery fails / `s` is
    ///         in the high half (malleable). We enforce low-`s` so a state has a
    ///         single canonical signature (matching Rust's normalized `s`).
    function recoverSigner(State memory s, bytes32 r, bytes32 sigS, uint8 v)
        public
        pure
        returns (address)
    {
        // Enforce EIP-2 low-`s`: secp256k1n/2.
        if (uint256(sigS) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v != 27 && v != 28) {
            return address(0);
        }
        return ecrecover(stateDigest(s), v, r, sigS);
    }

    // ---------------------------------------------------------------------
    // open
    // ---------------------------------------------------------------------

    /// @notice Open a channel, escrowing `B0 = msg.value`.
    /// @dev    Stores the genesis parameters, both participant keys (addresses),
    ///         the refund-on-timeout deadline, and a user bond. In this model the
    ///         escrow doubles as the slashable bond (`bond == B0`): the user's
    ///         at-risk stake IS its escrowed balance, so provable equivocation
    ///         forfeits it to the counterparty (see {slashEquivocation}).
    /// @param  channelId opaque 32-byte channel id (pool-derived in the full design)
    /// @param  user      the payer address (equivocation is attributed here)
    /// @param  relayer   the single payee / counterparty
    /// @param  timeout   unix second after which the user may refund (must be future)
    function open(bytes32 channelId, address user, address relayer, uint256 timeout)
        external
        payable
    {
        require(channels[channelId].status == Status.None, "ALREADY_OPEN");
        require(user != address(0) && relayer != address(0), "ZERO_ADDR");
        require(user != relayer, "SAME_PARTY");
        require(msg.value > 0, "ZERO_ESCROW");
        require(msg.value <= type(uint128).max, "ESCROW_TOO_LARGE");
        require(timeout > block.timestamp, "TIMEOUT_IN_PAST");
        require(timeout <= type(uint64).max, "TIMEOUT_TOO_LARGE");

        channels[channelId] = Channel({
            user: user,
            relayer: relayer,
            // forge-lint: disable-next-line(unsafe-typecast)
            b0: uint128(msg.value),
            // forge-lint: disable-next-line(unsafe-typecast)
            bond: uint128(msg.value),
            // forge-lint: disable-next-line(unsafe-typecast)
            timeout: uint64(timeout),
            status: Status.Open,
            bestSeq: 0,
            bestBalance: 0,
            challengeEnd: 0
        });

        // forge-lint: disable-next-line(unsafe-typecast)
        emit Opened(channelId, user, relayer, msg.value, uint64(timeout));
    }

    // ---------------------------------------------------------------------
    // cooperativeClose
    // ---------------------------------------------------------------------

    /// @notice Cooperative close at a doubly-signed `state`: pay the relayer
    ///         `B0 - balance` and refund the user `balance` (they sum to B0).
    /// @dev    Mirrors `Verdict::Settle`. Requires BOTH a valid user signature and
    ///         a valid relayer co-signature over the state (i.e. a doubly-signed
    ///         "unit of truth"). Checks-effects-interactions + nonReentrant.
    /// @param  state         the agreed final state (`chanId` must match)
    /// @param  userR/S/V     the user's recoverable secp256k1 signature
    /// @param  relayerR/S/V  the relayer's co-signature over the same state
    function cooperativeClose(
        State calldata state,
        bytes32 userR,
        bytes32 userS,
        uint8 userV,
        bytes32 relayerR,
        bytes32 relayerS,
        uint8 relayerV
    ) external nonReentrant {
        Channel storage ch = channels[state.chanId];
        require(ch.status == Status.Open, "NOT_OPEN");
        require(state.balance <= ch.b0, "BALANCE_GT_B0");

        // Both signatures must be present and valid (doubly-signed).
        require(recoverSigner(state, userR, userS, userV) == ch.user, "BAD_USER_SIG");
        require(recoverSigner(state, relayerR, relayerS, relayerV) == ch.relayer, "BAD_RELAYER_SIG");

        uint256 relayerPayout = uint256(ch.b0) - uint256(state.balance);
        uint256 userRefund = uint256(state.balance);
        address user = ch.user;
        address relayer = ch.relayer;

        // Effects: terminal before any value transfer.
        ch.status = Status.Closed;

        // Interactions.
        _pay(relayer, relayerPayout);
        _pay(user, userRefund);

        emit CooperativeClosed(state.chanId, state.seq, relayerPayout, userRefund);
    }

    // ---------------------------------------------------------------------
    // unilateralClose + challenge + settleDispute
    // ---------------------------------------------------------------------

    /// @notice Start a unilateral close at a doubly-signed `state`, opening a
    ///         challenge window in which the counterparty can override with a
    ///         strictly-higher-seq doubly-signed state ({challenge}).
    /// @dev    Either party can start it (it requires a doubly-signed state, which
    ///         only honest cooperation could have produced). Mirrors the design's
    ///         "unilateral close opens a dispute window where the highest
    ///         doubly-signed seq wins".
    function unilateralClose(
        State calldata state,
        bytes32 userR,
        bytes32 userS,
        uint8 userV,
        bytes32 relayerR,
        bytes32 relayerS,
        uint8 relayerV
    ) external {
        Channel storage ch = channels[state.chanId];
        require(ch.status == Status.Open, "NOT_OPEN");
        require(state.balance <= ch.b0, "BALANCE_GT_B0");
        require(recoverSigner(state, userR, userS, userV) == ch.user, "BAD_USER_SIG");
        require(recoverSigner(state, relayerR, relayerS, relayerV) == ch.relayer, "BAD_RELAYER_SIG");

        ch.status = Status.Disputing;
        ch.bestSeq = state.seq;
        ch.bestBalance = state.balance;
        ch.challengeEnd = uint64(block.timestamp) + CHALLENGE_WINDOW;

        emit DisputeStarted(state.chanId, state.seq, ch.challengeEnd);
    }

    /// @notice During the challenge window, override the current best with a
    ///         STRICTLY-higher-seq doubly-signed state (the latest truth wins).
    function challenge(
        State calldata state,
        bytes32 userR,
        bytes32 userS,
        uint8 userV,
        bytes32 relayerR,
        bytes32 relayerS,
        uint8 relayerV
    ) external {
        Channel storage ch = channels[state.chanId];
        require(ch.status == Status.Disputing, "NOT_DISPUTING");
        require(block.timestamp <= ch.challengeEnd, "WINDOW_CLOSED");
        require(state.seq > ch.bestSeq, "NOT_HIGHER_SEQ");
        require(state.balance <= ch.b0, "BALANCE_GT_B0");
        require(recoverSigner(state, userR, userS, userV) == ch.user, "BAD_USER_SIG");
        require(recoverSigner(state, relayerR, relayerS, relayerV) == ch.relayer, "BAD_RELAYER_SIG");

        ch.bestSeq = state.seq;
        ch.bestBalance = state.balance;

        emit Challenged(state.chanId, state.seq);
    }

    /// @notice After the challenge window closes, settle at the highest
    ///         doubly-signed state seen: relayer gets `B0 - bestBalance`, user
    ///         gets `bestBalance`. CEI + nonReentrant.
    function settleDispute(bytes32 channelId) external nonReentrant {
        Channel storage ch = channels[channelId];
        require(ch.status == Status.Disputing, "NOT_DISPUTING");
        require(block.timestamp > ch.challengeEnd, "WINDOW_OPEN");

        uint256 relayerPayout = uint256(ch.b0) - uint256(ch.bestBalance);
        uint256 userRefund = uint256(ch.bestBalance);
        address user = ch.user;
        address relayer = ch.relayer;
        uint64 seq = ch.bestSeq;

        ch.status = Status.Closed;

        _pay(relayer, relayerPayout);
        _pay(user, userRefund);

        emit DisputeSettled(channelId, seq, relayerPayout, userRefund);
    }

    // ---------------------------------------------------------------------
    // slashEquivocation
    // ---------------------------------------------------------------------

    /// @notice Slash provable user equivocation: two states at the SAME seq with
    ///         DIFFERENT commitments, both carrying the user's valid secp256k1
    ///         signature, are attributable double-spend. Mirrors
    ///         `Verdict::SlashUser`. The user's at-risk escrow/bond is forfeited
    ///         to the relayer (the bonded counterparty). CEI + nonReentrant.
    /// @dev    Only the user's signatures are required (the equivocation is the
    ///         user's fault and is provable from the user's key alone — exactly
    ///         the off-chain settlement rule: "both bear the user's valid sig").
    function slashEquivocation(
        State calldata stateA,
        State calldata stateB,
        bytes32 userRA,
        bytes32 userSA,
        uint8 userVA,
        bytes32 userRB,
        bytes32 userSB,
        uint8 userVB
    ) external nonReentrant {
        require(stateA.chanId == stateB.chanId, "DIFFERENT_CHANNEL");
        Channel storage ch = channels[stateA.chanId];
        // Slashing is valid whether the channel is Open or already Disputing.
        require(ch.status == Status.Open || ch.status == Status.Disputing, "NOT_SLASHABLE");

        require(stateA.seq == stateB.seq, "SEQ_MISMATCH");
        bytes32 cA = commitment(stateA);
        bytes32 cB = commitment(stateB);
        require(cA != cB, "SAME_COMMITMENT"); // must actually conflict

        // Both conflicting states must bear the USER's valid signature.
        require(recoverSigner(stateA, userRA, userSA, userVA) == ch.user, "BAD_USER_SIG_A");
        require(recoverSigner(stateB, userRB, userSB, userVB) == ch.user, "BAD_USER_SIG_B");

        uint256 toRelayer = uint256(ch.b0); // escrow doubles as the bond here
        address relayer = ch.relayer;
        uint64 seq = stateA.seq;

        ch.status = Status.Closed;

        _pay(relayer, toRelayer);

        emit Slashed(stateA.chanId, seq, toRelayer);
    }

    // ---------------------------------------------------------------------
    // refundOnTimeout
    // ---------------------------------------------------------------------

    /// @notice After `timeout` with no advance (relayer-dark), refund the user
    ///         the full escrow B0. Mirrors `Verdict::RefundUser`. CEI + nonReentrant.
    /// @dev    Callable only while still `Open` (no cooperative/unilateral close
    ///         has happened). The refund branch is the payer-safety backstop.
    function refundOnTimeout(bytes32 channelId) external nonReentrant {
        Channel storage ch = channels[channelId];
        require(ch.status == Status.Open, "NOT_OPEN");
        require(block.timestamp >= ch.timeout, "BEFORE_TIMEOUT");

        uint256 userRefund = uint256(ch.b0);
        address user = ch.user;

        ch.status = Status.Closed;

        _pay(user, userRefund);

        emit RefundedOnTimeout(channelId, userRefund);
    }

    // ---------------------------------------------------------------------
    // internals
    // ---------------------------------------------------------------------

    /// @dev Pay `amount` to `to` (no-op on zero). Reverts on failure so a stuck
    ///      transfer cannot silently strand funds.
    function _pay(address to, uint256 amount) private {
        if (amount == 0) return;
        (bool ok,) = payable(to).call{value: amount}("");
        require(ok, "PAY_FAILED");
    }
}
