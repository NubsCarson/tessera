// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

/// @title TokenMint — the ETH-paid mint rail for Tessera's ecash access tokens
/// @notice The leaner architecture (`docs/ARCHITECTURE.md`) pays for access with
///         blind-signed ecash tokens (an ARC credential) instead of a payment
///         channel. This contract is the **on-chain purchase rail**: a buyer pays
///         ETH and earns a redeemable *entitlement* to N tokens; the off-chain
///         ARC issuer then **blind-issues** those N credentials and calls
///         {redeem} to consume the entitlement.
///
///         The privacy model is the standard ecash-mint one: this purchase is
///         on-chain and therefore links `buyer → "obtained N tokens"`, but the
///         credentials are **blind-issued** (the ARC issuance the issuer already
///         performs), so a token's later *presentations* are unlinkable to this
///         purchase — exactly the property that makes the channel + the shielded
///         pool + the MPC ceremony unnecessary for the common path. The mint
///         learns you withdrew, never what you spend it on.
///
/// @dev    UNAUDITED, testnet-only research code. The off-chain issuer watching
///         {Purchased} and blind-issuing is the operational integration (it
///         reuses the existing `tessera-arc` issuance); this contract is the
///         verifiable on-chain half — the entitlement ledger + double-issue
///         guard + proceeds accounting. CEI throughout; no external dependency.
contract TokenMint {
    /// The ARC issuer authorized to redeem entitlements (blind-issue the tokens)
    /// and withdraw sale proceeds. Immutable; set at deploy.
    address public immutable issuer;

    /// Price of one access token, in wei. Immutable.
    uint256 public immutable price;

    /// Unredeemed token entitlements per buyer (incremented on {purchase},
    /// decremented as the issuer blind-issues and {redeem}s them).
    mapping(address => uint256) public entitled;

    /// Sale proceeds the issuer may {withdraw}.
    uint256 public proceeds;

    event Purchased(address indexed buyer, uint256 tokens, uint256 paid);
    event Redeemed(address indexed buyer, uint256 tokens);
    event Withdrawn(address indexed to, uint256 amount);

    /// @param _issuer the ARC issuer (the only address that may redeem/withdraw)
    /// @param _price   wei per access token (must be non-zero)
    constructor(address _issuer, uint256 _price) {
        require(_issuer != address(0), "ZERO_ISSUER");
        require(_price > 0, "ZERO_PRICE");
        issuer = _issuer;
        price = _price;
    }

    // ---------------------------------------------------------------------
    // purchase — pay ETH, earn a token entitlement
    // ---------------------------------------------------------------------

    /// @notice Buy `floor(msg.value / price)` token entitlements; any remainder
    ///         below one token's price is refunded (no dust is silently kept).
    ///         The buyer then proves to the issuer (off-chain) that it controls
    ///         this address and the issuer blind-issues the tokens + {redeem}s.
    /// @dev    CEI: the ledger + proceeds are updated before the refund transfer.
    ///         A reentrant call during the refund carries `msg.value == 0` and
    ///         reverts `BELOW_PRICE`, so it cannot double-credit.
    function purchase() external payable {
        require(msg.value >= price, "BELOW_PRICE");
        uint256 tokens = msg.value / price;
        uint256 cost = tokens * price;

        entitled[msg.sender] += tokens;
        proceeds += cost;
        emit Purchased(msg.sender, tokens, cost);

        uint256 change = msg.value - cost;
        if (change > 0) {
            (bool ok,) = payable(msg.sender).call{value: change}("");
            require(ok, "REFUND_FAILED");
        }
    }

    // ---------------------------------------------------------------------
    // redeem — the issuer consumes an entitlement after blind-issuing
    // ---------------------------------------------------------------------

    /// @notice Consume `tokens` of `buyer`'s entitlement. Called by the issuer
    ///         **after** it has blind-issued those tokens via ARC, so a given
    ///         entitlement is turned into credentials exactly once (the double-
    ///         issue guard). Only the issuer may call it.
    function redeem(address buyer, uint256 tokens) external {
        require(msg.sender == issuer, "NOT_ISSUER");
        require(entitled[buyer] >= tokens, "INSUFFICIENT_ENTITLEMENT");
        entitled[buyer] -= tokens;
        emit Redeemed(buyer, tokens);
    }

    // ---------------------------------------------------------------------
    // withdraw — the issuer collects sale proceeds
    // ---------------------------------------------------------------------

    /// @notice Withdraw all accumulated sale proceeds to `to`. Issuer-only.
    /// @dev    CEI: `proceeds` is zeroed before the transfer, so a reentrant
    ///         withdraw sees 0 and transfers nothing.
    function withdraw(address to) external {
        require(msg.sender == issuer, "NOT_ISSUER");
        require(to != address(0), "ZERO_TO");
        uint256 amount = proceeds;
        proceeds = 0;
        (bool ok,) = payable(to).call{value: amount}("");
        require(ok, "WITHDRAW_FAILED");
    }
}

// forge-lint: payable purchase() takes value; receive() intentionally absent so
// stray plain transfers revert rather than being stranded.
