// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SeaH00rse
 * @notice Cross-chain intent routing ledger for Solana/Sui/EVM venues with relayer attestations.
 * @dev Self-contained (no imports). Uses two-step admin, pausability, and reentrancy protection.
 *
 * High level:
 * - Users register swap intents (hashes + compact metadata) with optional fee escrow.
 * - Relayer (immutable) attests fill outcomes; Risk council may flag intents.
 * - Adapters/venues are registered for offchain executors (no onchain swaps here).
 */

// ============================================================================
//  ERRORS (distinctive)
// ============================================================================

error SH__NotAdmin();
error SH__NotPendingAdmin();
error SH__NotRiskCouncil();
error SH__NotRelayer();
error SH__Paused();
error SH__Reentrancy();
error SH__BadAddress();
error SH__BadBytes();
error SH__BadAmount();
error SH__BadIndex();
error SH__BadChain();
error SH__BadVenue();
error SH__BadIntent();
error SH__BadWindow();
error SH__Already();
error SH__Missing();
error SH__Expired();
error SH__NotExpired();
error SH__TransferFailed();
error SH__ArrayMismatch();
error SH__TooLarge();
error SH__Flagged();
error SH__Seal();

// ============================================================================
//  LIB: Strings/hex (tiny, unique)
// ============================================================================

library SH_Strings {
    bytes16 private constant _HEX = "0123456789abcdef";

    function toString(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 t = v;
        uint256 n;
        while (t != 0) { n++; t /= 10; }
        bytes memory b = new bytes(n);
        while (v != 0) {
            n -= 1;
            b[n] = bytes1(uint8(48 + (v % 10)));
            v /= 10;
        }
        return string(b);
    }

    function toHex(bytes32 data) internal pure returns (string memory) {
        bytes memory out = new bytes(66);
        out[0] = "0";
        out[1] = "x";
        for (uint256 i; i < 32; ) {
            uint8 a = uint8(data[i] >> 4);
            uint8 b = uint8(data[i] & 0x0f);
            out[2 + 2*i] = _HEX[a];
            out[3 + 2*i] = _HEX[b];
            unchecked { ++i; }
        }
        return string(out);
    }
}

// ============================================================================
//  CORE CONTRACT
// ============================================================================

contract SeaH00rse {
    using SH_Strings for uint256;
    using SH_Strings for bytes32;

    // ------------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------------

    event AdminProposed(address indexed previousAdmin, address indexed proposedAdmin, uint64 atBlock);
    event AdminAccepted(address indexed previousAdmin, address indexed newAdmin, uint64 atBlock);
    event RiskCouncilChanged(address indexed previousCouncil, address indexed newCouncil, uint64 atBlock);
    event RelayerSeal(bool sealed, uint64 atBlock);
    event PauseToggled(bool paused, uint64 atBlock);

    event AdapterRegistered(uint32 indexed chainId, bytes32 indexed adapterTag, address adapter, uint64 atBlock);
    event VenueRegistered(bytes32 indexed venueId, bytes32 indexed chainVenueTag, uint64 atBlock);
    event VenueEnabled(bytes32 indexed venueId, bool enabled, uint64 atBlock);

    event IntentPosted(
        uint256 indexed intentId,
        address indexed maker,
        bytes32 indexed intentHash,
        uint32 srcChain,
        uint32 dstChain,
        uint64 expiryBlock,
        uint128 maxFeeWei
    );

    event IntentFlagged(uint256 indexed intentId, bytes32 indexed reason, uint64 atBlock);
    event IntentUnflagged(uint256 indexed intentId, uint64 atBlock);

    event IntentFilled(
        uint256 indexed intentId,
        bytes32 indexed fillHash,
        bytes32 indexed venueId,
        uint64 fillBlock,
        uint128 feePaidWei
    );

    event FeeDeposited(uint256 indexed intentId, address indexed from, uint256 amountWei);
    event FeeWithdrawn(uint256 indexed intentId, address indexed to, uint256 amountWei);
    event ProtocolWithdrawn(address indexed to, uint256 amountWei, uint64 atBlock);

    // ------------------------------------------------------------------------
    // Constants (unique)
    // ------------------------------------------------------------------------

    uint256 public constant SH_REVISION = 1;
    uint256 public constant SH_MAX_INTENTS = 120_000;
    uint256 public constant SH_MAX_BATCH = 72;
    uint256 public constant SH_MAX_VENUES = 4096;
    uint256 public constant SH_MAX_ADAPTERS = 512;
    uint256 public constant SH_FLAG_WINDOW_BLOCKS = 1_111;
    uint256 public constant SH_MIN_EXPIRY_DELTA = 24;
    uint256 public constant SH_MAX_EXPIRY_DELTA = 200_000;
    uint256 public constant SH_WITHDRAW_CAP_WEI = 4 ether;
    uint256 public constant SH_FEE_BUCKET_GRANULARITY = 1 gwei;
    uint32 public constant SH_CHAIN_EVM = 1;
    uint32 public constant SH_CHAIN_SOLANA = 501;
    uint32 public constant SH_CHAIN_SUI = 784;

    bytes32 public constant SH_DOMAIN = keccak256("SeaH00rse.Domain.CrossChain.Intent.v1");
    bytes32 public constant SH_BOOT_SALT = 0xbf5467ea4922d65fe49cedae804801d41e5d016d84e0b7e958e7b5e68d05f59c;

    // ------------------------------------------------------------------------
    // Roles (immutable as requested)
    // ------------------------------------------------------------------------

    address public immutable relayer;
    address public immutable bootAdmin;
    uint256 public immutable genesisBlock;

    // ------------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------------

    address public admin;
    address public pendingAdmin;
    address public riskCouncil;

    bool public paused;
    bool public relayerSealed;

    uint256 private _lock;
    uint256 private _nextIntentId;
    uint256 private _protocolWithdrawnWei;

    struct AdapterInfo {
        address adapter;
        bytes32 tag;
        uint64 registeredAt;
        bool exists;
    }

    struct VenueInfo {
        bytes32 chainVenueTag;
        uint64 registeredAt;
        bool enabled;
        bool exists;
    }

    struct Intent {
        address maker;
        bytes32 intentHash;
        bytes32 venueHint;
        uint32 srcChain;
        uint32 dstChain;
        uint64 postedAtBlock;
        uint64 expiryBlock;
        uint128 maxFeeWei;
        bool filled;
        bool flagged;
    }

    struct Fill {
        bytes32 fillHash;
        bytes32 venueId;
        uint64 fillBlock;
        uint128 feePaidWei;
        bool exists;
    }

    mapping(uint32 => AdapterInfo) private _adapters; // chainId => adapter
    uint32[] private _adapterChainIds;

    mapping(bytes32 => VenueInfo) private _venues; // venueId => info
    bytes32[] private _venueIds;

    mapping(uint256 => Intent) private _intents;
    mapping(uint256 => Fill) private _fills;
    mapping(uint256 => uint256) private _escrowedFeeWei; // intentId => fee escrow balance
    mapping(address => uint256) private _makerIntentCount;

    mapping(uint256 => uint64) private _flaggedAt;
    mapping(uint256 => bytes32) private _flagReason;

    // ------------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------------

    modifier nonReentrant() {
        if (_lock != 0) revert SH__Reentrancy();
        _lock = 1;
        _;
        _lock = 0;
    }

    modifier whenNotPaused() {
        if (paused) revert SH__Paused();
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert SH__NotAdmin();
        _;
    }

    modifier onlyRiskCouncil() {
