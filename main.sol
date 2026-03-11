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
        if (msg.sender != riskCouncil) revert SH__NotRiskCouncil();
        _;
    }

    modifier onlyRelayer() {
        if (msg.sender != relayer) revert SH__NotRelayer();
        _;
    }

    // ------------------------------------------------------------------------
    // Constructor (random addresses, EIP-55)
    // ------------------------------------------------------------------------

    constructor() {
        bootAdmin = 0xA17B4eC9D2F3a65B1c0dE8F7A9bC3D4E5F607182;
        admin = bootAdmin;
        riskCouncil = 0x4cD8F1aB0E26c9D3F7bA51cE9D0f2A6B8C3e5D71;
        relayer = 0x7E3aB9C0dF12E456aBcD7890Ef12aB34C56dE789;
        genesisBlock = block.number;
        _nextIntentId = 1;
    }

    // ------------------------------------------------------------------------
    // Admin / governance
    // ------------------------------------------------------------------------

    function proposeAdmin(address next) external onlyAdmin {
        if (next == address(0)) revert SH__BadAddress();
        pendingAdmin = next;
        emit AdminProposed(admin, next, uint64(block.number));
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert SH__NotPendingAdmin();
        address prev = admin;
        admin = pendingAdmin;
        pendingAdmin = address(0);
        emit AdminAccepted(prev, admin, uint64(block.number));
    }

    function setRiskCouncil(address next) external onlyAdmin {
        if (next == address(0)) revert SH__BadAddress();
        address prev = riskCouncil;
        riskCouncil = next;
        emit RiskCouncilChanged(prev, next, uint64(block.number));
    }

    function togglePause() external onlyAdmin {
        paused = !paused;
        emit PauseToggled(paused, uint64(block.number));
    }

    function sealRelayer(bool sealed) external onlyAdmin {
        relayerSealed = sealed;
        emit RelayerSeal(sealed, uint64(block.number));
    }

    // ------------------------------------------------------------------------
    // Adapter / venue registry (offchain execution targets)
    // ------------------------------------------------------------------------

    function registerAdapter(uint32 chainId, bytes32 adapterTag, address adapter) external onlyAdmin nonReentrant {
        if (adapter == address(0)) revert SH__BadAddress();
        if (chainId == 0) revert SH__BadChain();
        AdapterInfo storage a = _adapters[chainId];
        if (!a.exists) {
            if (_adapterChainIds.length >= SH_MAX_ADAPTERS) revert SH__TooLarge();
            _adapterChainIds.push(chainId);
            a.exists = true;
        }
        a.adapter = adapter;
        a.tag = adapterTag;
        a.registeredAt = uint64(block.number);
        emit AdapterRegistered(chainId, adapterTag, adapter, uint64(block.number));
    }

    function adapterOf(uint32 chainId) external view returns (address adapter, bytes32 tag, uint64 registeredAt, bool exists) {
        AdapterInfo storage a = _adapters[chainId];
        return (a.adapter, a.tag, a.registeredAt, a.exists);
    }

    function adapterChainIds() external view returns (uint32[] memory) {
        return _adapterChainIds;
    }

    function registerVenue(bytes32 venueId, bytes32 chainVenueTag) external onlyAdmin nonReentrant {
        if (venueId == bytes32(0)) revert SH__BadVenue();
        VenueInfo storage v = _venues[venueId];
        if (!v.exists) {
            if (_venueIds.length >= SH_MAX_VENUES) revert SH__TooLarge();
            _venueIds.push(venueId);
            v.exists = true;
            v.registeredAt = uint64(block.number);
        }
        v.chainVenueTag = chainVenueTag;
        v.enabled = true;
        emit VenueRegistered(venueId, chainVenueTag, uint64(block.number));
        emit VenueEnabled(venueId, true, uint64(block.number));
    }

    function setVenueEnabled(bytes32 venueId, bool enabled) external onlyAdmin {
        VenueInfo storage v = _venues[venueId];
        if (!v.exists) revert SH__Missing();
        v.enabled = enabled;
        emit VenueEnabled(venueId, enabled, uint64(block.number));
    }

    function venueOf(bytes32 venueId) external view returns (bytes32 chainVenueTag, uint64 registeredAt, bool enabled, bool exists) {
        VenueInfo storage v = _venues[venueId];
        return (v.chainVenueTag, v.registeredAt, v.enabled, v.exists);
    }

    function venueIds() external view returns (bytes32[] memory) {
        return _venueIds;
    }

    // ------------------------------------------------------------------------
    // Intent posting + fee escrow
    // ------------------------------------------------------------------------

    function postIntent(
        bytes32 intentHash,
        uint32 srcChain,
        uint32 dstChain,
        uint64 expiryBlock,
        uint128 maxFeeWei,
        bytes32 venueHint
    ) external payable whenNotPaused nonReentrant returns (uint256 intentId) {
        if (intentHash == bytes32(0)) revert SH__BadIntent();
        if (srcChain == 0 || dstChain == 0) revert SH__BadChain();
        if (srcChain == dstChain) revert SH__BadChain();
        uint64 nowB = uint64(block.number);
        if (expiryBlock <= nowB + SH_MIN_EXPIRY_DELTA) revert SH__BadWindow();
        if (expiryBlock > nowB + SH_MAX_EXPIRY_DELTA) revert SH__BadWindow();
        if (_nextIntentId > SH_MAX_INTENTS) revert SH__TooLarge();
        intentId = _nextIntentId;
        unchecked { ++_nextIntentId; }

        Intent storage it = _intents[intentId];
        it.maker = msg.sender;
        it.intentHash = intentHash;
        it.venueHint = venueHint;
        it.srcChain = srcChain;
        it.dstChain = dstChain;
        it.postedAtBlock = nowB;
        it.expiryBlock = expiryBlock;
        it.maxFeeWei = maxFeeWei;
        it.filled = false;
        it.flagged = false;

        unchecked { _makerIntentCount[msg.sender] += 1; }

        if (msg.value != 0) {
            if (msg.value % SH_FEE_BUCKET_GRANULARITY != 0) revert SH__BadAmount();
            _escrowedFeeWei[intentId] = msg.value;
            emit FeeDeposited(intentId, msg.sender, msg.value);
        }

        emit IntentPosted(intentId, msg.sender, intentHash, srcChain, dstChain, expiryBlock, maxFeeWei);
    }

    function depositFee(uint256 intentId) external payable whenNotPaused nonReentrant {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) revert SH__Missing();
        if (msg.value == 0) revert SH__BadAmount();
        if (msg.value % SH_FEE_BUCKET_GRANULARITY != 0) revert SH__BadAmount();
        _escrowedFeeWei[intentId] += msg.value;
        emit FeeDeposited(intentId, msg.sender, msg.value);
    }

    function withdrawFee(uint256 intentId, address to, uint256 amountWei) external nonReentrant {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) revert SH__Missing();
        if (msg.sender != it.maker) revert SH__NotAdmin();
        if (to == address(0)) revert SH__BadAddress();
        if (amountWei == 0) revert SH__BadAmount();
        if (_escrowedFeeWei[intentId] < amountWei) revert SH__BadAmount();
        _escrowedFeeWei[intentId] -= amountWei;
        (bool ok,) = to.call{value: amountWei}("");
        if (!ok) revert SH__TransferFailed();
        emit FeeWithdrawn(intentId, to, amountWei);
    }

    function escrowedFee(uint256 intentId) external view returns (uint256) {
        return _escrowedFeeWei[intentId];
    }

    function makerIntentCount(address maker) external view returns (uint256) {
        return _makerIntentCount[maker];
    }

    // ------------------------------------------------------------------------
    // Flags (risk council)
    // ------------------------------------------------------------------------

    function flagIntent(uint256 intentId, bytes32 reason) external onlyRiskCouncil nonReentrant {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) revert SH__Missing();
        if (it.filled) revert SH__Already();
        if (it.flagged) revert SH__Already();
        it.flagged = true;
        _flaggedAt[intentId] = uint64(block.number);
        _flagReason[intentId] = reason;
        emit IntentFlagged(intentId, reason, uint64(block.number));
    }

    function unflagIntent(uint256 intentId) external onlyRiskCouncil nonReentrant {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) revert SH__Missing();
        if (!it.flagged) revert SH__Missing();
        it.flagged = false;
        _flaggedAt[intentId] = 0;
        _flagReason[intentId] = bytes32(0);
        emit IntentUnflagged(intentId, uint64(block.number));
    }

    function flagInfo(uint256 intentId) external view returns (bool flagged, uint64 flaggedAt, bytes32 reason) {
        flagged = _intents[intentId].flagged;
        flaggedAt = _flaggedAt[intentId];
        reason = _flagReason[intentId];
    }

    // ------------------------------------------------------------------------
    // Relayer attestations
    // ------------------------------------------------------------------------

    function attestFill(
        uint256 intentId,
        bytes32 fillHash,
        bytes32 venueId,
        uint128 feePaidWei
    ) external onlyRelayer whenNotPaused nonReentrant {
        if (relayerSealed) revert SH__Seal();
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) revert SH__Missing();
        if (it.filled) revert SH__Already();
        if (it.flagged) revert SH__Flagged();
        if (fillHash == bytes32(0)) revert SH__BadBytes();
        VenueInfo storage v = _venues[venueId];
        if (!v.exists || !v.enabled) revert SH__BadVenue();
        if (block.number > it.expiryBlock) revert SH__Expired();
        if (feePaidWei > it.maxFeeWei) revert SH__BadAmount();

        it.filled = true;
        Fill storage f = _fills[intentId];
        f.fillHash = fillHash;
        f.venueId = venueId;
        f.fillBlock = uint64(block.number);
        f.feePaidWei = feePaidWei;
        f.exists = true;

        if (feePaidWei != 0) {
            uint256 bal = _escrowedFeeWei[intentId];
            if (bal < feePaidWei) revert SH__BadAmount();
            _escrowedFeeWei[intentId] = bal - feePaidWei;
            _protocolWithdrawnWei += feePaidWei;
        }

        emit IntentFilled(intentId, fillHash, venueId, uint64(block.number), feePaidWei);
    }

    // ------------------------------------------------------------------------
    // Getters
    // ------------------------------------------------------------------------

    function nextIntentId() external view returns (uint256) {
        return _nextIntentId;
    }

    function intentOf(uint256 intentId) external view returns (
        address maker,
        bytes32 intentHash,
        bytes32 venueHint,
        uint32 srcChain,
        uint32 dstChain,
        uint64 postedAtBlock,
        uint64 expiryBlock,
        uint128 maxFeeWei,
        bool filled,
        bool flagged
    ) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) revert SH__Missing();
        return (
            it.maker,
            it.intentHash,
            it.venueHint,
            it.srcChain,
            it.dstChain,
            it.postedAtBlock,
            it.expiryBlock,
            it.maxFeeWei,
            it.filled,
            it.flagged
        );
    }

    function fillOf(uint256 intentId) external view returns (bytes32 fillHash, bytes32 venueId, uint64 fillBlock, uint128 feePaidWei, bool exists) {
        Fill storage f = _fills[intentId];
        return (f.fillHash, f.venueId, f.fillBlock, f.feePaidWei, f.exists);
    }

    function isExpired(uint256 intentId) external view returns (bool) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) return false;
        return block.number > it.expiryBlock;
    }

    function blocksUntilExpiry(uint256 intentId) external view returns (uint256) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) return 0;
        return block.number >= it.expiryBlock ? 0 : it.expiryBlock - uint64(block.number);
    }

    function domainSeparator() external view returns (bytes32) {
        return keccak256(abi.encodePacked(SH_DOMAIN, SH_BOOT_SALT, block.chainid, address(this)));
    }

    function contractLabel() external pure returns (string memory) {
        return "SeaH00rse";
    }

    function platformLabel() external pure returns (string memory) {
        return "cross-chain trading platform (Solana/Sui/EVM)";
    }

    function quote() external pure returns (string memory) {
        return "Ride the currents.";
    }

    // ------------------------------------------------------------------------
    // Protocol withdraw (cap)
    // ------------------------------------------------------------------------

    function protocolWithdrawnWei() external view returns (uint256) {
        return _protocolWithdrawnWei;
    }

    function remainingProtocolWithdrawCap() external view returns (uint256) {
        return _protocolWithdrawnWei >= SH_WITHDRAW_CAP_WEI ? 0 : SH_WITHDRAW_CAP_WEI - _protocolWithdrawnWei;
    }

    function withdrawProtocol(address to, uint256 amountWei) external onlyAdmin nonReentrant {
        if (to == address(0)) revert SH__BadAddress();
        if (amountWei == 0) revert SH__BadAmount();
        if (_protocolWithdrawnWei + amountWei > SH_WITHDRAW_CAP_WEI) revert SH__BadAmount();
        _protocolWithdrawnWei += amountWei;
        (bool ok,) = to.call{value: amountWei}("");
        if (!ok) revert SH__TransferFailed();
        emit ProtocolWithdrawn(to, amountWei, uint64(block.number));
    }

    // ------------------------------------------------------------------------
    // Batch helpers
    // ------------------------------------------------------------------------

    function intentDigest(uint256 intentId) external view returns (bytes32) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) revert SH__Missing();
        return keccak256(abi.encodePacked(
            intentId,
            it.maker,
            it.intentHash,
            it.venueHint,
            it.srcChain,
            it.dstChain,
            it.postedAtBlock,
            it.expiryBlock,
            it.maxFeeWei,
            it.filled,
            it.flagged
        ));
    }

    function intentDigests(uint256[] calldata intentIds) external view returns (bytes32[] memory digests) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        digests = new bytes32[](n);
        for (uint256 i; i < n; ) {
            uint256 id = intentIds[i];
            Intent storage it = _intents[id];
            if (it.maker != address(0)) {
                digests[i] = keccak256(abi.encodePacked(
                    id, it.maker, it.intentHash, it.venueHint, it.srcChain, it.dstChain, it.postedAtBlock, it.expiryBlock, it.maxFeeWei, it.filled, it.flagged
                ));
            }
            unchecked { ++i; }
        }
    }

    function intentsPage(uint256 offset, uint256 limit) external view returns (uint256[] memory ids) {
        if (limit > SH_MAX_BATCH) revert SH__TooLarge();
        uint256 nextId = _nextIntentId;
        if (offset == 0) offset = 1;
        if (offset >= nextId) return new uint256[](0);
        uint256 end = offset + limit;
        if (end > nextId) end = nextId;
        uint256 n = end - offset;
        ids = new uint256[](n);
        for (uint256 i; i < n; ) {
            ids[i] = offset + i;
            unchecked { ++i; }
        }
    }

    // ------------------------------------------------------------------------
    // Pure helpers (distinct; used by UI/offchain)
    // ------------------------------------------------------------------------

    function hashIntentParts(bytes32 a, bytes32 b, bytes32 c) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b, c));
    }

    function hashVenue(bytes32 chainVenueTag, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(chainVenueTag, salt));
    }

    function chainName(uint32 chainId) external pure returns (string memory) {
        if (chainId == SH_CHAIN_EVM) return "EVM";
        if (chainId == SH_CHAIN_SOLANA) return "SOLANA";
        if (chainId == SH_CHAIN_SUI) return "SUI";
        return string(abi.encodePacked("CHAIN_", uint256(chainId).toString()));
    }

    function bytes32ToHex(bytes32 v) external pure returns (string memory) {
        return v.toHex();
    }

    // ------------------------------------------------------------------------
    // Receive (fee deposits)
    // ------------------------------------------------------------------------

    receive() external payable {}

    // ------------------------------------------------------------------------
    // Extended read API (batch + pagination + stats)
    // ------------------------------------------------------------------------

    struct IntentView {
        uint256 intentId;
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
        uint256 escrowedFeeWei;
        bytes32 fillHash;
        bytes32 fillVenueId;
        uint64 fillBlock;
        uint128 feePaidWei;
        bool fillExists;
    }

    function intentExists(uint256 intentId) public view returns (bool) {
        return _intents[intentId].maker != address(0);
    }

    function intentMaker(uint256 intentId) external view returns (address) {
        return _intents[intentId].maker;
    }

    function intentHash(uint256 intentId) external view returns (bytes32) {
        return _intents[intentId].intentHash;
    }

    function intentVenueHint(uint256 intentId) external view returns (bytes32) {
        return _intents[intentId].venueHint;
    }

    function intentChains(uint256 intentId) external view returns (uint32 src, uint32 dst) {
        Intent storage it = _intents[intentId];
        return (it.srcChain, it.dstChain);
    }

    function intentTiming(uint256 intentId) external view returns (uint64 postedAtBlock, uint64 expiryBlock) {
        Intent storage it = _intents[intentId];
        return (it.postedAtBlock, it.expiryBlock);
    }

    function intentState(uint256 intentId) external view returns (bool filled, bool flagged) {
        Intent storage it = _intents[intentId];
        return (it.filled, it.flagged);
    }

    function fillExists(uint256 intentId) external view returns (bool) {
        return _fills[intentId].exists;
    }

    function fillVenue(uint256 intentId) external view returns (bytes32) {
        return _fills[intentId].venueId;
    }

    function fillHash(uint256 intentId) external view returns (bytes32) {
        return _fills[intentId].fillHash;
    }

    function fillTiming(uint256 intentId) external view returns (uint64 fillBlock) {
        return _fills[intentId].fillBlock;
    }

    function fillFeePaid(uint256 intentId) external view returns (uint128) {
        return _fills[intentId].feePaidWei;
    }

    function getIntentView(uint256 intentId) external view returns (IntentView memory v) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) revert SH__Missing();
        Fill storage f = _fills[intentId];
        v.intentId = intentId;
        v.maker = it.maker;
        v.intentHash = it.intentHash;
        v.venueHint = it.venueHint;
        v.srcChain = it.srcChain;
        v.dstChain = it.dstChain;
        v.postedAtBlock = it.postedAtBlock;
        v.expiryBlock = it.expiryBlock;
        v.maxFeeWei = it.maxFeeWei;
        v.filled = it.filled;
        v.flagged = it.flagged;
        v.escrowedFeeWei = _escrowedFeeWei[intentId];
        v.fillHash = f.fillHash;
        v.fillVenueId = f.venueId;
        v.fillBlock = f.fillBlock;
        v.feePaidWei = f.feePaidWei;
        v.fillExists = f.exists;
    }

    function getIntentViews(uint256[] calldata intentIds) external view returns (IntentView[] memory views) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        views = new IntentView[](n);
        for (uint256 i; i < n; ) {
            uint256 id = intentIds[i];
            Intent storage it = _intents[id];
            if (it.maker != address(0)) {
                Fill storage f = _fills[id];
                views[i] = IntentView({
                    intentId: id,
                    maker: it.maker,
                    intentHash: it.intentHash,
                    venueHint: it.venueHint,
                    srcChain: it.srcChain,
                    dstChain: it.dstChain,
                    postedAtBlock: it.postedAtBlock,
                    expiryBlock: it.expiryBlock,
                    maxFeeWei: it.maxFeeWei,
                    filled: it.filled,
                    flagged: it.flagged,
                    escrowedFeeWei: _escrowedFeeWei[id],
                    fillHash: f.fillHash,
                    fillVenueId: f.venueId,
                    fillBlock: f.fillBlock,
                    feePaidWei: f.feePaidWei,
                    fillExists: f.exists
                });
            }
            unchecked { ++i; }
        }
    }

    function intentIdsReverse(uint256 offset, uint256 limit) external view returns (uint256[] memory ids) {
        if (limit > SH_MAX_BATCH) revert SH__TooLarge();
        uint256 nextId = _nextIntentId;
        if (nextId <= 1) return new uint256[](0);
        uint256 start = nextId - 1;
        if (offset > start) return new uint256[](0);
        start = start - offset;
        uint256 n = limit;
        if (start + 1 < n) n = start + 1;
        ids = new uint256[](n);
        for (uint256 i; i < n; ) {
            ids[i] = start - i;
            unchecked { ++i; }
        }
    }

    function countVenues() external view returns (uint256) {
        return _venueIds.length;
    }

    function countAdapters() external view returns (uint256) {
        return _adapterChainIds.length;
    }

    function venueIdsPage(uint256 offset, uint256 limit) external view returns (bytes32[] memory ids) {
        if (limit == 0) revert SH__BadAmount();
        uint256 nAll = _venueIds.length;
        if (offset >= nAll) return new bytes32[](0);
        uint256 end = offset + limit;
        if (end > nAll) end = nAll;
        uint256 n = end - offset;
        ids = new bytes32[](n);
        for (uint256 i; i < n; ) {
            ids[i] = _venueIds[offset + i];
            unchecked { ++i; }
        }
    }

    function adapterChainIdsPage(uint256 offset, uint256 limit) external view returns (uint32[] memory ids) {
        if (limit == 0) revert SH__BadAmount();
        uint256 nAll = _adapterChainIds.length;
        if (offset >= nAll) return new uint32[](0);
        uint256 end = offset + limit;
        if (end > nAll) end = nAll;
        uint256 n = end - offset;
        ids = new uint32[](n);
        for (uint256 i; i < n; ) {
            ids[i] = _adapterChainIds[offset + i];
            unchecked { ++i; }
        }
    }

    function isVenueEnabled(bytes32 venueId) external view returns (bool) {
        VenueInfo storage v = _venues[venueId];
        return v.exists && v.enabled;
    }

    function venueRegisteredAt(bytes32 venueId) external view returns (uint64) {
        return _venues[venueId].registeredAt;
    }

    function venueTag(bytes32 venueId) external view returns (bytes32) {
        return _venues[venueId].chainVenueTag;
    }

    function adapterRegisteredAt(uint32 chainId) external view returns (uint64) {
        return _adapters[chainId].registeredAt;
    }

    function adapterTag(uint32 chainId) external view returns (bytes32) {
        return _adapters[chainId].tag;
    }

    function adapterExists(uint32 chainId) external view returns (bool) {
        return _adapters[chainId].exists;
    }

    function adapterAddress(uint32 chainId) external view returns (address) {
        return _adapters[chainId].adapter;
    }

    function config() external pure returns (
        uint256 revision,
        uint256 maxIntents,
        uint256 maxBatch,
        uint256 maxVenues,
        uint256 maxAdapters,
        uint256 flagWindowBlocks,
        uint256 minExpiryDelta,
        uint256 maxExpiryDelta,
        uint256 withdrawCapWei,
        uint256 feeBucketGranularity
    ) {
        return (
            SH_REVISION,
            SH_MAX_INTENTS,
            SH_MAX_BATCH,
            SH_MAX_VENUES,
            SH_MAX_ADAPTERS,
            SH_FLAG_WINDOW_BLOCKS,
            SH_MIN_EXPIRY_DELTA,
            SH_MAX_EXPIRY_DELTA,
            SH_WITHDRAW_CAP_WEI,
            SH_FEE_BUCKET_GRANULARITY
        );
    }

    function roleAddresses() external view returns (address admin_, address pendingAdmin_, address riskCouncil_, address relayer_) {
        return (admin, pendingAdmin, riskCouncil, relayer);
    }

    function meta() external view returns (bytes32 domain, bytes32 salt, uint256 chainId, address self, uint256 genesisBlock_, uint256 nextIntentId_) {
        return (SH_DOMAIN, SH_BOOT_SALT, block.chainid, address(this), genesisBlock, _nextIntentId);
    }

    function blockMeta() external view returns (uint256 chainId, uint256 number, uint256 timestamp) {
        return (block.chainid, block.number, block.timestamp);
    }

    function pausedState() external view returns (bool paused_, bool relayerSealed_) {
        return (paused, relayerSealed);
    }

    // ------------------------------------------------------------------------
    // Intent filtering (views)
    // ------------------------------------------------------------------------

    function isFillable(uint256 intentId) external view returns (bool) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) return false;
        if (it.filled || it.flagged) return false;
        if (block.number > it.expiryBlock) return false;
        return true;
    }

    function isFlagWithinWindow(uint256 intentId) external view returns (bool) {
        uint64 at = _flaggedAt[intentId];
        if (at == 0) return false;
        return block.number <= uint256(at) + SH_FLAG_WINDOW_BLOCKS;
    }

    function intentFeeHeadroom(uint256 intentId) external view returns (uint256 headroomWei) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) return 0;
        uint256 escrow = _escrowedFeeWei[intentId];
        if (escrow >= it.maxFeeWei) return escrow - it.maxFeeWei;
        return 0;
    }

    function intentCanPay(uint256 intentId, uint128 feeWei) external view returns (bool) {
        return _escrowedFeeWei[intentId] >= feeWei;
    }

    function intentSummary(uint256 intentId) external view returns (
        bool exists,
        bool filled,
        bool flagged,
        bool expired_,
        uint256 blocksLeft
    ) {
        Intent storage it = _intents[intentId];
        exists = it.maker != address(0);
        if (!exists) return (false, false, false, false, 0);
        filled = it.filled;
        flagged = it.flagged;
        expired_ = block.number > it.expiryBlock;
        blocksLeft = block.number >= it.expiryBlock ? 0 : it.expiryBlock - uint64(block.number);
    }

    function intentSummaries(uint256[] calldata intentIds) external view returns (
        bool[] memory exists,
        bool[] memory filled,
        bool[] memory flagged,
        bool[] memory expired_,
        uint256[] memory blocksLeft
    ) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        exists = new bool[](n);
        filled = new bool[](n);
        flagged = new bool[](n);
        expired_ = new bool[](n);
        blocksLeft = new uint256[](n);
        for (uint256 i; i < n; ) {
            uint256 id = intentIds[i];
            Intent storage it = _intents[id];
            exists[i] = it.maker != address(0);
            if (exists[i]) {
                filled[i] = it.filled;
                flagged[i] = it.flagged;
                expired_[i] = block.number > it.expiryBlock;
                blocksLeft[i] = block.number >= it.expiryBlock ? 0 : it.expiryBlock - uint64(block.number);
            }
            unchecked { ++i; }
        }
    }

    function findFirstFillable(uint256 fromId, uint256 toId) external view returns (uint256 intentId, bool found) {
        if (fromId == 0) fromId = 1;
        if (toId >= _nextIntentId) toId = _nextIntentId - 1;
        if (fromId > toId) return (0, false);
        for (uint256 id = fromId; id <= toId; ) {
            Intent storage it = _intents[id];
            if (it.maker != address(0) && !it.filled && !it.flagged && block.number <= it.expiryBlock) {
                return (id, true);
            }
            unchecked { ++id; }
        }
        return (0, false);
    }

    function countFillable(uint256 fromId, uint256 toId) external view returns (uint256 count) {
        if (fromId == 0) fromId = 1;
        if (toId >= _nextIntentId) toId = _nextIntentId - 1;
        if (fromId > toId) return 0;
        for (uint256 id = fromId; id <= toId; ) {
            Intent storage it = _intents[id];
            if (it.maker != address(0) && !it.filled && !it.flagged && block.number <= it.expiryBlock) {
                unchecked { ++count; }
            }
            unchecked { ++id; }
        }
    }

    function fillableIds(uint256 fromId, uint256 limit) external view returns (uint256[] memory ids) {
        if (limit > SH_MAX_BATCH) revert SH__TooLarge();
        if (fromId == 0) fromId = 1;
        uint256[] memory temp = new uint256[](limit);
        uint256 found;
        for (uint256 id = fromId; id < _nextIntentId && found < limit; ) {
            Intent storage it = _intents[id];
            if (it.maker != address(0) && !it.filled && !it.flagged && block.number <= it.expiryBlock) {
                temp[found] = id;
                unchecked { ++found; }
            }
            unchecked { ++id; }
        }
        ids = new uint256[](found);
        for (uint256 i; i < found; ) {
            ids[i] = temp[i];
            unchecked { ++i; }
        }
    }

    // ------------------------------------------------------------------------
    // Count aggregations (O(n) views)
    // ------------------------------------------------------------------------

    function counts() external view returns (uint256 total, uint256 filledCount, uint256 flaggedCount, uint256 expiredCount) {
        uint256 nextId = _nextIntentId;
        total = nextId <= 1 ? 0 : nextId - 1;
        for (uint256 id = 1; id < nextId; ) {
            Intent storage it = _intents[id];
            if (it.maker != address(0)) {
                if (it.filled) unchecked { ++filledCount; }
                if (it.flagged) unchecked { ++flaggedCount; }
                if (block.number > it.expiryBlock) unchecked { ++expiredCount; }
            }
            unchecked { ++id; }
        }
    }

    function totalEscrowed() external view returns (uint256 totalWei) {
        uint256 nextId = _nextIntentId;
        for (uint256 id = 1; id < nextId; ) {
            totalWei += _escrowedFeeWei[id];
            unchecked { ++id; }
        }
    }

    function totalEscrowedInRange(uint256 fromId, uint256 toId) external view returns (uint256 totalWei) {
        if (fromId == 0) fromId = 1;
        if (toId >= _nextIntentId) toId = _nextIntentId - 1;
        if (fromId > toId) return 0;
        for (uint256 id = fromId; id <= toId; ) {
            totalWei += _escrowedFeeWei[id];
            unchecked { ++id; }
        }
    }

    // ------------------------------------------------------------------------
    // More pure helpers (cross-chain tags)
    // ------------------------------------------------------------------------

    function computeVenueId(bytes32 chainVenueTag, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("VENUE", chainVenueTag, salt));
    }

    function computeAdapterTag(string calldata name, uint32 chainId) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("ADAPTER", name, chainId));
    }

    function computeIntentHash(
        bytes32 makerSalt,
        uint32 srcChain,
        uint32 dstChain,
        bytes32 srcAsset,
        bytes32 dstAsset,
        uint128 srcAmount,
        uint128 minDstAmount
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "INTENT",
            makerSalt,
            srcChain,
            dstChain,
            srcAsset,
            dstAsset,
            srcAmount,
            minDstAmount
        ));
    }

    function computeFillHash(bytes32 intentHash, bytes32 executorSig, bytes32 outcomeDigest) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("FILL", intentHash, executorSig, outcomeDigest));
    }

    function min(uint256 a, uint256 b) external pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) external pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 v, uint256 lo, uint256 hi) external pure returns (uint256) {
        if (v < lo) return lo;
        if (v > hi) return hi;
        return v;
    }

    // ------------------------------------------------------------------------
    // Convenience: expose common chain IDs
    // ------------------------------------------------------------------------

    function chainIdEvm() external pure returns (uint32) { return SH_CHAIN_EVM; }
    function chainIdSolana() external pure returns (uint32) { return SH_CHAIN_SOLANA; }
    function chainIdSui() external pure returns (uint32) { return SH_CHAIN_SUI; }

    // ------------------------------------------------------------------------
    // Versioning and names
    // ------------------------------------------------------------------------

    function revision() external pure returns (uint256) { return SH_REVISION; }
    function domain() external pure returns (bytes32) { return SH_DOMAIN; }
    function bootSalt() external pure returns (bytes32) { return SH_BOOT_SALT; }
    function name() external pure returns (string memory) { return "SeaH00rse Cross-Chain Intent Ledger"; }
    function symbol() external pure returns (string memory) { return "SH00"; }

    function tagline() external pure returns (string memory) {
        return "Route quotes and fills across Solana/Sui/EVM venues.";
    }

    function uiHintColor() external pure returns (bytes3) {
        return 0x00d4aa;
    }

    function uiHintAccent() external pure returns (bytes3) {
        return 0xc84ef6;
    }

    // ------------------------------------------------------------------------
    // Guard rails (read-only checks)
    // ------------------------------------------------------------------------

    function validateExpiry(uint64 expiryBlock) external view returns (bool ok, string memory why) {
        uint64 nowB = uint64(block.number);
        if (expiryBlock <= nowB + SH_MIN_EXPIRY_DELTA) return (false, "too_soon");
        if (expiryBlock > nowB + SH_MAX_EXPIRY_DELTA) return (false, "too_far");
        return (true, "ok");
    }

    function validateChains(uint32 srcChain, uint32 dstChain) external pure returns (bool ok, string memory why) {
        if (srcChain == 0 || dstChain == 0) return (false, "zero_chain");
        if (srcChain == dstChain) return (false, "same_chain");
        return (true, "ok");
    }

    function validateVenue(bytes32 venueId) external view returns (bool ok, string memory why) {
        VenueInfo storage v = _venues[venueId];
        if (!v.exists) return (false, "missing");
        if (!v.enabled) return (false, "disabled");
        return (true, "ok");
    }

    function validateIntent(uint256 intentId) external view returns (bool ok, string memory why) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) return (false, "missing");
        if (it.flagged) return (false, "flagged");
        if (it.filled) return (false, "filled");
        if (block.number > it.expiryBlock) return (false, "expired");
        return (true, "ok");
    }

    // ------------------------------------------------------------------------
    // Extra pagination helpers
    // ------------------------------------------------------------------------

    function intentIdRange() external view returns (uint256 minId, uint256 maxId, uint256 nextId) {
        nextId = _nextIntentId;
        if (nextId <= 1) return (0, 0, nextId);
        return (1, nextId - 1, nextId);
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function canWithdrawProtocol(uint256 amountWei) external view returns (bool) {
        if (amountWei == 0) return false;
        return _protocolWithdrawnWei + amountWei <= SH_WITHDRAW_CAP_WEI;
    }

    // ------------------------------------------------------------------------
    // Bulk escrow reads
    // ------------------------------------------------------------------------

    function escrowedFees(uint256[] calldata intentIds) external view returns (uint256[] memory fees) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        fees = new uint256[](n);
        for (uint256 i; i < n; ) {
            fees[i] = _escrowedFeeWei[intentIds[i]];
            unchecked { ++i; }
        }
    }

    function fillHashes(uint256[] calldata intentIds) external view returns (bytes32[] memory hashes) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        hashes = new bytes32[](n);
        for (uint256 i; i < n; ) {
            hashes[i] = _fills[intentIds[i]].fillHash;
            unchecked { ++i; }
        }
    }

    function fillVenues(uint256[] calldata intentIds) external view returns (bytes32[] memory venues) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        venues = new bytes32[](n);
        for (uint256 i; i < n; ) {
            venues[i] = _fills[intentIds[i]].venueId;
            unchecked { ++i; }
        }
    }

    function fillBlocks(uint256[] calldata intentIds) external view returns (uint64[] memory blocks_) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        blocks_ = new uint64[](n);
        for (uint256 i; i < n; ) {
            blocks_[i] = _fills[intentIds[i]].fillBlock;
            unchecked { ++i; }
        }
    }

    function feePaid(uint256[] calldata intentIds) external view returns (uint128[] memory fees_) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        fees_ = new uint128[](n);
        for (uint256 i; i < n; ) {
            fees_[i] = _fills[intentIds[i]].feePaidWei;
            unchecked { ++i; }
        }
    }

    function chainsOf(uint256[] calldata intentIds) external view returns (uint32[] memory src, uint32[] memory dst) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        src = new uint32[](n);
        dst = new uint32[](n);
        for (uint256 i; i < n; ) {
            Intent storage it = _intents[intentIds[i]];
            src[i] = it.srcChain;
            dst[i] = it.dstChain;
            unchecked { ++i; }
        }
    }

    function expiriesOf(uint256[] calldata intentIds) external view returns (uint64[] memory exp) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        exp = new uint64[](n);
        for (uint256 i; i < n; ) {
            exp[i] = _intents[intentIds[i]].expiryBlock;
            unchecked { ++i; }
        }
    }

    function makersOf(uint256[] calldata intentIds) external view returns (address[] memory makers) {
        uint256 n = intentIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        makers = new address[](n);
        for (uint256 i; i < n; ) {
            makers[i] = _intents[intentIds[i]].maker;
            unchecked { ++i; }
        }
    }

    // ------------------------------------------------------------------------
    // “Cross-chain trading platform” themed helpers (UI convenience)
    // ------------------------------------------------------------------------

    function venueDisplay(bytes32 venueId) external view returns (string memory) {
        VenueInfo storage v = _venues[venueId];
        if (!v.exists) return "VENUE_UNKNOWN";
        return string(abi.encodePacked(
            "VENUE_",
            uint256(uint32(uint256(v.chainVenueTag))).toString(),
            "_",
            v.enabled ? "ON" : "OFF"
        ));
    }

    function adapterDisplay(uint32 chainId) external view returns (string memory) {
        AdapterInfo storage a = _adapters[chainId];
        if (!a.exists) return "ADAPTER_NONE";
        return string(abi.encodePacked("ADAPTER_", uint256(chainId).toString()));
    }

    function intentDisplay(uint256 intentId) external view returns (string memory) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) return "INTENT_NONE";
        string memory s = chainName(it.srcChain);
        string memory d = chainName(it.dstChain);
        return string(abi.encodePacked("INTENT_", intentId.toString(), "_", s, "_TO_", d));
    }

    function intentHex(uint256 intentId) external view returns (string memory) {
        Intent storage it = _intents[intentId];
        if (it.maker == address(0)) return "0x";
        return it.intentHash.toHex();
    }

    function fillHex(uint256 intentId) external view returns (string memory) {
        Fill storage f = _fills[intentId];
        if (!f.exists) return "0x";
        return f.fillHash.toHex();
    }

    function venueHex(bytes32 venueId) external pure returns (string memory) {
        return venueId.toHex();
    }

    function computeRouteKey(uint32 srcChain, uint32 dstChain, bytes32 venueHint) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("ROUTE", srcChain, dstChain, venueHint));
    }

    function computeQuoteKey(bytes32 intentHash, bytes32 venueId, uint64 expiryBlock) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("QUOTE", intentHash, venueId, expiryBlock));
    }

    function computeBridgeTag(uint32 srcChain, uint32 dstChain, bytes32 bridgeName) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("BRIDGE", srcChain, dstChain, bridgeName));
    }

    function computeExecutorTag(address executorAddr, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("EXECUTOR", executorAddr, salt));
    }

    function computeMakerTag(address makerAddr, bytes32 salt) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("MAKER", makerAddr, salt));
    }

    function computeAssetTag(string calldata symbol_, uint8 decimals_) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("ASSET", symbol_, decimals_));
    }

    function computeVenueTag(string calldata name_, uint32 chainId) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("VENUE_TAG", name_, chainId));
    }

    function computeOrderTag(bytes32 intentHash, uint256 nonce) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("ORDER", intentHash, nonce));
    }

    function computeAuditTag(bytes32 fillHash_, bytes32 auditorSalt) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("AUDIT", fillHash_, auditorSalt));
    }

    function computeDisputeTag(uint256 intentId, bytes32 reason, uint64 atBlock) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("DISPUTE", intentId, reason, atBlock));
    }

    function formatUint(uint256 v) external pure returns (string memory) {
        return v.toString();
    }

    function formatChain(uint32 chainId) external pure returns (string memory) {
        return chainName(chainId);
    }

    function formatIntent(uint256 intentId) external view returns (string memory) {
        return intentDisplay(intentId);
    }

    function formatVenue(bytes32 venueId) external view returns (string memory) {
        return venueDisplay(venueId);
    }

    function formatAdapter(uint32 chainId) external view returns (string memory) {
        return adapterDisplay(chainId);
    }

    // ------------------------------------------------------------------------
    // “Keep it different”: extra deterministic constants and helpers
    // ------------------------------------------------------------------------

    bytes32 public constant SH_CROSS_TAG = keccak256("SeaH00rse.CrossChain.Tag.v1");
    bytes32 public constant SH_EXEC_TAG = keccak256("SeaH00rse.Executor.Tag.v1");
    bytes32 public constant SH_RISK_TAG = keccak256("SeaH00rse.Risk.Tag.v1");
    bytes32 public constant SH_ROUTE_TAG = keccak256("SeaH00rse.Route.Tag.v1");

    function crossTag() external pure returns (bytes32) { return SH_CROSS_TAG; }
    function execTag() external pure returns (bytes32) { return SH_EXEC_TAG; }
    function riskTag() external pure returns (bytes32) { return SH_RISK_TAG; }
    function routeTag() external pure returns (bytes32) { return SH_ROUTE_TAG; }

    function mixTag(bytes32 a, bytes32 b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }

    function mixTag3(bytes32 a, bytes32 b, bytes32 c) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b, c));
    }

    function mixTag4(bytes32 a, bytes32 b, bytes32 c, bytes32 d) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b, c, d));
    }

    function asBytes32(uint256 x) external pure returns (bytes32) {
        return bytes32(x);
    }

    function asUint256(bytes32 x) external pure returns (uint256) {
        return uint256(x);
    }

    function asUint32(uint256 x) external pure returns (uint32) {
        return uint32(x);
    }

    function asUint64(uint256 x) external pure returns (uint64) {
        return uint64(x);
    }

    function asUint128(uint256 x) external pure returns (uint128) {
        return uint128(x);
    }

    function asAddress(bytes32 x) external pure returns (address) {
        return address(uint160(uint256(x)));
    }

    function packChains(uint32 srcChain, uint32 dstChain) external pure returns (uint64 packed) {
        packed = (uint64(srcChain) << 32) | uint64(dstChain);
    }

    function unpackChains(uint64 packed) external pure returns (uint32 srcChain, uint32 dstChain) {
        srcChain = uint32(packed >> 32);
        dstChain = uint32(packed);
    }

    function packFee(uint128 a, uint128 b) external pure returns (bytes32) {
        return bytes32((uint256(a) << 128) | uint256(b));
    }

    function unpackFee(bytes32 x) external pure returns (uint128 a, uint128 b) {
        uint256 u = uint256(x);
        a = uint128(u >> 128);
        b = uint128(u);
    }

    function safeBucket(uint256 amountWei) external pure returns (uint256) {
        return amountWei - (amountWei % SH_FEE_BUCKET_GRANULARITY);
    }

    // ------------------------------------------------------------------------
    // More batch registry reads (adapters + venues)
    // ------------------------------------------------------------------------

    struct AdapterView {
        uint32 chainId;
        address adapter;
        bytes32 tag;
        uint64 registeredAt;
        bool exists;
    }

    struct VenueView {
        bytes32 venueId;
        bytes32 chainVenueTag;
        uint64 registeredAt;
        bool enabled;
        bool exists;
    }

    function getAdapterView(uint32 chainId) external view returns (AdapterView memory v) {
        AdapterInfo storage a = _adapters[chainId];
        v.chainId = chainId;
        v.adapter = a.adapter;
        v.tag = a.tag;
        v.registeredAt = a.registeredAt;
        v.exists = a.exists;
    }

    function getAdapterViews(uint32[] calldata chainIds) external view returns (AdapterView[] memory views) {
        uint256 n = chainIds.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        views = new AdapterView[](n);
        for (uint256 i; i < n; ) {
            uint32 cid = chainIds[i];
            AdapterInfo storage a = _adapters[cid];
            views[i] = AdapterView({
                chainId: cid,
                adapter: a.adapter,
                tag: a.tag,
                registeredAt: a.registeredAt,
                exists: a.exists
            });
            unchecked { ++i; }
        }
    }

    function getVenueView(bytes32 venueId) external view returns (VenueView memory v) {
        VenueInfo storage info = _venues[venueId];
        v.venueId = venueId;
        v.chainVenueTag = info.chainVenueTag;
        v.registeredAt = info.registeredAt;
        v.enabled = info.enabled;
        v.exists = info.exists;
    }

    function getVenueViews(bytes32[] calldata venueIds_) external view returns (VenueView[] memory views) {
        uint256 n = venueIds_.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        views = new VenueView[](n);
        for (uint256 i; i < n; ) {
            bytes32 id = venueIds_[i];
            VenueInfo storage info = _venues[id];
            views[i] = VenueView({
                venueId: id,
                chainVenueTag: info.chainVenueTag,
                registeredAt: info.registeredAt,
                enabled: info.enabled,
                exists: info.exists
            });
            unchecked { ++i; }
        }
    }

    function venueEnabledFlags(bytes32[] calldata venueIds_) external view returns (bool[] memory enabled) {
        uint256 n = venueIds_.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        enabled = new bool[](n);
        for (uint256 i; i < n; ) {
            VenueInfo storage info = _venues[venueIds_[i]];
            enabled[i] = info.exists && info.enabled;
            unchecked { ++i; }
        }
    }

    function adapterAddresses(uint32[] calldata chainIds_) external view returns (address[] memory adapters_) {
        uint256 n = chainIds_.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        adapters_ = new address[](n);
        for (uint256 i; i < n; ) {
            adapters_[i] = _adapters[chainIds_[i]].adapter;
            unchecked { ++i; }
        }
    }

    function adapterTags(uint32[] calldata chainIds_) external view returns (bytes32[] memory tags) {
        uint256 n = chainIds_.length;
        if (n > SH_MAX_BATCH) revert SH__TooLarge();
        tags = new bytes32[](n);
        for (uint256 i; i < n; ) {
            tags[i] = _adapters[chainIds_[i]].tag;
            unchecked { ++i; }
        }
    }

    function venuesEnabledCount() external view returns (uint256 count) {
        uint256 n = _venueIds.length;
        for (uint256 i; i < n; ) {
            if (_venues[_venueIds[i]].enabled) unchecked { ++count; }
            unchecked { ++i; }
        }
    }

    function venuesDisabledCount() external view returns (uint256 count) {
        uint256 n = _venueIds.length;
        for (uint256 i; i < n; ) {
            if (_venues[_venueIds[i]].exists && !_venues[_venueIds[i]].enabled) unchecked { ++count; }
            unchecked { ++i; }
        }
    }

    function adaptersSetCount() external view returns (uint256 count) {
        uint256 n = _adapterChainIds.length;
        for (uint256 i; i < n; ) {
            if (_adapters[_adapterChainIds[i]].adapter != address(0)) unchecked { ++count; }
            unchecked { ++i; }
        }
    }

    function lastVenueId() external view returns (bytes32) {
        uint256 n = _venueIds.length;
        if (n == 0) return bytes32(0);
        return _venueIds[n - 1];
    }

    function lastAdapterChainId() external view returns (uint32) {
        uint256 n = _adapterChainIds.length;
        if (n == 0) return 0;
        return _adapterChainIds[n - 1];
    }

    // ------------------------------------------------------------------------
    // Intent histogram (O(n) view)
    // ------------------------------------------------------------------------

    function chainHistogram() external view returns (
        uint256 evmCount,
        uint256 solCount,
        uint256 suiCount,
        uint256 otherCount
    ) {
        uint256 nextId = _nextIntentId;
        for (uint256 id = 1; id < nextId; ) {
            Intent storage it = _intents[id];
            if (it.maker != address(0)) {
                if (it.dstChain == SH_CHAIN_EVM) unchecked { ++evmCount; }
                else if (it.dstChain == SH_CHAIN_SOLANA) unchecked { ++solCount; }
                else if (it.dstChain == SH_CHAIN_SUI) unchecked { ++suiCount; }
                else unchecked { ++otherCount; }
            }
            unchecked { ++id; }
        }
    }

    function venueHistogram(uint256 fromIndex, uint256 maxItems) external view returns (bytes32[] memory venues_, uint256[] memory counts_) {
        uint256 nAll = _venueIds.length;
        if (fromIndex >= nAll) return (new bytes32[](0), new uint256[](0));
        if (maxItems == 0) revert SH__BadAmount();
        uint256 end = fromIndex + maxItems;
        if (end > nAll) end = nAll;
        uint256 n = end - fromIndex;
        venues_ = new bytes32[](n);
        counts_ = new uint256[](n);
        for (uint256 i; i < n; ) {
            bytes32 venueId = _venueIds[fromIndex + i];
            venues_[i] = venueId;
            uint256 nextId = _nextIntentId;
            uint256 c;
            for (uint256 id = 1; id < nextId; ) {
                if (_fills[id].exists && _fills[id].venueId == venueId) unchecked { ++c; }
                unchecked { ++id; }
            }
            counts_[i] = c;
            unchecked { ++i; }
        }
    }

    // ------------------------------------------------------------------------
    // Misc helpers for offchain indexers
    // ------------------------------------------------------------------------

    function eventTopicIntentPosted() external pure returns (bytes32) {
        return keccak256("IntentPosted(uint256,address,bytes32,uint32,uint32,uint64,uint128)");
    }

    function eventTopicIntentFilled() external pure returns (bytes32) {
        return keccak256("IntentFilled(uint256,bytes32,bytes32,uint64,uint128)");
    }

    function eventTopicAdapterRegistered() external pure returns (bytes32) {
        return keccak256("AdapterRegistered(uint32,bytes32,address,uint64)");
    }

    function eventTopicVenueRegistered() external pure returns (bytes32) {
        return keccak256("VenueRegistered(bytes32,bytes32,uint64)");
    }

    function eventTopicVenueEnabled() external pure returns (bytes32) {
        return keccak256("VenueEnabled(bytes32,bool,uint64)");
    }

    function eventTopicFlag() external pure returns (bytes32) {
        return keccak256("IntentFlagged(uint256,bytes32,uint64)");
    }

    function eventTopicUnflag() external pure returns (bytes32) {
        return keccak256("IntentUnflagged(uint256,uint64)");
    }

    function computeLogKey(bytes32 topic0, bytes32 topic1, bytes32 topic2) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(topic0, topic1, topic2));
    }

    function computeIndexKey(bytes32 namespace_, uint256 id) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(namespace_, id));
    }

    function computeNamespace(string calldata label) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("NS", label));
    }

    function computeVenueNamespace(uint32 chainId) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("VENUE_NS", chainId));
    }

    function computeAdapterNamespace(uint32 chainId) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("ADAPTER_NS", chainId));
    }

    function computeIntentNamespace(uint32 srcChain, uint32 dstChain) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("INTENT_NS", srcChain, dstChain));
    }

    function computeFillNamespace(uint32 dstChain, bytes32 venueId) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("FILL_NS", dstChain, venueId));
    }

    function computeFeeNamespace(address makerAddr) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("FEE_NS", makerAddr));
    }

    function computeRiskNamespace(bytes32 reason) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("RISK_NS", reason));
    }

    // ------------------------------------------------------------------------
    // Final helper bundle (small, deterministic, UI-friendly)
    // ------------------------------------------------------------------------

    function isSolanaLike(uint32 chainId) external pure returns (bool) {
        return chainId == SH_CHAIN_SOLANA;
    }

    function isSuiLike(uint32 chainId) external pure returns (bool) {
        return chainId == SH_CHAIN_SUI;
    }

    function isEvmLike(uint32 chainId) external pure returns (bool) {
        return chainId == SH_CHAIN_EVM;
    }

    function requireVenueEnabled(bytes32 venueId) external view {
        VenueInfo storage v = _venues[venueId];
        if (!v.exists || !v.enabled) revert SH__BadVenue();
    }

    function requireAdapter(uint32 chainId) external view {
