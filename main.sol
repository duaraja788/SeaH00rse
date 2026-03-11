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
