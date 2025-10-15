// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/*
Nick’s method (keyless / one-time EOA), summarized:

- Ethereum derives the "from" address of a signature/tx via `ecrecover(msgHash, v, r, s)`.
- For roughly half of random (v,r,s) tuples, `ecrecover` returns *some* address,
  even though no one computed (or knows) the matching private key for that address.
- By picking random r,s (with EIP-2 constraints: 1 <= r < n, 1 <= s <= n/2) and v in {27,28},
  and trying until `ecrecover` != address(0), we obtain an address that was *not*
  generated from any private key we know or control.
- This is useful when you need a non-zero, non-controllable EOA (e.g., Safe owner)
  so all authority flows through a module. We do NOT store or derive any private key.

See: 
- medium.com/patronum-labs/nicks-method-ethereum-keyless-execution-168a6659479c
*/

library NickAddress {
    // secp256k1 curve order (n) and n/2 (EIP-2 low-s requirement)
    uint256 private constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant HALF_N = (N >> 1);

    /// @notice Create a "keyless" random-looking EOA address via Nick’s method.
    /// @dev    Never generates or requires a private key. Deterministic from `seed`.
    ///         Loops up to 1024 attempts to find a nonzero `ecrecover`.
    /// @param  seed Arbitrary seed (e.g., keccak256 of env + block, or vm randomness in scripts)
    /// @return addr A nonzero address that we did not (and cannot) derive a private key for
    function createRandomAddress(
        bytes32 seed
    ) internal pure returns (address addr) {
        // Fixed message domain to avoid accidental collisions with app messages.
        bytes32 m = keccak256(abi.encodePacked("nick-method.addr.v1", seed));

        unchecked {
            for (uint256 i = 0; i < 1024; ++i) {
                // Pseudo-random candidates from the seed; map into valid ranges.
                uint256 rNum = (uint256(
                    keccak256(abi.encodePacked(seed, i, "r"))
                ) % (N - 1)) + 1;
                uint256 sNum = (uint256(
                    keccak256(abi.encodePacked(seed, i, "s"))
                ) % (HALF_N - 1)) + 1;
                uint8 v = uint8(
                    uint256(keccak256(abi.encodePacked(seed, i, "v"))) & 1
                ) + 27;

                address a = ecrecover(m, v, bytes32(rNum), bytes32(sNum));
                if (a != address(0)) {
                    return a;
                }
            }
        }
        revert("nick: no address found (try different seed)");
    }
}
