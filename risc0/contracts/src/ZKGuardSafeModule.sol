// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Minimal IRiscZeroVerifier (kept inline to avoid path headaches).
/// Matches risczero-ethereum IRiscZeroVerifier: verify(seal, imageId, journalDigest).
interface IRiscZeroVerifier {
    function verify(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest
    ) external view;
}

/// Minimal Safe interface for module execution.
library Enum {
    enum Operation {
        Call, // 0
        DelegateCall // 1
    }
}

interface ISafe {
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external returns (bool success, bytes memory returnData);
    // Optional early sanity check; Safe will enforce module enablement anyway.
    function isModuleEnabled(address module) external view returns (bool);
    function enableModule(address module) external;
}

/// @notice Interface for the ImageID contract.
interface IImageID {
    function ZKGUARD_POLICY_ID() external view returns (bytes32);
}

/// @title ZKGuardSafeModule
/// @notice A Safe Module that verifies a RISC0 proof attesting that an action
///         complies with the ZKGuard policy engine, then executes that action via the Safe.
/// @dev Journal layout (same as your wrapper):
///      abi.encode(
///         bytes32 claimed_action_hash,
///         bytes32 claimed_policy_hash,
///         bytes32 claimed_groups_hash,
///         bytes32 claimed_allow_hash
///      )
///      userAction layout (same as your wrapper):
///      abi.encode(address to, uint256 value, bytes data, address signer, bytes signature)
contract ZKGuardSafeModule {
    /// Immutable verifier + imageId (pinned at construction time).
    /// @notice Image ID of the only zkVM binary to accept verification from.
    bytes32 public imageId;
    IRiscZeroVerifier public immutable verifier;

    /// Policy root commitments pinned in the module.
    bytes32 public immutable policy_hash;
    bytes32 public immutable groups_hash;
    bytes32 public immutable allow_hash;

    /// Replay protection keyed by (sha256(journal) || keccak256(userAction)).
    mapping(bytes32 => bool) public usedReceipt;

    event VerifiedAndExecuted(
        address indexed safe,
        address indexed to,
        uint256 value,
        Enum.Operation operation,
        bytes32 actionHash,
        bytes32 journalDigest
    );

    constructor(
        address _verifier,
        address _imageId,
        bytes32 _policy_hash,
        bytes32 _groups_hash,
        bytes32 _allow_hash
    ) {
        require(_verifier != address(0), "bad-verifier");
        verifier = IRiscZeroVerifier(_verifier);
        imageId = IImageID(_imageId).ZKGUARD_POLICY_ID();

        policy_hash = _policy_hash;
        groups_hash = _groups_hash;
        allow_hash = _allow_hash;
    }

    /// @notice Called via Safe.setup through DELEGATECALL to enable `moduleAddr` on the Safe.
    /// @dev    Runs in the Safe's context (delegatecall), then performs an external self-call:
    ///         ISafe(address(this)).enableModule(moduleAddr).
    function installOnSetup(address moduleAddr) external {
        // Self-call from the Safe to itself so ModuleManager's `authorized` check passes.
        ISafe(address(this)).enableModule(moduleAddr);
    }

    /// @notice Verify proof & execute the action via the Safe (module path).
    /// @param safe       The Safe to execute via (must have this module enabled).
    /// @param userAction Encodes (to, value, data, signer, signature).
    /// @param seal       RISC0 receipt seal (proof).
    /// @param journal    RISC0 journal bytes encoding the four hashes described above.
    /// @param operation  Safe operation (Call or DelegateCall).
    /// @return returnData Bytes returned by the target call.
    function verifyAndExec(
        address safe,
        bytes calldata userAction,
        bytes calldata seal,
        bytes calldata journal,
        Enum.Operation operation
    ) external returns (bytes memory returnData) {
        // (1) Verify RISC Zero proof; inherits all invariants enforced by the canonical verifier.
        bytes32 jdig = sha256(journal);
        verifier.verify(seal, imageId, jdig);
        // (2) Decode journal claims + enforce against module state.
        (
            bytes32 claimed_action_hash,
            bytes32 claimed_policy_hash,
            bytes32 claimed_groups_hash,
            bytes32 claimed_allow_hash
        ) = abi.decode(journal, (bytes32, bytes32, bytes32, bytes32));

        require(claimed_policy_hash == policy_hash, "policy-hash-mismatch");
        require(claimed_groups_hash == groups_hash, "groups-hash-mismatch");
        require(claimed_allow_hash == allow_hash, "allow-hash-mismatch");

        // (3) Bind to exact user action.
        bytes32 actionHash = keccak256(userAction);
        require(claimed_action_hash == actionHash, "action-hash-mismatch");

        // (4) Basic replay protection (receipt+action uniqueness).
        bytes32 receiptKey = keccak256(abi.encodePacked(jdig, actionHash));
        require(!usedReceipt[receiptKey], "receipt-reused");
        usedReceipt[receiptKey] = true;

        // (5) Decode the actionable call (same tuple as your wrapper; signature is currently informational).
        (address to, uint256 value, bytes memory data) = abi.decode(
            userAction,
            (address, uint256, bytes)
        );

        // (6) Execute via the Safe module path (must be enabled on `safe`).
        //     If this module is not enabled on `safe`, the call reverts inside the Safe.
        //     Use ReturnData variant so callers can bubble up the target's returndata.
        (bool ok, bytes memory ret) = ISafe(safe)
            .execTransactionFromModuleReturnData(to, value, data, operation);
        require(ok, "safe-exec-failed");

        emit VerifiedAndExecuted(safe, to, value, operation, actionHash, jdig);
        return ret;
    }

    /// Convenience: early check to fail fast (optional; Safe will enforce at execution).
    function isEnabledOn(address safe) external view returns (bool) {
        try ISafe(safe).isModuleEnabled(address(this)) returns (bool enabled) {
            return enabled;
        } catch {
            // Some Safe versions may not expose isModuleEnabled externally; ignore.
            return true;
        }
    }
}
