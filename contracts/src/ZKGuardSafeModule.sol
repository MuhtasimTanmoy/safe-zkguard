// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IRiscZeroVerifier {
    function verify(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest
    ) external view;
}

library Enum {
    enum Operation {
        Call,
        DelegateCall
    }
}

interface ISafe {
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external returns (bool success, bytes memory returnData);
    function isModuleEnabled(address module) external view returns (bool);
    function enableModule(address module) external;
    function nonce() external view returns (uint256);
}
/// @notice Interface for the ImageID contract.
interface IImageID {
    function ZKGUARD_POLICY_ID() external view returns (bytes32);
}
/// @title ZKGuardSafeModule
/// @notice A Safe Module that verifies a RISC0 proof attesting that an action
///         complies with the ZKGuard policy engine, then executes that action via the Safe.
/// @dev Journal layout:
///      abi.encode(
///         bytes32 claimedActionHash,
///         bytes32 claimedPolicyHash,
///         bytes32 claimedGroupsHash,
///         bytes32 claimedAllowHash
///      )
///      userAction layout
///      abi.encode(address to, uint256 value, bytes data, uint256 nonce)
contract ZKGuardSafeModule {
    /// Immutable verifier + imageId (pinned at construction time).
    /// @notice Image ID of the only zkVM binary to accept verification from.
    bytes32 public immutable IMAGE_ID;
    IRiscZeroVerifier public immutable VERIFIER;
    /// Policy root commitments pinned in the module.
    bytes32 public policyHash;
    bytes32 public groupsHash;
    bytes32 public allowHash;

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
        bytes32 _policyHash,
        bytes32 _groupsHash,
        bytes32 _allowHash
    ) {
        require(_verifier != address(0), "bad-verifier");
        VERIFIER = IRiscZeroVerifier(_verifier);
        IMAGE_ID = IImageID(_imageId).ZKGUARD_POLICY_ID();

        policyHash = _policyHash;
        groupsHash = _groupsHash;
        allowHash = _allowHash;
    }

    function installOnSetup(address moduleAddr) external {
        ISafe(address(this)).enableModule(moduleAddr);
    }

    function updateHashes(
        bytes32 newPolicyHash,
        bytes32 newGroupsHash,
        bytes32 newAllowHash
    ) external {
        policyHash = newPolicyHash;
        groupsHash = newGroupsHash;
        allowHash = newAllowHash;
    }

    function _verify(
        bytes calldata seal,
        bytes calldata journal
    ) internal view returns (bytes32, bytes32) {
        // (1) Verify RISC Zero proof; inherits all invariants enforced by the canonical verifier.
        bytes32 jdig = sha256(journal);
        VERIFIER.verify(seal, IMAGE_ID, jdig);

        // (2) Decode journal claims + enforce against module state.
        (
            bytes32 claimedActionHash,
            bytes32 claimedPolicyHash,
            bytes32 claimedGroupsHash,
            bytes32 claimedAllowHash
        ) = abi.decode(journal, (bytes32, bytes32, bytes32, bytes32));

        require(claimedPolicyHash == policyHash, "policy-hash-mismatch");
        require(claimedGroupsHash == groupsHash, "groups-hash-mismatch");
        require(claimedAllowHash == allowHash, "allow-hash-mismatch");

        // (3) Return claimed action hash for further processing.
        return (claimedActionHash, jdig);
    }

    function verifyAndExec(
        address safe,
        bytes calldata userAction,
        bytes calldata seal,
        bytes calldata journal,
        Enum.Operation operation
    ) external returns (bytes memory returnData) {
        // (1) Verify the proof and journal claims.
        (bytes32 claimedActionHash, bytes32 jdig) = _verify(seal, journal);

        // (2) Decode the user action.
        (address to, uint256 value, uint256 nonce, bytes memory data) = abi
            .decode(userAction, (address, uint256, uint256, bytes));

        // (3) Bind to exact user action.
        bytes32 actionHash = keccak256(userAction);
        require(claimedActionHash == actionHash, "action-hash-mismatch");

        // (4) Enforce replay protection by requiring the action's nonce to match the Safe's current nonce.
        //     This binds the proof to a specific state of the Safe, preventing replay attacks.
        require(nonce == ISafe(safe).nonce(), "invalid-nonce");

        // (5) Execute via the Safe module path (must be enabled on `safe`).
        //     If this module is not enabled on `safe`, the call reverts inside the Safe.
        //     Use ReturnData variant so callers can bubble up the target's returndata.
        (bool ok, bytes memory ret) = ISafe(safe)
            .execTransactionFromModuleReturnData(to, value, data, operation);
        require(ok, "safe-exec-failed");

        // (6) Emit event for off-chain indexing.
        emit VerifiedAndExecuted(safe, to, value, operation, actionHash, jdig);
        return ret;
    }
}
