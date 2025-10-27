// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IRiscZeroVerifier {
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
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

    /// The Safe this module is installed on.
    address public safe;

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
    event HashesUpdated(bytes32 newPolicyHash, bytes32 newGroupsHash, bytes32 newAllowHash);

    /// @notice Constructor
    /// @param _verifier The RISC0 verifier contract address.
    /// @param _imageId The RISC0 image ID for the ZKGuard policy engine.
    /// @param _groupsHash The initial groups root hash.
    /// @param _allowHash The initial allowlists root hash.
    constructor(address _verifier, address _imageId, bytes32 _groupsHash, bytes32 _allowHash) {
        require(_verifier != address(0), "zero-address-verifier");
        VERIFIER = IRiscZeroVerifier(_verifier);
        IMAGE_ID = IImageID(_imageId).ZKGUARD_POLICY_ID();

        groupsHash = _groupsHash;
        allowHash = _allowHash;
    }

    /// @notice Sets the internal SAFE address. Can only be called once, and only by the Safe itself.
    /// @param _safe The address of the Safe to associate with this module.
    /// @param _policyHash The initial policy root hash.
    /// @dev This function is intended to be called during the Safe's setup process via DELEGATECALL.
    ///   In case it is NOT called during setup, ANYONE could call this function later to set the Safe address,
    ///   which could be a security risk. If the SAFE address is already set, or if the caller is not the Safe itself, the call reverts.
    function setSafe(address _safe, bytes32 _policyHash) external {
        // (1) Ensure safe is not already set, module is enabled on the Safe, and caller is the Safe itself.
        require(safe == address(0), "already-set");
        require(ISafe(_safe).isModuleEnabled(address(this)), "module-not-enabled");
        require(msg.sender == _safe, "only-safe");

        // (2) Set the safe and policy hash.
        policyHash = _policyHash;
        safe = _safe;
    }

    /// @notice Updates the policy, groups, and allowlist root hashes.
    /// @param newPolicyHash The new policy root hash.
    /// @param newGroupsHash The new groups root hash.
    /// @param newAllowHash The new allowlists root hash.
    /// @dev Can only be called by the Safe itself when this module is enabled.
    function updateHashes(bytes32 newPolicyHash, bytes32 newGroupsHash, bytes32 newAllowHash) external {
        // (1) Verify caller is the Safe and that this module is enabled on it.
        require(msg.sender == safe, "only-safe-caller");

        require(ISafe(safe).isModuleEnabled(address(this)), "module-not-enabled");

        // (2) Update the hashes.
        policyHash = newPolicyHash;
        groupsHash = newGroupsHash;
        allowHash = newAllowHash;

        // (3) Emit event for off-chain indexing.
        emit HashesUpdated(newPolicyHash, newGroupsHash, newAllowHash);
    }

    /// @notice Verifies the RISC0 proof and enforces the journal claims against the module state.
    /// @param seal The RISC0 proof seal.
    /// @param journal The RISC0 proof journal.
    /// @return claimedActionHash The action hash claimed in the journal.
    /// @return jdig The SHA256 digest of the journal.
    function _verify(bytes calldata seal, bytes calldata journal) internal view returns (bytes32, bytes32) {
        // (1) Verify RISC Zero proof
        bytes32 jdig = sha256(journal);
        VERIFIER.verify(seal, IMAGE_ID, jdig);

        // (2) Decode journal claims + enforce against module state.
        (bytes32 claimedActionHash, bytes32 claimedPolicyHash, bytes32 claimedGroupsHash, bytes32 claimedAllowHash) =
            abi.decode(journal, (bytes32, bytes32, bytes32, bytes32));

        require(claimedPolicyHash == policyHash, "policy-hash-mismatch");
        require(claimedGroupsHash == groupsHash, "groups-hash-mismatch");
        require(claimedAllowHash == allowHash, "allow-hash-mismatch");

        // (3) Return claimed action hash for further processing.
        return (claimedActionHash, jdig);
    }

    /// @notice Verifies a user action via RISC0 proof and executes it via the Safe.
    /// @param userAction The encoded user action: abi.encode(address from, address to, uint256 value, bytes data, uint256 nonce)
    /// @param seal The RISC0 proof seal.
    /// @param journal The RISC0 proof journal.
    /// @param operation The Safe operation type (Call or DelegateCall).
    /// @return returnData The returndata from the Safe execution.
    function verifyAndExec(
        bytes calldata userAction,
        bytes calldata seal,
        bytes calldata journal,
        Enum.Operation operation
    ) external returns (bytes memory returnData) {
        // (1) Verify the proof and journal claims.
        (bytes32 claimedActionHash, bytes32 jdig) = _verify(seal, journal);

        // (2) Decode the user action.
        (address from, address to, uint256 value, uint256 nonce, bytes memory data) =
            abi.decode(userAction, (address, address, uint256, uint256, bytes));

        // (3) Bind to exact user action.
        bytes32 actionHash = keccak256(userAction);
        require(claimedActionHash == actionHash, "action-hash-mismatch");

        // (4) Enforce that from == safe
        require(from == safe, "invalid-user-action-from");

        // (5) Enforce replay protection by requiring the action's nonce to match the Safe's current nonce.
        uint256 safeNonce = ISafe(safe).nonce();
        require(nonce == safeNonce, "invalid-nonce");

        // (6) Execute via the Safe module path (must be enabled on `safe`).
        (bool ok, bytes memory ret) = ISafe(safe).execTransactionFromModuleReturnData(to, value, data, operation);
        require(ok, "safe-exec-failed");

        // (7) Emit event for off-chain indexing.
        emit VerifiedAndExecuted(safe, to, value, operation, actionHash, jdig);
        return ret;
    }
}
