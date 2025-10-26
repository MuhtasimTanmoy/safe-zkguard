// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Script.sol";
import {ZKGuardSafeModule} from "../src/ZKGuardSafeModule.sol";
import "./NickAddress.sol";

// --- Minimal Safe interfaces (same as used broadly in Safe scripts) ---
interface ISafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external
        returns (address proxy);

    function proxyCreationCode() external view returns (bytes memory);
}

interface ISafe {
    function setup(
        address[] memory owners,
        uint256 threshold,
        address to,
        bytes memory data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;
    function isModuleEnabled(address module) external view returns (bool);
    function enableModule(address module) external;
}

contract SafeModuleSetup {
    /// @notice Enables multiple modules on the Safe.
    /// @param modules The list of module addresses to enable.
    /// @dev This function is intended to be called via DELEGATECALL during Safe.setup
    ///      to enable modules and then call setSafe on them.
    function enableModules(address[] calldata modules, bytes32[] calldata policyHashList) external {
        for (uint256 i = 0; i < modules.length; i++) {
            // (1) Enable the module on the Safe
            ISafe(address(this)).enableModule(modules[i]);

            // (2) Call setSafe on the module to bind it to this Safe
            ZKGuardSafeModule(modules[i]).setSafe(address(this), policyHashList[i]);
        }
    }
}

contract DeployModule is Script {
    // Predict CREATE2 address exactly like SafeProxyFactory does:
    // salt = keccak256( keccak256(initializer) || saltNonce )
    function _predictSafeAddress(address factory, address singleton, bytes memory initializer, uint256 saltNonce)
        internal
        view
        returns (address predicted)
    {
        bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        bytes memory creationCode = ISafeProxyFactory(factory).proxyCreationCode();
        bytes memory initCode = abi.encodePacked(creationCode, uint256(uint160(singleton)));
        bytes32 initCodeHash = keccak256(initCode);
        bytes32 raw = keccak256(abi.encodePacked(bytes1(0xff), factory, salt, initCodeHash));
        predicted = address(uint160(uint256(raw)));
    }

    function run() external {
        // -------- ENV (align with your CI/secrets) --------
        address verifier = vm.envAddress("RISC0_VERIFIER"); // IRiscZeroVerifier
        address imageId = vm.envAddress("RISC0_IMAGE_ID"); // per-Safe guest image id

        bytes32 groupsHash = vm.envBytes32("GROUPS_HASH"); // groups root
        bytes32 allowHash = vm.envBytes32("ALLOW_HASH"); // allowlists root

        vm.startBroadcast();

        // 1) Deploy per-Safe ZKGuard module (unique instance; do not reuse across Safes)
        ZKGuardSafeModule zkModule = new ZKGuardSafeModule(verifier, imageId, groupsHash, allowHash);

        vm.stopBroadcast();

        console2.log("ZKGuard module:", address(zkModule));
    }
}
