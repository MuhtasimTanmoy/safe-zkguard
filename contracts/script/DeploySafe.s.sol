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

contract DeploySafe is Script {
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
        address singleton = vm.envAddress("SAFE_SINGLETON"); // Safe or SafeL2
        address proxyFactory = vm.envAddress("SAFE_PROXY_FACTORY"); // SafeProxyFactory
        address fallbackHandler = vm.envAddress("SAFE_FALLBACK_HANDLER"); // optional
        uint256 saltNonce = vm.envUint("SAFE_SALT_NONCE");

        address zkGuardModuleAddress = vm.envAddress("ZKGUARD_MODULE_ADDRESS");
        bytes32 policyHash = vm.envBytes32("POLICY_HASH");

        uint256 ownersLen = 1;
        address[] memory owners = new address[](ownersLen);
        address nickOwner = NickAddress.createRandomAddress(
            keccak256(abi.encodePacked(block.timestamp, msg.sender, vm.envBytes32("NICK_SEED")))
        );
        owners[0] = nickOwner;

        vm.startBroadcast();

        // 1) Deploy tiny setup helper (enables modules during Safe.setup via delegatecall)
        SafeModuleSetup setupHelper = new SafeModuleSetup();

        // 2) Build Safe.setup initializer to enable our ZKGuard module
        address[] memory mods = new address[](1);
        mods[0] = zkGuardModuleAddress;

        bytes32[] memory policyHashList = new bytes32[](1);
        policyHashList[0] = policyHash;

        bytes memory enableData = abi.encodeWithSelector(SafeModuleSetup.enableModules.selector, mods, policyHashList);

        bytes memory initializer = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            1,
            address(setupHelper), // to (delegatecall target)
            enableData, // data (enable our module)
            fallbackHandler,
            address(0), // paymentToken
            0, // payment
            address(0) // paymentReceiver
        );

        // 4) (Optional) Predict the Safe address for logs/binding
        address predictedSafe = _predictSafeAddress(proxyFactory, singleton, initializer, saltNonce);

        // 5) Create the Safe proxy with module enabled at setup
        address safeAddr = ISafeProxyFactory(proxyFactory).createProxyWithNonce(singleton, initializer, saltNonce);

        // 6) Sanity checks
        require(safeAddr == predictedSafe, "SAFE_ADDRESS_MISMATCH");
        require(ISafe(safeAddr).isModuleEnabled(zkGuardModuleAddress), "MODULE_NOT_ENABLED");

        vm.stopBroadcast();

        console2.log("Safe:", safeAddr);
        console2.log("ZKGuard module:", zkGuardModuleAddress);
        console2.log("Setup helper:", address(setupHelper));
    }
}
