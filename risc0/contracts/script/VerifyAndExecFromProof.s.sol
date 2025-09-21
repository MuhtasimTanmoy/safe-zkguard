// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Script.sol";
import {ZKGuardSafeModule, Enum, ISafe} from "../src/ZKGuardSafeModule.sol";

contract VerifyAndExecFromProof is Script {
    function run() external {
        // --- Required inputs (taken from .env) ---
        address safe = vm.envAddress("SAFE_ADDR"); // the Safe
        address moduleAddr = vm.envAddress("ZKGUARD_MODULE"); // deployed ZKGuardSafeModule
        address to = vm.envAddress("ACTION_TO"); // target
        uint256 value = vm.envUint("ACTION_VALUE"); // wei
        bytes memory data = vm.envBytes("ACTION_DATA"); // 0x... calldata
        bytes memory seal = vm.envBytes("RISC0_SEAL"); // RISC0 receipt seal (0x...)
        bytes memory journal = vm.envBytes("RISC0_JOURNAL"); // RISC0 journal bytes (0x...)
        // uint256 opRaw = vm.envUint("ACTION_OPERATION"); // 0=Call, 1=DelegateCall

        // Only calls allowed for now
        Enum.Operation operation = Enum.Operation.Call;

        // Assemble the userAction exactly as the module decodes:
        // (address to, uint256 value, bytes data)
        bytes memory userAction = abi.encode(to, value, data);

        vm.startBroadcast();
        bytes memory ret = ZKGuardSafeModule(moduleAddr).verifyAndExec(
            safe,
            userAction,
            seal,
            journal,
            operation
        );
        vm.stopBroadcast();

        // Helpful logs
        console2.log("verifyAndExec ok. Safe:", safe);
        console2.log("Target:", to);
        console2.log("Returned bytes len:", ret.length);
    }
}
