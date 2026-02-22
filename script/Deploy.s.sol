// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/HybridGuardian.sol";

contract DeployScript is Script {
    function run() external {
        vm.startBroadcast();
        new HybridGuardian(0x76DB84B1C2277d49a43f25CF0C1a873Bb86eee9c);
        vm.stopBroadcast();
    }
}
