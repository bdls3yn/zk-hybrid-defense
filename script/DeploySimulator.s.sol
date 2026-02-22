// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/AttackSimulator.sol";

contract DeploySimulator is Script {
    function run() external {
        vm.startBroadcast();
        AttackSimulator sim = new AttackSimulator(
            0x733a81BCBF22815675e788D3e406Dc2f0cE71E8f
        );
        console.log("AttackSimulator deployed:", address(sim));
        vm.stopBroadcast();
    }
}
