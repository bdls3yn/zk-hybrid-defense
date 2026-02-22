// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/ThreatDetector.sol";

contract DeployThreatDetector is Script {
    function run() external {
        vm.startBroadcast();
        ThreatDetector td = new ThreatDetector();
        console.log("ThreatDetector deployed:", address(td));
        vm.stopBroadcast();
    }
}
