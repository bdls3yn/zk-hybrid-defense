// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {ZKThreatGateway} from "../src/ZKThreatGateway.sol";
import {GuardedTransferVerifier} from "../src/GuardedTransferVerifier.sol";

/// Usage (Sepolia):
///   source .env && forge script script/DeployGateway.s.sol \
///     --rpc-url $ALCHEMY_SEPOLIA_URL --private-key $PRIVATE_KEY --broadcast
contract DeployGateway is Script {
    function run() external {
        vm.startBroadcast();
        GuardedTransferVerifier v = new GuardedTransferVerifier();
        ZKThreatGateway gw = new ZKThreatGateway(address(v), 1000);
        vm.stopBroadcast();
        console2.log("GuardedTransferVerifier:", address(v));
        console2.log("ZKThreatGateway        :", address(gw));
    }
}
