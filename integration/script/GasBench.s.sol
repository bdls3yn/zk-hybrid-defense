// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {ZKThreatGateway} from "../src/ZKThreatGateway.sol";
import {GuardedTransferVerifier} from "../src/GuardedTransferVerifier.sol";
import {HybridGuardian} from "v1/HybridGuardian.sol";
import {Groth16Verifier} from "v1/RangeProofVerifier.sol";
import {Fixtures} from "../test/Fixtures.sol";

/// Broadcasts real transactions to a local anvil (chainId 31337) to obtain
/// full receipt gas (intrinsic + calldata + execution) for each path.
contract GasBench is Script {
    function run() external {
        uint256[14] memory p = Fixtures.benign()[0];
        bytes32 ct = Fixtures.benignCt()[0];
        address actor = address(uint160(p[12]));
        uint256[10] memory o = Fixtures.old_legit();

        vm.startBroadcast(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80); // anvil #0
        Groth16Verifier v1 = new Groth16Verifier();
        HybridGuardian hg = new HybridGuardian(address(v1));
        hg.submitVerifiedTransaction([o[0], o[1]], [[o[2], o[3]], [o[4], o[5]]], [o[6], o[7]], [o[8], o[9]], keccak256("bench"));
        GuardedTransferVerifier v2 = new GuardedTransferVerifier();
        ZKThreatGateway gw = new ZKThreatGateway(address(v2), 1000);
        vm.stopBroadcast();

        vm.startBroadcast(actor); // anvil is started with --auto-impersonate
        gw.submit([p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]], [p[8], p[9], p[10], p[11], p[12], p[13]], ct); // Accepted
        gw.submit([p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]], [p[8], p[9], p[10], p[11], p[12], p[13]], ct); // Replay
        vm.stopBroadcast();
    }
}
