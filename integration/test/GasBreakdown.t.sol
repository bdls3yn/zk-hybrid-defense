// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test, console2} from "forge-std/Test.sol";
import {GuardedTransferVerifier} from "../src/GuardedTransferVerifier.sol";
import {Groth16Verifier} from "v1/RangeProofVerifier.sol";
import {ZKThreatGateway} from "../src/ZKThreatGateway.sol";
import {Fixtures} from "./Fixtures.sol";
contract GasBreakdownTest is Test {
    function test_Breakdown() public {
        vm.chainId(31337);
        GuardedTransferVerifier v2 = new GuardedTransferVerifier();
        Groth16Verifier v1 = new Groth16Verifier();
        uint256[14] memory p = Fixtures.benign()[0];
        uint256[10] memory o = Fixtures.old_legit();
        uint256 g = gasleft();
        v1.verifyProof([o[0], o[1]], [[o[2], o[3]], [o[4], o[5]]], [o[6], o[7]], [o[8], o[9]]);
        console2.log("v1 verifier (2 public):", g - gasleft());
        g = gasleft();
        v2.verifyProof([p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]], [p[8], p[9], p[10], p[11], p[12], p[13]]);
        console2.log("v2 verifier (6 public):", g - gasleft());
        ZKThreatGateway gw = new ZKThreatGateway(address(v2), 1000);
        vm.prank(address(uint160(p[12])));
        g = gasleft();
        gw.submit([p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]], [p[8], p[9], p[10], p[11], p[12], p[13]], Fixtures.benignCt()[0]);
        console2.log("gateway submit total:", g - gasleft());
        console2.log("cm", p[8]); console2.log("nf", p[9]); console2.log("cipher field", p[11]);
    }
}
