// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test, console2} from "forge-std/Test.sol";
import {ZKThreatGateway} from "../src/ZKThreatGateway.sol";
import {GuardedTransferVerifier} from "../src/GuardedTransferVerifier.sol";
import {Fixtures} from "./Fixtures.sol";

/// @notice Logs the on-chain risk score of two attackers over 4 hours (used for the score-trajectory figure).
contract TrajectoryTest is Test {
    ZKThreatGateway gw;
    function setUp() public {
        vm.chainId(31337); vm.warp(1_760_000_000); vm.roll(1_000_000);
        gw = new ZKThreatGateway(address(new GuardedTransferVerifier()), 1000);
    }
    function _sub(uint256[14] memory p, bytes32 ct) internal returns (ZKThreatGateway.Status) {
        vm.prank(address(uint160(p[12])));
        return gw.submit([p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]], [p[8], p[9], p[10], p[11], p[12], p[13]], ct);
    }
    function test_Trajectory() public {
        uint256[14][] memory E = Fixtures.esc(); bytes32[] memory EC = Fixtures.escCt();
        uint256[14][] memory D = Fixtures.ddos(); bytes32[] memory DC = Fixtures.ddosCt();
        address r = address(uint160(E[0][12])); address d = address(uint160(D[0][12]));
        uint256 t0 = block.timestamp;
        _sub(E[0], EC[0]); vm.warp(t0 + 5); _sub(E[0], EC[0]); vm.warp(t0 + 10); _sub(E[0], EC[0]);
        for (uint256 i; i < 11; i++) { vm.warp(t0 + 10 + 4 * (i + 1)); vm.roll(block.number + 3); _sub(D[i], DC[i]); }
        for (uint256 s = 0; s <= 14400; s += 300) {
            vm.warp(t0 + 60 + s);
            console2.log(string.concat("TRAJ,", vm.toString(s), ",", vm.toString(uint256(gw.currentScore(r))), ",", vm.toString(uint256(gw.currentScore(d))), ",", gw.riskLevel(r)));
        }
    }
}
