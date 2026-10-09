// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ZKThreatGateway} from "../src/ZKThreatGateway.sol";
import {GuardedTransferVerifier} from "../src/GuardedTransferVerifier.sol";
import {Fixtures} from "./Fixtures.sol";

/// @notice Auditor-side same-plaintext consistency (response to reviewer:
///         "the SNARK witness is not bound to the CKKS plaintext").
contract AuditTest is Test {
    ZKThreatGateway gw;
    address auditor = address(0xA0D17);

    function setUp() public {
        vm.chainId(31337);
        vm.warp(1_760_000_000);
        vm.roll(1_000_000);
        gw = new ZKThreatGateway(address(new GuardedTransferVerifier()), 1000);
        gw.setAuditor(auditor);
    }

    function _accept(uint256 i) internal returns (uint256 cm, address who) {
        uint256[14] memory p = Fixtures.benign()[i];
        who = address(uint160(p[12]));
        vm.prank(who);
        ZKThreatGateway.Status s = gw.submit([p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]],
            [p[8], p[9], p[10], p[11], p[12], p[13]], Fixtures.benignCt()[i]);
        assertEq(uint8(s), 0);
        cm = p[8];
    }

    function _audit(uint256 cm) internal view returns (uint8 au) {
        (,,, au) = gw.records(cm);
    }

    function test_ConsistentAudit_NoPenalty() public {
        (uint256 cm, address who) = _accept(0);
        vm.prank(auditor);
        gw.recordAudit(cm, true);
        assertEq(_audit(cm), 1);
        assertEq(gw.currentScore(who), 0);
    }

    function test_InconsistentAudit_QuarantinesSender() public {
        (uint256 cm, address who) = _accept(1);
        vm.expectEmit(true, true, false, true);
        emit ZKThreatGateway.AuditRecorded(cm, who, false);
        vm.prank(auditor);
        gw.recordAudit(cm, false);
        assertEq(_audit(cm), 2);
        assertEq(gw.currentScore(who), 100);
        assertEq(gw.riskLevel(who), "CRITICAL");
        // the sender cannot submit while quarantined
        uint256[14] memory p = Fixtures.benign()[1];
        vm.prank(who);
        ZKThreatGateway.Status s = gw.submit([p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]],
            [p[8], p[9], p[10], p[11], p[12], p[13]], Fixtures.benignCt()[1]);
        assertEq(uint8(s), uint8(ZKThreatGateway.Status.Quarantined));
    }

    function test_OnlyAuditor() public {
        (uint256 cm,) = _accept(2);
        vm.prank(address(0xBAD));
        vm.expectRevert("not auditor");
        gw.recordAudit(cm, false);
    }

    function test_UnknownRecord_Reverts() public {
        vm.prank(auditor);
        vm.expectRevert("unknown record");
        gw.recordAudit(12345, true);
    }

    function test_NoDoubleAudit() public {
        (uint256 cm,) = _accept(3);
        vm.startPrank(auditor);
        gw.recordAudit(cm, true);
        vm.expectRevert("already audited");
        gw.recordAudit(cm, false);
        vm.stopPrank();
    }

    function test_AuditorMustBeSet() public {
        ZKThreatGateway g2 = new ZKThreatGateway(address(new GuardedTransferVerifier()), 1000);
        vm.prank(address(0));
        vm.expectRevert("not auditor");
        g2.recordAudit(1, true);
    }

    function test_OnlyOwnerSetsAuditor() public {
        vm.prank(address(0xBAD));
        vm.expectRevert("not owner");
        gw.setAuditor(address(0xBAD));
    }
}
