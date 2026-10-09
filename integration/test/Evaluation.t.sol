// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {ZKThreatGateway} from "../src/ZKThreatGateway.sol";
import {GuardedTransferVerifier} from "../src/GuardedTransferVerifier.sol";
import {Fixtures} from "./Fixtures.sol";
import {EvalFixtures} from "./EvalFixtures.sol";

/// @notice §3.3 scenario evaluation executed on the EVM with real Groth16 proofs
///         (no Python re-implementation of the rules). Also measures two
///         evasion strategies that the per-address rules cannot detect.
contract EvaluationTest is Test {
    ZKThreatGateway gw;
    uint256 tp; uint256 fn; uint256 fp; uint256 tn;

    function setUp() public {
        vm.chainId(31337);
        vm.warp(1_760_000_000);
        vm.roll(1_000_000);
        gw = new ZKThreatGateway(address(new GuardedTransferVerifier()), 1000);
    }

    function _sub(address who, uint256[14] memory p, bytes32 ct) internal returns (ZKThreatGateway.Status s) {
        vm.prank(who);
        s = gw.submit([p[0], p[1]], [[p[2], p[3]], [p[4], p[5]]], [p[6], p[7]], [p[8], p[9], p[10], p[11], p[12], p[13]], ct);
    }
    function _who(uint256[14] memory p) internal pure returns (address) { return address(uint160(p[12])); }
    function _tick() internal { vm.roll(block.number + 1); vm.warp(block.timestamp + 12); }
    function _attack(string memory name, uint256 det, uint256 n) internal {
        tp += det; fn += n - det;
        console2.log(string.concat("  ", name, "  detected/total:"), det, n);
    }

    function test_Evaluation() public {
        uint256 det; uint256[14][] memory P; bytes32[] memory C;

        // Benign (40 distinct users)
        P = Fixtures.benign(); C = Fixtures.benignCt();
        for (uint256 i; i < P.length; i++) {
            _tick();
            if (_sub(_who(P[i]), P[i], C[i]) == ZKThreatGateway.Status.Accepted && gw.currentScore(_who(P[i])) == 0) tn++; else fp++;
        }
        console2.log("  benign  accepted/total:", tn, P.length);

        // Replay: resubmission of 15 already accepted proofs by their owners
        det = 0;
        for (uint256 i; i < 15; i++) { _tick(); if (_sub(_who(P[i]), P[i], C[i]) == ZKThreatGateway.Status.Replay) det++; }
        _attack("replay  ", det, 15);

        // Front-running: 10 third parties submit stolen proofs
        det = 0;
        for (uint256 i; i < 10; i++) {
            _tick(); address thief = address(uint160(0xBEEF00 + i));
            if (_sub(thief, P[15 + i], C[15 + i]) == ZKThreatGateway.Status.ContextMismatch && gw.currentScore(_who(P[15 + i])) == 0) det++;
        }
        _attack("frontrun", det, 10);

        (P, C) = EvalFixtures.swap(); det = 0;
        for (uint256 i; i < P.length; i++) { _tick(); if (_sub(_who(P[i]), P[i], keccak256(abi.encode("swap", i))) == ZKThreatGateway.Status.ContextMismatch) det++; }
        _attack("ct-swap ", det, P.length);

        (P, C) = EvalFixtures.xchain(); det = 0;
        for (uint256 i; i < P.length; i++) { _tick(); if (_sub(_who(P[i]), P[i], C[i]) == ZKThreatGateway.Status.ContextMismatch) det++; }
        _attack("x-chain ", det, P.length);

        (P, C) = EvalFixtures.policy(); det = 0;
        for (uint256 i; i < P.length; i++) { _tick(); if (_sub(_who(P[i]), P[i], C[i]) == ZKThreatGateway.Status.PolicyMismatch) det++; }
        _attack("policy  ", det, P.length);

        (P, C) = EvalFixtures.forged(); det = 0;
        for (uint256 i; i < P.length; i++) {
            _tick(); uint256[14] memory q = P[i]; q[6 + (i % 2)] ^= (i + 1);
            if (_sub(_who(q), q, C[i]) == ZKThreatGateway.Status.InvalidProof) det++;
        }
        _attack("forged  ", det, P.length);

        // DDoS: 5 attackers x 11 submissions in 44 s (spread over 33 blocks)
        (P, C) = EvalFixtures.ddos(); det = 0;
        for (uint256 a; a < 5; a++) {
            ZKThreatGateway.Status last;
            for (uint256 k; k < 11; k++) { vm.warp(block.timestamp + 4); vm.roll(block.number + 3); last = _sub(_who(P[a * 11 + k]), P[a * 11 + k], C[a * 11 + k]); }
            if (last == ZKThreatGateway.Status.DDoS) det++;
        }
        _attack("ddos    ", det, 5);

        // Sybil: 5 fresh addresses x 9 submissions in 9 consecutive blocks
        (P, C) = EvalFixtures.sybil(); det = 0;
        for (uint256 a; a < 5; a++) {
            for (uint256 k; k < 9; k++) { _tick(); _sub(_who(P[a * 9 + k]), P[a * 9 + k], C[a * 9 + k]); }
            (,,,,,,, bool flagged,,) = gw.actors(_who(P[a * 9]));
            if (flagged) det++;
        }
        _attack("sybil   ", det, 5);

        console2.log("  TP / FN / FP / TN:", tp, fn);
        console2.log("                    ", fp, tn);
        assertEq(fp, 0); assertEq(fn, 0);
    }

    /// Known limits (reported honestly in §3.3.4): attacks that stay below
    /// per-address thresholds are NOT detected by design.
    function test_EvasionLimits() public {
        (uint256[14][] memory P, bytes32[] memory C) = EvalFixtures.slowddos();
        uint256 acc;
        for (uint256 i; i < P.length; i++) { vm.warp(block.timestamp + 6); vm.roll(block.number + 3); if (_sub(_who(P[i]), P[i], C[i]) == ZKThreatGateway.Status.Accepted) acc++; }
        console2.log("  slow-rate DDoS (10 req/min) accepted/total:", acc, P.length);
        console2.log("  slow-rate DDoS final score:", gw.currentScore(_who(P[0])));
        assertEq(acc, P.length);

        (P, C) = EvalFixtures.multisybil(); acc = 0;
        for (uint256 i; i < P.length; i++) { if (i % 2 == 0) vm.roll(block.number + 1); if (_sub(_who(P[i]), P[i], C[i]) == ZKThreatGateway.Status.Accepted) acc++; }
        console2.log("  distributed Sybil (30 addr x 1 tx) accepted/total:", acc, P.length);
        assertEq(acc, P.length);
    }
}
