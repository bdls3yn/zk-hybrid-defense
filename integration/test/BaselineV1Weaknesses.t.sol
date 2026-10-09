// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {HybridGuardian} from "v1/HybridGuardian.sol";
import {Groth16Verifier} from "v1/RangeProofVerifier.sol";
import {ThreatDetector} from "v1/ThreatDetector.sol";
import {Fixtures} from "./Fixtures.sol";

/// @notice Documents, with REAL proofs against the deployed v1 contracts, the
///         weaknesses of the stand-alone design that ZKThreatGateway removes.
///         These tests PASS when the weakness is present (they are evidence,
///         not regressions).
contract BaselineV1WeaknessesTest is Test {
    HybridGuardian hg;
    Groth16Verifier v1;
    ThreatDetector td;

    function setUp() public {
        v1 = new Groth16Verifier();
        hg = new HybridGuardian(address(v1));
        td = new ThreatDetector();
    }

    function _old(uint256[10] memory p)
        internal pure
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[2] memory pub)
    {
        a = [p[0], p[1]];
        b = [[p[2], p[3]], [p[4], p[5]]];
        c = [p[6], p[7]];
        pub = [p[8], p[9]];
    }

    function test_V1_LegitProof_GasBaseline() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[2] memory pub) = _old(Fixtures.old_legit());
        uint256 g0 = gasleft();
        bool ok = hg.submitVerifiedTransaction(a, b, c, pub, keccak256("ct-1"));
        console2.log("gas, v1 HybridGuardian accepted path (execution):", g0 - gasleft());
        assertTrue(ok);
    }

    /// W1: maxAmount is a prover-chosen public input — a 1e9 amount passes.
    function test_V1_W1_ProverChosenLimitAccepted() public {
        uint256[10] memory p = Fixtures.old_inflated();
        assertEq(p[9], 4294967295);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[2] memory pub) = _old(p);
        assertTrue(hg.submitVerifiedTransaction(a, b, c, pub, keccak256("ct-2")));
    }

    /// W2: proof is not bound to the ciphertext — one proof, unlimited submissions.
    function test_V1_W2_ProofReusableWithAnyCiphertext() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[2] memory pub) = _old(Fixtures.old_legit());
        for (uint256 i; i < 5; i++) {
            vm.prank(address(uint160(0x9000 + i))); // also not bound to sender
            assertTrue(hg.submitVerifiedTransaction(a, b, c, pub, keccak256(abi.encode(i))));
        }
        (uint256 verified,) = hg.getStats();
        assertEq(verified, 5);
    }

    /// W3: detection entry points are public — anyone can get a victim blocked.
    function test_V1_W3_ThirdPartyGriefing() public {
        address victim = address(0xA11CE);
        for (uint256 i; i < 11; i++) td.checkDDoS(victim); // called by the attacker
        (uint8 score, bool blocked,,,) = td.getSummary(victim);
        assertTrue(blocked);
        assertEq(score, 35);
    }

    /// W4: in assessThreat the replay score is credited to the contract, not the actor.
    function test_V1_W4_ReplayScoreMisattributed() public {
        address actor = address(0xB0B);
        bytes32 nf = keccak256("nf");
        td.assessThreat(actor, nf, 100, block.timestamp + 1);
        td.assessThreat(actor, nf, 100, block.timestamp + 1);
        (uint8 actorScore,,,,) = td.getSummary(actor);
        (uint8 selfScore,,,,) = td.getSummary(address(td));
        assertEq(actorScore, 0, "actor not penalised");
        assertEq(selfScore, 50, "score went to ThreatDetector itself");
    }

    /// W5: Sybil account age is caller-supplied and can be spoofed.
    function test_V1_W5_SpoofedAccountAgeEvadesSybil() public {
        address s = address(0x5B);
        for (uint256 i; i < 20; i++) td.checkSybil(s, 1_000_000);
        (, , , bool sybil,) = td.getSummary(s);
        assertFalse(sybil);
    }
}
