// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {ZKThreatGateway} from "../src/ZKThreatGateway.sol";
import {GuardedTransferVerifier} from "../src/GuardedTransferVerifier.sol";
import {Fixtures} from "./Fixtures.sol";

/// @notice Integration tests for ZK-HHCF + ThreatDetector (§3.3).
///         All proofs are REAL Groth16 proofs generated from guarded_transfer.circom.
contract ZKThreatGatewayTest is Test {
    ZKThreatGateway gw;
    GuardedTransferVerifier verifier;

    uint256 constant POLICY_MAX = 1000;

    function setUp() public {
        vm.chainId(31337);
        vm.warp(1_760_000_000);
        vm.roll(1_000_000);
        verifier = new GuardedTransferVerifier();
        gw = new ZKThreatGateway(address(verifier), POLICY_MAX);
    }

    // ── helpers ────────────────────────────────────────────────────────
    function _split(uint256[14] memory p)
        internal pure
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[6] memory pub)
    {
        a = [p[0], p[1]];
        b = [[p[2], p[3]], [p[4], p[5]]];
        c = [p[6], p[7]];
        pub = [p[8], p[9], p[10], p[11], p[12], p[13]];
    }

    function _actor(uint256[14] memory p) internal pure returns (address) {
        return address(uint160(p[12]));
    }

    function _submit(address who, uint256[14] memory p, bytes32 ct) internal returns (ZKThreatGateway.Status s) {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[6] memory pub) = _split(p);
        vm.prank(who);
        s = gw.submit(a, b, c, pub, ct);
    }

    function _score(address who) internal view returns (uint8) {
        return gw.currentScore(who);
    }

    // ── 0. fixture integrity ───────────────────────────────────────────
    function test_RealCkksCiphertextIsAnchored() public view {
        bytes memory ct = vm.readFileBinary("../python/ciphertext.bin");
        assertEq(ct.length, 334313, "CKKS ciphertext size (TenSEAL, N=8192)");
        assertEq(keccak256(ct), Fixtures.benignCt()[0], "proof #0 is bound to the real CKKS ciphertext");
    }

    // ── 1. benign traffic: no false positives ──────────────────────────
    function test_BenignTraffic_AllAccepted_NoFalsePositives() public {
        uint256[14][] memory P = Fixtures.benign();
        bytes32[] memory C = Fixtures.benignCt();
        for (uint256 i; i < P.length; i++) {
            vm.roll(block.number + 1);
            vm.warp(block.timestamp + 12);
            assertEq(uint8(_submit(_actor(P[i]), P[i], C[i])), uint8(ZKThreatGateway.Status.Accepted));
            assertEq(_score(_actor(P[i])), 0);
        }
        assertEq(gw.acceptedCount(), P.length);
        assertEq(gw.rejectedCount(), 0);
    }

    function test_AcceptedRecordStoresCommitmentAndCipherHash() public {
        uint256[14] memory p = Fixtures.benign()[0];
        bytes32 ct = Fixtures.benignCt()[0];
        _submit(_actor(p), p, ct);
        (bytes32 h, address who, uint40 ts, uint8 au) = gw.records(p[8]);
        assertEq(au, 0);
        assertEq(h, ct);
        assertEq(who, _actor(p));
        assertEq(ts, block.timestamp);
        assertTrue(gw.usedNullifiers(p[9]));
    }

    // ── 2. I1: ZK nullifier drives replay detection ────────────────────
    function test_Replay_SameProofRejectedAndScored() public {
        uint256[14] memory p = Fixtures.benign()[1];
        bytes32 ct = Fixtures.benignCt()[1];
        address u = _actor(p);
        assertEq(uint8(_submit(u, p, ct)), uint8(ZKThreatGateway.Status.Accepted));
        assertEq(uint8(_submit(u, p, ct)), uint8(ZKThreatGateway.Status.Replay));
        assertEq(_score(u), 50);
    }

    // ── 3. I2: context binding ─────────────────────────────────────────
    function test_FrontRunning_StolenProofRejected_OnlyThiefScored() public {
        uint256[14] memory p = Fixtures.benign()[2];
        bytes32 ct = Fixtures.benignCt()[2];
        address victim = _actor(p);
        address thief = address(0xBEEF);
        assertEq(uint8(_submit(thief, p, ct)), uint8(ZKThreatGateway.Status.ContextMismatch));
        assertEq(_score(thief), 20);
        assertEq(_score(victim), 0, "I6: victim is never scored");
        // victim can still use the proof (nullifier was not consumed)
        assertEq(uint8(_submit(victim, p, ct)), uint8(ZKThreatGateway.Status.Accepted));
    }

    function test_CiphertextSwap_Rejected() public {
        uint256[14] memory p = Fixtures.benign()[3];
        bytes32 other = keccak256("attacker-chosen ciphertext");
        assertEq(uint8(_submit(_actor(p), p, other)), uint8(ZKThreatGateway.Status.ContextMismatch));
    }

    function test_CrossChainReplay_Rejected_ThenValidOnSepolia() public {
        uint256[14] memory p = Fixtures.sepolia()[0];
        bytes32 ct = Fixtures.sepoliaCt()[0];
        assertEq(uint8(_submit(_actor(p), p, ct)), uint8(ZKThreatGateway.Status.ContextMismatch));
        vm.chainId(11155111);
        ZKThreatGateway gs = new ZKThreatGateway(address(verifier), POLICY_MAX);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[6] memory pub) = _split(p);
        vm.prank(_actor(p));
        assertEq(uint8(gs.submit(a, b, c, pub, ct)), uint8(ZKThreatGateway.Status.Accepted));
    }

    // ── 4. I3: policy is fixed by the contract ─────────────────────────
    function test_ProverChosenMaxAmount_Rejected() public {
        uint256[14] memory p = Fixtures.policy()[0];   // amount=1e9, maxAmount=2^32-1 (valid proof!)
        assertEq(p[10], 4294967295);
        assertEq(uint8(_submit(_actor(p), p, Fixtures.policyCt()[0])), uint8(ZKThreatGateway.Status.PolicyMismatch));
    }

    // ── 5. forged proofs ───────────────────────────────────────────────
    function test_ForgedProofElement_Rejected() public {
        uint256[14] memory p = Fixtures.benign()[4];
        p[6] = p[6] ^ 1; // tamper C.x
        assertEq(uint8(_submit(_actor(p), p, Fixtures.benignCt()[4])), uint8(ZKThreatGateway.Status.InvalidProof));
    }

    function test_TamperedCommitment_Rejected() public {
        uint256[14] memory p = Fixtures.benign()[5];
        p[8] = p[8] + 1; // claim a different commitment
        assertEq(uint8(_submit(_actor(p), p, Fixtures.benignCt()[5])), uint8(ZKThreatGateway.Status.InvalidProof));
    }

    function testFuzz_RandomPublicSignalsNeverAccepted(uint256 cm, uint256 nf, bytes32 ct) public {
        uint256[14] memory p = Fixtures.benign()[6];
        vm.assume(cm != p[8] || nf != p[9]);
        p[8] = cm % 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        p[9] = nf % 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        p[11] = uint256(ct) % 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        ZKThreatGateway.Status s = _submit(_actor(p), p, ct);
        assertTrue(s != ZKThreatGateway.Status.Accepted);
    }

    // ── 6. DDoS ────────────────────────────────────────────────────────
    function test_DDoS_BlockedAfter10_ThenRecovers() public {
        uint256[14][] memory P = Fixtures.ddos();
        bytes32[] memory C = Fixtures.ddosCt();
        address att = _actor(P[0]);
        for (uint256 i; i < 10; i++) {
            vm.warp(block.timestamp + 4);
            vm.roll(block.number + 3); // spread over >20 blocks: isolate DDoS from Sybil
            assertEq(uint8(_submit(att, P[i], C[i])), uint8(ZKThreatGateway.Status.Accepted));
        }
        vm.warp(block.timestamp + 4);
        assertEq(uint8(_submit(att, P[10], C[10])), uint8(ZKThreatGateway.Status.DDoS));
        assertEq(_score(att), 35);
        vm.warp(block.timestamp + 10);
        assertEq(uint8(_submit(att, P[10], C[10])), uint8(ZKThreatGateway.Status.RateBlocked));
        vm.warp(block.timestamp + 300);
        assertEq(uint8(_submit(att, P[10], C[10])), uint8(ZKThreatGateway.Status.Accepted));
    }

    function test_BlockedActor_RejectedBeforePairing_GasSaving() public {
        uint256[14][] memory P = Fixtures.ddos();
        bytes32[] memory C = Fixtures.ddosCt();
        address att = _actor(P[0]);
        for (uint256 i; i < 11; i++) { vm.roll(block.number + 3); _submit(att, P[i], C[i]); }
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[6] memory pub) = _split(P[11]);
        vm.prank(att);
        uint256 g0 = gasleft();
        ZKThreatGateway.Status s = gw.submit(a, b, c, pub, C[11]);
        uint256 used = g0 - gasleft();
        assertEq(uint8(s), uint8(ZKThreatGateway.Status.RateBlocked));
        console2.log("gas, rejected at threat gate:", used);
        assertLt(used, 30_000);
    }

    // ── 7. Sybil ───────────────────────────────────────────────────────
    function test_Sybil_BurstFromFreshAddressFlagged() public {
        uint256[14][] memory P = Fixtures.sybil();
        bytes32[] memory C = Fixtures.sybilCt();
        address s = _actor(P[0]);
        for (uint256 i; i < 9; i++) {
            vm.roll(block.number + 1);
            vm.warp(block.timestamp + 12); // 9 tx in 108 s: no DDoS
            assertEq(uint8(_submit(s, P[i], C[i])), uint8(ZKThreatGateway.Status.Accepted));
        }
        (,,,,,,, bool flagged,,) = gw.actors(s);
        assertTrue(flagged);
        assertEq(_score(s), 30);
    }

    function test_Sybil_SlowAddressNotFlagged() public {
        uint256[14][] memory P = Fixtures.sybil();
        bytes32[] memory C = Fixtures.sybilCt();
        address s = _actor(P[0]);
        for (uint256 i; i < 10; i++) {
            vm.roll(block.number + 5);
            vm.warp(block.timestamp + 60);
            _submit(s, P[i], C[i]);
        }
        (,,,,,,, bool flagged,,) = gw.actors(s);
        assertFalse(flagged);
        assertEq(_score(s), 0);
    }

    // ── 8. I5: graduated response ──────────────────────────────────────
    function test_Alert_ThrottlesThenRecovers() public {
        uint256[14][] memory P = Fixtures.esc();
        bytes32[] memory C = Fixtures.escCt();
        address u = _actor(P[0]);
        _submit(u, P[0], C[0]);                                  // accepted
        _submit(u, P[0], C[0]);                                  // replay  +50
        _submit(u, P[1], keccak256("swap"));                     // context +20 -> 70 ALERT
        assertEq(_score(u), 70);
        assertEq(gw.riskLevel(u), "HIGH");
        vm.warp(block.timestamp + 5);
        assertEq(uint8(_submit(u, P[1], C[1])), uint8(ZKThreatGateway.Status.Throttled));
        vm.warp(block.timestamp + 30);
        assertEq(uint8(_submit(u, P[1], C[1])), uint8(ZKThreatGateway.Status.Accepted));
    }

    function test_Critical_QuarantineThenDecayAndRelease() public {
        uint256[14][] memory P = Fixtures.esc();
        bytes32[] memory C = Fixtures.escCt();
        address u = _actor(P[0]);
        _submit(u, P[0], C[0]);
        _submit(u, P[0], C[0]); // 50
        _submit(u, P[0], C[0]); // 100 -> CRITICAL
        assertEq(_score(u), 100);
        assertEq(gw.riskLevel(u), "CRITICAL");
        assertEq(uint8(_submit(u, P[2], C[2])), uint8(ZKThreatGateway.Status.Quarantined));
        vm.warp(block.timestamp + 1 days + 1);
        assertEq(_score(u), 0, "score decays to 0 after 1 day of good behaviour");
        assertEq(uint8(_submit(u, P[2], C[2])), uint8(ZKThreatGateway.Status.Accepted));
    }

    function test_OwnerCanRelease() public {
        uint256[14][] memory P = Fixtures.esc();
        bytes32[] memory C = Fixtures.escCt();
        address u = _actor(P[0]);
        _submit(u, P[0], C[0]); _submit(u, P[0], C[0]); _submit(u, P[0], C[0]);
        gw.release(u);
        assertEq(uint8(_submit(u, P[3], C[3])), uint8(ZKThreatGateway.Status.Accepted));
        vm.prank(u);
        vm.expectRevert("not owner");
        gw.release(u);
    }

    function test_ScoreDecaysLinearly() public {
        uint256[14][] memory P = Fixtures.esc();
        bytes32[] memory C = Fixtures.escCt();
        address u = _actor(P[0]);
        _submit(u, P[4], C[4]); _submit(u, P[4], C[4]); // 50
        vm.warp(block.timestamp + 600); // 5 periods
        assertEq(_score(u), 45);
        assertEq(gw.riskLevel(u), "MEDIUM");
    }

    // ── 9. gas ─────────────────────────────────────────────────────────
    function test_Gas_AcceptedPath() public {
        uint256[14] memory p = Fixtures.benign()[7];
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[6] memory pub) = _split(p);
        vm.prank(_actor(p));
        uint256 g0 = gasleft();
        gw.submit(a, b, c, pub, Fixtures.benignCt()[7]);
        console2.log("gas, accepted path (execution):", g0 - gasleft());
    }
}
