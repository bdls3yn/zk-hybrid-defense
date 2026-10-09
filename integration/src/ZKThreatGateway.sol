// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  ZKThreatGateway — integrated ZK-HHCF + ThreatDetector (Dissertation §3.3)
 * @author Abdulhuseyn V. Agayev
 * @notice Single entry point that couples privacy-preserving transaction
 *         verification (Groth16 range proof + Poseidon commitment + CKKS
 *         ciphertext anchor) with adaptive on-chain threat scoring.
 *
 *  Integration properties (each one is enforced on-chain and unit-tested):
 *   I1  ZK nullifier = replay key.  The nullifier is an output of the proof
 *       (Poseidon(secret, chainId)), so the ThreatDetector replay registry is
 *       driven by a value whose uniqueness is cryptographically guaranteed.
 *   I2  Context binding.  The proof is bound to the CKKS ciphertext hash,
 *       msg.sender and block.chainid; it cannot be re-used with another
 *       ciphertext, by a front-runner, or on another chain.
 *   I3  Policy binding.  maxAmount is fixed by the contract (policyMax), not
 *       chosen by the prover.
 *   I4  Threat-gated verification.  Blocked / quarantined actors are rejected
 *       before the ~200k-gas pairing check is executed.
 *   I5  Graduated, adaptive response.  Cumulative score with saturation (100),
 *       linear time decay, ALERT (>=70) throttling and CRITICAL (>=90)
 *       quarantine — enforced on-chain, not only in the off-chain monitor.
 *   I6  No third-party griefing.  Scores are only ever assigned to msg.sender;
 *       detection functions are internal (cannot be called on a victim).
 */
interface IGuardedTransferVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[6] calldata pubSignals
    ) external view returns (bool);
}

contract ZKThreatGateway {
    // ── BN254 scalar field ─────────────────────────────────────────────
    uint256 internal constant SNARK_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ── Public-signal layout (circom: outputs first, then public inputs) ─
    uint256 internal constant PS_COMMITMENT = 0;
    uint256 internal constant PS_NULLIFIER  = 1;
    uint256 internal constant PS_MAX        = 2;
    uint256 internal constant PS_CIPHER     = 3;
    uint256 internal constant PS_ACTOR      = 4;
    uint256 internal constant PS_CHAIN      = 5;

    // ── Detection parameters (same values as ThreatDetector v3) ────────
    uint256 public constant DDOS_WINDOW       = 60;   // s
    uint256 public constant DDOS_MAX          = 10;   // requests / window
    uint256 public constant DDOS_BLOCK_SECS   = 300;  // s
    uint256 public constant SYBIL_WINDOW      = 20;   // blocks since first seen
    uint256 public constant SYBIL_MAX_FREQ    = 8;    // interactions in window

    uint8   public constant SCORE_DDOS        = 35;
    uint8   public constant SCORE_SYBIL       = 30;
    uint8   public constant SCORE_REPLAY      = 50;
    uint8   public constant SCORE_BAD_PROOF   = 20;   // invalid / mis-bound proof
    uint8   public constant SCORE_CAP         = 100;

    uint8   public constant ALERT             = 70;
    uint8   public constant CRITICAL          = 90;
    uint256 public constant ALERT_COOLDOWN    = 30;   // s between submissions at ALERT
    uint256 public constant QUARANTINE_SECS   = 1 days;
    uint256 public constant DECAY_PERIOD      = 120;  // s per score point
    uint256 public constant VERIFY_GAS_CAP    = 400_000;

    enum Status {
        Accepted,          // 0
        Quarantined,       // 1
        RateBlocked,       // 2  (DDoS block window)
        DDoS,              // 3
        Throttled,         // 4  (ALERT cooldown)
        PolicyMismatch,    // 5  (maxAmount != policyMax)
        ContextMismatch,   // 6  (cipherHash / actor / chainId binding)
        Replay,            // 7
        InvalidProof,      // 8
        Sybil,             // 9  (score cause only; Sybil alone does not reject)
        AuditFailure       // 10 (score cause only; set by the auditor after decryption)
    }

    struct Actor {
        // slot 0
        uint40 windowStart;
        uint40 blockedUntil;
        uint40 quarantinedUntil;
        uint40 lastScoreUpdate;
        uint40 lastAccepted;
        uint16 reqCount;
        uint8  score;
        bool   sybilFlagged;
        // slot 1
        uint64 firstSeenBlock;
        uint32 interactions;
    }

    struct Record {
        bytes32 cipherHash;   // keccak256(CKKS ciphertext) — off-chain anchor
        address actor;
        uint40  timestamp;
        uint8   audit;        // 0 = pending, 1 = consistent, 2 = inconsistent
    }

    address public owner;
    address public auditor;   // holder of the CKKS secret key (off-chain decryption)
    IGuardedTransferVerifier public immutable verifier;
    uint256 public policyMax;

    mapping(address => Actor)   public actors;
    mapping(uint256 => bool)    public usedNullifiers;
    mapping(uint256 => Record)  public records;      // Poseidon commitment => record

    uint256 public acceptedCount;
    uint256 public rejectedCount;

    // ── Events ─────────────────────────────────────────────────────────
    event TransactionAccepted(address indexed actor, uint256 indexed commitment, uint256 nullifier, bytes32 cipherHash);
    event TransactionRejected(address indexed actor, Status status, uint8 score);
    event ThreatScored(address indexed actor, Status cause, uint8 delta, uint8 newScore);
    event SybilDetected(address indexed actor, uint32 interactions);
    event ThreatAlert(address indexed actor, uint8 score);
    event ActorQuarantined(address indexed actor, uint40 until);
    event ActorReleased(address indexed actor);
    event PolicyUpdated(uint256 policyMax);
    event AuditorUpdated(address auditor);
    event AuditRecorded(uint256 indexed commitment, address indexed actor, bool consistent);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _verifier, uint256 _policyMax) {
        require(_verifier != address(0), "verifier=0");
        owner = msg.sender;
        verifier = IGuardedTransferVerifier(_verifier);
        policyMax = _policyMax;
        emit PolicyUpdated(_policyMax);
    }

    // ── Main entry point ───────────────────────────────────────────────
    /**
     * @notice Submit a confidential transaction.
     * @dev Never reverts on a detected threat, so that the threat score
     *      update is persisted on-chain (a revert would erase it).
     */
    function submit(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[6] calldata pub,
        bytes32 cipherHash
    ) external returns (Status) {
        Actor storage a = actors[msg.sender];
        _decay(a);

        // I4/I5 — quarantine and DDoS block are checked before any pairing work
        if (block.timestamp < a.quarantinedUntil) return _reject(a, Status.Quarantined);
        if (block.timestamp < a.blockedUntil)     return _reject(a, Status.RateBlocked);

        // DDoS — sliding window over submission attempts
        if (block.timestamp >= uint256(a.windowStart) + DDOS_WINDOW) {
            a.windowStart = uint40(block.timestamp);
            a.reqCount = 0;
        }
        unchecked { a.reqCount += 1; }
        if (a.reqCount > DDOS_MAX) {
            a.blockedUntil = uint40(block.timestamp + DDOS_BLOCK_SECS);
            _addScore(a, Status.DDoS, SCORE_DDOS);
            return _reject(a, Status.DDoS);
        }

        // Sybil — burst of interactions from a freshly seen address
        if (a.firstSeenBlock == 0) a.firstSeenBlock = uint64(block.number);
        unchecked { a.interactions += 1; }
        if (!a.sybilFlagged
            && a.interactions > SYBIL_MAX_FREQ
            && block.number - a.firstSeenBlock < SYBIL_WINDOW)
        {
            a.sybilFlagged = true;
            emit SybilDetected(msg.sender, a.interactions);
            _addScore(a, Status.Sybil, SCORE_SYBIL);
            if (block.timestamp < a.quarantinedUntil) return _reject(a, Status.Quarantined);
        }

        // I5 — ALERT level: adaptive throttling
        if (a.score >= ALERT && block.timestamp < uint256(a.lastAccepted) + ALERT_COOLDOWN) {
            return _reject(a, Status.Throttled);
        }

        // I3 — policy binding
        if (pub[PS_MAX] != policyMax) {
            _addScore(a, Status.PolicyMismatch, SCORE_BAD_PROOF);
            return _reject(a, Status.PolicyMismatch);
        }

        // I2 — context binding (ciphertext, sender, chain)
        if (pub[PS_CIPHER] != uint256(cipherHash) % SNARK_FIELD
            || pub[PS_ACTOR] != uint256(uint160(msg.sender))
            || pub[PS_CHAIN] != block.chainid)
        {
            _addScore(a, Status.ContextMismatch, SCORE_BAD_PROOF);
            return _reject(a, Status.ContextMismatch);
        }

        // I1 — ZK nullifier as replay key
        uint256 nf = pub[PS_NULLIFIER];
        if (usedNullifiers[nf]) {
            _addScore(a, Status.Replay, SCORE_REPLAY);
            return _reject(a, Status.Replay);
        }

        // Groth16 verification (most expensive step, executed last)
        bool ok;
        // Gas-capped call: a malformed (off-curve) proof makes the pairing
        // precompile consume all forwarded gas; capping bounds that cost.
        try verifier.verifyProof{gas: VERIFY_GAS_CAP}(pA, pB, pC, pub) returns (bool r) { ok = r; } catch { ok = false; }
        if (!ok) {
            _addScore(a, Status.InvalidProof, SCORE_BAD_PROOF);
            return _reject(a, Status.InvalidProof);
        }

        // Accept
        usedNullifiers[nf] = true;
        uint256 cm = pub[PS_COMMITMENT];
        records[cm] = Record({cipherHash: cipherHash, actor: msg.sender, timestamp: uint40(block.timestamp), audit: 0});
        a.lastAccepted = uint40(block.timestamp);
        unchecked { acceptedCount++; }
        emit TransactionAccepted(msg.sender, cm, nf, cipherHash);
        return Status.Accepted;
    }

    // ── Internal ───────────────────────────────────────────────────────
    function _reject(Actor storage a, Status s) internal returns (Status) {
        unchecked { rejectedCount++; }
        emit TransactionRejected(msg.sender, s, a.score);
        return s;
    }

    function _addScore(Actor storage a, Status cause, uint8 pts) internal {
        _addScoreTo(a, msg.sender, cause, pts);
    }

    function _addScoreTo(Actor storage a, address who, Status cause, uint8 pts) internal {
        uint256 s = uint256(a.score) + pts;
        uint8 ns = s > SCORE_CAP ? SCORE_CAP : uint8(s);
        uint8 old = a.score;
        a.score = ns;
        a.lastScoreUpdate = uint40(block.timestamp);
        emit ThreatScored(who, cause, pts, ns);

        if (old < ALERT && ns >= ALERT) emit ThreatAlert(who, ns);
        if (ns >= CRITICAL && block.timestamp >= a.quarantinedUntil) {
            a.quarantinedUntil = uint40(block.timestamp + QUARANTINE_SECS);
            emit ActorQuarantined(who, a.quarantinedUntil);
        }
    }

    // ── Audit (same-plaintext consistency, checked off-chain) ─────────
    /**
     * @notice Called by the auditor after decrypting the CKKS ciphertext of an
     *         accepted record. `consistent` is true iff (i) keccak256(ciphertext)
     *         equals the stored cipherHash and (ii) Poseidon(amount', secret')
     *         recomputed from the decrypted slots equals the on-chain commitment.
     *         An inconsistent record proves that the sender bound a range proof
     *         to a ciphertext of a different value; the sender is quarantined.
     */
    function recordAudit(uint256 commitment, bool consistent) external {
        require(msg.sender == auditor && auditor != address(0), "not auditor");
        Record storage r = records[commitment];
        require(r.actor != address(0), "unknown record");
        require(r.audit == 0, "already audited");
        r.audit = consistent ? 1 : 2;
        emit AuditRecorded(commitment, r.actor, consistent);
        if (!consistent) {
            Actor storage a = actors[r.actor];
            _decay(a);
            _addScoreTo(a, r.actor, Status.AuditFailure, SCORE_CAP);
        }
    }

    function setAuditor(address _auditor) external onlyOwner {
        auditor = _auditor;
        emit AuditorUpdated(_auditor);
    }

    /// @dev Lazy linear decay: one point per DECAY_PERIOD seconds of good behaviour.
    function _decay(Actor storage a) internal {
        if (a.score == 0) return;
        uint256 elapsed = block.timestamp - a.lastScoreUpdate;
        uint256 dec = elapsed / DECAY_PERIOD;
        if (dec == 0) return;
        a.score = dec >= a.score ? 0 : uint8(a.score - dec);
        a.lastScoreUpdate = uint40(a.lastScoreUpdate + dec * DECAY_PERIOD);
    }

    // ── Views ──────────────────────────────────────────────────────────
    function currentScore(address actor) external view returns (uint8) {
        Actor memory a = actors[actor];
        if (a.score == 0) return 0;
        uint256 dec = (block.timestamp - a.lastScoreUpdate) / DECAY_PERIOD;
        return dec >= a.score ? 0 : uint8(a.score - dec);
    }

    function riskLevel(address actor) external view returns (string memory) {
        uint8 s = this.currentScore(actor);
        if (block.timestamp < actors[actor].quarantinedUntil || s >= CRITICAL) return "CRITICAL";
        if (s >= ALERT) return "HIGH";
        if (s >= 40) return "MEDIUM";
        return "NORMAL";
    }

    // ── Admin ──────────────────────────────────────────────────────────
    function release(address actor) external onlyOwner {
        Actor storage a = actors[actor];
        a.quarantinedUntil = 0;
        a.blockedUntil = 0;
        a.score = 0;
        a.sybilFlagged = false;
        emit ActorReleased(actor);
    }

    function setPolicyMax(uint256 _policyMax) external onlyOwner {
        policyMax = _policyMax;
        emit PolicyUpdated(_policyMax);
    }

    function transferOwnership(address n) external onlyOwner {
        require(n != address(0), "owner=0");
        owner = n;
    }
}
