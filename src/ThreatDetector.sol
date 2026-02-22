// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatDetector v2
 * @notice Gas-optimized. DDoS + Sybil + Replay aşkarlama.
 * @dev Dissertasiya Fəsil 3, Bölmə 3.2
 */
contract ThreatDetector {

    // ── STORAGE (minimal) ──────────────────────────────────
    address public owner;

    // DDoS
    mapping(address => uint256) public windowStart;
    mapping(address => uint256) public reqCount;
    mapping(address => uint256) public blockedUntil;

    // Sybil
    mapping(address => uint256) public firstSeenBlock;
    mapping(address => uint256) public interactions;
    mapping(address => bool)    public sybilFlagged;

    // Replay
    mapping(bytes32 => bool)    public usedNullifiers;

    // Threat Score
    mapping(address => uint8)   public threatScore;

    // ── SABITLƏR ──────────────────────────────────────────
    uint256 constant DDOS_WINDOW     = 60;
    uint256 constant DDOS_MAX        = 10;
    uint256 constant DDOS_BLOCK_SECS = 300;
    uint256 constant SYBIL_MIN_AGE   = 50;
    uint256 constant SYBIL_MAX_FREQ  = 8;
    uint256 constant SYBIL_WINDOW    = 20;

    // ── EVENTS ─────────────────────────────────────────────
    event DDoSDetected   (address indexed actor, uint256 count);
    event SybilDetected  (address indexed actor);
    event ReplayDetected (bytes32 indexed nullifier, address indexed actor);
    event ThreatBlocked  (address indexed actor, uint256 until);

    // ── MODIFIER ───────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ── 1. DDoS ────────────────────────────────────────────
    function checkDDoS(address actor) external returns (bool) {
        // Pəncərə bitibsə sıfırla
        if (block.timestamp >= windowStart[actor] + DDOS_WINDOW) {
            windowStart[actor] = block.timestamp;
            reqCount[actor]    = 0;
        }

        reqCount[actor]++;

        if (reqCount[actor] > DDOS_MAX) {
            blockedUntil[actor] = block.timestamp + DDOS_BLOCK_SECS;
            _score(actor, 35);
            emit DDoSDetected(actor, reqCount[actor]);
            emit ThreatBlocked(actor, blockedUntil[actor]);
            return true;
        }
        return false;
    }

    // ── 2. Sybil ───────────────────────────────────────────
    function checkSybil(address actor, uint256 acctAge) external returns (bool) {
        if (firstSeenBlock[actor] == 0) {
            firstSeenBlock[actor] = block.number;
        }
        interactions[actor]++;

        bool tooNew  = acctAge < SYBIL_MIN_AGE;
        bool tooFast = interactions[actor] > SYBIL_MAX_FREQ &&
                       (block.number - firstSeenBlock[actor]) < SYBIL_WINDOW;

        if (tooNew && tooFast && !sybilFlagged[actor]) {
            sybilFlagged[actor] = true;
            _score(actor, 30);
            emit SybilDetected(actor);
            return true;
        }
        return false;
    }

    // ── 3. Replay ──────────────────────────────────────────
    function registerNullifier(bytes32 nullifier, uint256 deadline)
        external returns (bool)
    {
        require(block.timestamp <= deadline, "expired");

        if (usedNullifiers[nullifier]) {
            _score(msg.sender, 50);
            emit ReplayDetected(nullifier, msg.sender);
            return false;   // revert yox — event yazılsın
        }

        usedNullifiers[nullifier] = true;
        return true;
    }

    // ── 4. Kompozit yoxlama ────────────────────────────────
    function assessThreat(
        address actor,
        bytes32 nullifier,
        uint256 acctAge,
        uint256 deadline
    ) external returns (bool) {
        require(block.timestamp >= blockedUntil[actor], "blocked");
        this.checkDDoS(actor);
        this.checkSybil(actor, acctAge);
        this.registerNullifier(nullifier, deadline);
        return true;
    }

    // ── INTERNAL ───────────────────────────────────────────
    function _score(address actor, uint8 pts) internal {
        uint8 s = threatScore[actor];
        threatScore[actor] = s + pts > 100 ? 100 : s + pts;
    }

    // ── ADMIN ──────────────────────────────────────────────
    function reset(address actor) external onlyOwner {
        threatScore[actor]  = 0;
        blockedUntil[actor] = 0;
        reqCount[actor]     = 0;
        sybilFlagged[actor] = false;
        interactions[actor] = 0;
        firstSeenBlock[actor] = 0; 
    }

    // ── VIEW ───────────────────────────────────────────────
    function getSummary(address actor) external view returns (
        uint8   score,
        bool    blocked,
        uint256 reqs,
        bool    sybil,
        uint256 txCount
    ) {
        return (
            threatScore[actor],
            block.timestamp < blockedUntil[actor],
            reqCount[actor],
            sybilFlagged[actor],
            interactions[actor]
        );
    }
}
