// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IThreatDetector {
    function checkDDoS(address actor) external returns (bool);
    function checkSybil(address actor, uint256 acctAge) external returns (bool);
    function registerNullifier(bytes32 nullifier, uint256 deadline) external returns (bool);
}

contract AttackSimulator {
    IThreatDetector public td;
    constructor(address _td) { td = IThreatDetector(_td); }

    function simulateDDoS(address victim) external {
        for (uint i = 0; i < 11; i++) {
            try td.checkDDoS(victim) {} catch {}
        }
    }

    function simulateSybil(address victim) external {
        for (uint i = 0; i < 9; i++) {
            try td.checkSybil(victim, 3) {} catch {}
        }
    }

    function simulateReplay(bytes32 nullifier, uint256 deadline) external {
        try td.registerNullifier(nullifier, deadline) {} catch {}
        try td.registerNullifier(nullifier, deadline) {} catch {}
    }
}
