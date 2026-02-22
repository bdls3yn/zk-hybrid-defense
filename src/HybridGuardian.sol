// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title HybridGuardian
 * @notice ZK-Homomorfik Hibrid Müdafiə Sistemi — Fəsil 3.1
 * @dev ZK sübutu + homomorfik şifrələnmiş məlumat inteqrasiyası
 *      Ethereum Sepolia Testnet
 */

interface IGroth16Verifier {
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[2] calldata _pubSignals
    ) external view returns (bool);
}

contract HybridGuardian {

    // ── State dəyişənləri ──────────────────────────────────────
    address public owner;
    IGroth16Verifier public verifier;
    uint256 public verifiedTxCount;
    uint256 public rejectedTxCount;

    // Homomorfik şifrələnmiş məlumatın on-chain saxlanması
    struct EncryptedRecord {
        bytes  ciphertext;      // TenSEAL ilə şifrələnmiş məlumat
        bytes32 commitment;     // ZK commitment (hash)
        uint256 timestamp;
        bool    verified;
    }

    mapping(address => EncryptedRecord[]) public records;
    mapping(bytes32 => bool) public usedCommitments; // replay attack qarşısı

    // ── Events ────────────────────────────────────────────────
    event TransactionVerified(
        address indexed sender,
        bytes32 commitment,
        uint256 timestamp
    );
    event TransactionRejected(
        address indexed sender,
        string reason
    );
    event ThreatDetected(
        address indexed sender,
        string threatType,
        uint256 timestamp
    );

    // ── Modifiers ─────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "HybridGuardian: not owner");
        _;
    }

    // ── Constructor ───────────────────────────────────────────
    constructor(address _verifier) {
        owner = msg.sender;
        verifier = IGroth16Verifier(_verifier);
    }

    /**
     * @notice ZK sübutu ilə şifrələnmiş tranzaksiyanı doğrula
     * @param _pA  Groth16 proof A
     * @param _pB  Groth16 proof B
     * @param _pC  Groth16 proof C
     * @param _pubSignals [valid, maxAmount]
     * @param _ciphertext Homomorfik şifrələnmiş məlumat (TenSEAL)
     */
    function submitVerifiedTransaction(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[2] calldata _pubSignals,
        bytes calldata _ciphertext
    ) external returns (bool) {

        // 1. ZK sübutunu yoxla
        bool isValid = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        if (!isValid) {
            rejectedTxCount++;
            emit TransactionRejected(msg.sender, "Invalid ZK proof");
            return false;
        }

        // 2. valid == 1 olmalıdır
        require(_pubSignals[0] == 1, "HybridGuardian: amount out of range");

        // 3. Commitment yarad — replay attack qarşısı
        bytes32 commitment = keccak256(
            abi.encodePacked(msg.sender, _ciphertext, block.timestamp)
        );
        require(!usedCommitments[commitment], "HybridGuardian: replay detected");
        usedCommitments[commitment] = true;

        // 4. Şifrələnmiş məlumatı saxla
        records[msg.sender].push(EncryptedRecord({
            ciphertext:  _ciphertext,
            commitment:  commitment,
            timestamp:   block.timestamp,
            verified:    true
        }));

        verifiedTxCount++;
        emit TransactionVerified(msg.sender, commitment, block.timestamp);
        return true;
    }

    /**
     * @notice Ünvanın bütün şifrələnmiş qeydlərini qaytar
     */
    function getRecords(address _addr)
        external view returns (EncryptedRecord[] memory)
    {
        return records[_addr];
    }

    /**
     * @notice Statistika
     */
    function getStats() external view returns (uint256 verified, uint256 rejected) {
        return (verifiedTxCount, rejectedTxCount);
    }
}

