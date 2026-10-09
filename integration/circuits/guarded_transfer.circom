pragma circom 2.0.0;

include "../../circuits/circomlib/circuits/poseidon.circom";
include "../../circuits/circomlib/circuits/comparators.circom";
include "../../circuits/circomlib/circuits/bitify.circom";

// GuardedTransfer — ZK-HHCF v2 integration circuit (Dissertation §3.3)
//
// Proves, without revealing `amount` or `secret`:
//   (1) 0 <= amount < 2^32 and amount <= maxAmount        (range policy)
//   (2) commitment = Poseidon(amount, secret)             (hiding, binding)
//   (3) nullifier  = Poseidon(secret, chainId)            (one-time, chain-bound)
// and binds the proof to the CKKS ciphertext hash, the sender address
// and the chain id, so the proof cannot be re-used with another
// ciphertext, by another sender, or on another chain.
template GuardedTransfer(n) {
    // private
    signal input amount;
    signal input secret;
    // public
    signal input maxAmount;
    signal input cipherHash;   // keccak256(CKKS ciphertext) mod p
    signal input actor;        // uint160(msg.sender)
    signal input chainId;      // block.chainid

    signal output commitment;
    signal output nullifier;

    // (1) range
    component aBits = Num2Bits(n);
    aBits.in <== amount;
    component mBits = Num2Bits(n);
    mBits.in <== maxAmount;
    component lte = LessEqThan(n);
    lte.in[0] <== amount;
    lte.in[1] <== maxAmount;
    lte.out === 1;

    // (2) commitment
    component c = Poseidon(2);
    c.inputs[0] <== amount;
    c.inputs[1] <== secret;
    commitment <== c.out;

    // (3) nullifier
    component nf = Poseidon(2);
    nf.inputs[0] <== secret;
    nf.inputs[1] <== chainId;
    nullifier <== nf.out;

    // bind public context into the constraint system (anti-malleability)
    signal cipherSq;
    signal actorSq;
    cipherSq <== cipherHash * cipherHash;
    actorSq  <== actor * actor;
}

component main {public [maxAmount, cipherHash, actor, chainId]} = GuardedTransfer(32);
