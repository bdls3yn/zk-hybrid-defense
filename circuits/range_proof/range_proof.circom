pragma circom 2.0.0;

include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/bitify.circom";

template RangeProof(n) {
    signal input amount;
    signal input maxAmount;
    signal output valid;

    component n2b = Num2Bits(n);
    n2b.in <== amount;

    component lte = LessEqThan(n);
    lte.in[0] <== amount;
    lte.in[1] <== maxAmount;

    valid <== lte.out;
}

component main {public [maxAmount]} = RangeProof(32);

