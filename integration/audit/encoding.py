"""Encoding of (amount, secret) into a CKKS-friendly real vector.
secret (< 2^248) is split into 16 limbs of 16 bits, so every slot is a small
integer that CKKS (scale 2^40) represents with error << 0.5 and rounding recovers it exactly."""
LIMB_BITS, N_LIMBS = 16, 16
MASK = (1 << LIMB_BITS) - 1

def encode(amount: int, secret: int):
    assert 0 <= amount < 2**32 and 0 <= secret < 2**(LIMB_BITS*N_LIMBS)
    return [float(amount)] + [float((secret >> (LIMB_BITS*i)) & MASK) for i in range(N_LIMBS)]

def decode(vec, tol=0.01):
    """Round decrypted CKKS slots; raise if any slot is not close to an integer."""
    ints = []
    for x in vec[:1+N_LIMBS]:
        r = round(x)
        if abs(x - r) > tol or r < 0:
            raise ValueError(f"slot not an integer within tolerance: {x}")
        ints.append(int(r))
    if ints[0] >= 1 << 32 or any(v >= 1 << LIMB_BITS for v in ints[1:]):
        raise ValueError("slot value outside the encoding range")
    amount = ints[0]
    secret = sum(v << (LIMB_BITS*i) for i, v in enumerate(ints[1:]))
    return amount, secret
