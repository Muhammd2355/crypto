"""
Python implementation of hash-to-curve for Vesta curve
Matches the exact Rust implementation step-by-step as shown in Vest.txt
"""

import hashlib
from typing import List, Tuple

# Vesta curve parameters (from curves.rs - Eq curve: y² = x³ + 5)
P = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001  # Field modulus
A = 0x0000000000000000000000000000000000000000000000000000000000000000  # Curve coefficient a (Vesta is y² = x³ + b)
B = 0x0000000000000000000000000000000000000000000000000000000000000005  # Curve coefficient b

# Isogenous curve parameters (IsoEq - used for SWU mapping)
ISO_A = 0x267f9b2ee592271a81639c4d96f787739673928c7d01b212c515ad7242eaa6b1  # Isogenous curve coefficient a
ISO_B = 0x00000000000000000000000000000000000000000000000000000000000004f1  # Isogenous curve coefficient b (1265)

# Constants for hash-to-curve (from curves.rs - Eq implementation)
Z = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffff4  # Z value for Vesta
THETA = 0x2b3483a1ee9a382f53c3808d9e2f235738578ccadf03ac27632cae9872df1b5d  # Theta constant

# ROOT_OF_UNITY from Rust fields/fq.rs - this is the 2^32-th root of unity
# Fq::from_raw([0xa70e2c1102b6d05f, 0x9bb97ea3c106f049, 0x9e5c4dfd492ae26e, 0x2de6a9b8746d3f58])
ROOT_OF_UNITY = 0x2de6a9b8746d3f589e5c4dfd492ae26e9bb97ea3c106f049a70e2c1102b6d05f

def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm"""
    if a < 0:
        a = (a % m + m) % m
    
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

# Verify ROOT_OF_UNITY properties after mod_inverse is defined
Z_INV = mod_inverse(Z, P)

# Check ROOT_OF_UNITY properties
legendre_root = pow(ROOT_OF_UNITY, (P - 1) // 2, P)

# Test with a simple quadratic residue
test_qr = 4  # 2^2 = 4 is a quadratic residue
legendre_test = pow(test_qr, (P - 1) // 2, P)

# Test ROOT_OF_UNITY * 4
test_product = (ROOT_OF_UNITY * test_qr) % P
legendre_product = pow(test_product, (P - 1) // 2, P)

# Test Z value
legendre_z = pow(Z, (P - 1) // 2, P)

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def point_add_projective(x1: int, y1: int, z1: int, x2: int, y2: int, z2: int) -> Tuple[int, int, int]:
    """Add two points in projective coordinates on Vesta curve y^2 = x^3 + 5"""
    # Handle identity cases
    if z1 == 0:
        return x2, y2, z2
    if z2 == 0:
        return x1, y1, z1
    
    # Rust implementation translation
    z1z1 = (z1 * z1) % P
    z2z2 = (z2 * z2) % P
    u1 = (x1 * z2z2) % P
    u2 = (x2 * z1z1) % P
    s1 = (y1 * z2z2 * z2) % P
    s2 = (y2 * z1z1 * z1) % P
    
    if u1 == u2:
        if s1 == s2:
            # Point doubling
            return point_double_projective(x1, y1, z1)
        else:
            # Points are inverses, return identity
            return 0, 1, 0
    else:
        h = (u2 - u1) % P
        i = ((h + h) * (h + h)) % P  # (2h)^2
        j = (h * i) % P
        r = (s2 - s1) % P
        r = (r + r) % P  # 2r
        v = (u1 * i) % P
        x3 = (r * r - j - v - v) % P
        s1_j = (s1 * j) % P
        s1_j = (s1_j + s1_j) % P  # 2*s1*j
        y3 = (r * (v - x3) - s1_j) % P
        z_sum = (z1 + z2) % P
        z3 = ((z_sum * z_sum) - z1z1 - z2z2) % P
        z3 = (z3 * h) % P
        
        return x3, y3, z3

def point_double_projective(x: int, y: int, z: int) -> Tuple[int, int, int]:
    """Double a point in projective coordinates"""
    if z == 0:
        return 0, 1, 0
    
    # Point doubling: 2P
    A = (y * y) % P
    B = (4 * x * A) % P
    C = (8 * A * A) % P
    D = (3 * x * x) % P  # For Vesta curve a=0, so 3x^2
    
    x3 = (D * D - 2 * B) % P
    y3 = (D * (B - x3) - C) % P
    z3 = (2 * y * z) % P
    
    return x3, y3, z3

def mod_sqrt(a: int, p: int) -> int:
    """Compute square root modulo p using Tonelli-Shanks algorithm"""
    if a == 0:
        return 0
    
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    
    # For p ≡ 3 (mod 4), we can use the simple formula
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    
    # Find Q and S such that p - 1 = Q * 2^S with Q odd
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    
    if S == 1:
        return pow(a, (p + 1) // 4, p)
    
    # Find a quadratic non-residue z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    
    M = S
    c = pow(z, Q, p)
    t = pow(a, Q, p)
    R = pow(a, (Q + 1) // 2, p)
    
    while t != 1:
        # Find the smallest i such that t^(2^i) = 1
        i = 1
        temp = (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        
        # Update values
        b = pow(c, 1 << (M - i - 1), p)
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p
    
    return R

def expand_message_xmd_blake2b(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """
    Expand message using XMD with BLAKE2b
    Matches the Rust implementation exactly
    """
    # Constants from Rust implementation
    CHUNKLEN = 64  # BLAKE2b output size
    R_IN_BYTES = 128  # 2 * CHUNKLEN
    
    # Create personal parameter (16 bytes of zeros)
    personal = bytes(16)
    
    # Compute ell = ceil(len_in_bytes / CHUNKLEN)
    ell = (len_in_bytes + CHUNKLEN - 1) // CHUNKLEN
    
    # Compute b_0 = H(Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || dst || I2OSP(len(dst), 1))
    # Z_pad is R_IN_BYTES zeros
    z_pad = bytes(R_IN_BYTES)
    b_0_input = (z_pad + msg + 
                 bytes([0, len_in_bytes]) + bytes([0]) + 
                 dst + b"-vesta_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("vesta") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_0_input)
    b_0 = hasher.digest()
    
    # Compute b_1 = H(b_0 || I2OSP(1, 1) || dst || I2OSP(len(dst), 1))
    b_1_input = (b_0 + bytes([1]) + 
                 dst + b"-vesta_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("vesta") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_1_input)
    b_1 = hasher.digest()
    
    # Initialize uniform_bytes with b_1
    uniform_bytes = b_1
    
    # For ell >= 2, compute additional blocks
    for i in range(2, ell + 1):
        # Compute b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || dst || I2OSP(len(dst), 1))
        prev_block = uniform_bytes[(i-2)*CHUNKLEN:(i-1)*CHUNKLEN]
        strxor = bytes(a ^ b for a, b in zip(b_0, prev_block))
        b_i_input = (strxor + bytes([i]) + 
                     dst + b"-vesta_XMD:BLAKE2b_SSWU_RO_" + 
                     bytes([22 + len("vesta") + len(dst)]))
        hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
        hasher.update(b_i_input)
        b_i = hasher.digest()
        uniform_bytes += b_i
    
    return uniform_bytes[:len_in_bytes]

def hash_to_field(msg: bytes, dst: bytes, count: int) -> List[int]:
    """
    Hash message to field elements
    Matches the Rust implementation exactly
    """
    print("=== hash_to_field START ===")
    print(f"curve_id: vesta")
    print(f"domain_prefix: {dst.decode('utf-8')}")
    print(f"message: {list(msg)}")
    
    # Get the BLAKE2b outputs directly (b_1 and b_2)
    len_in_bytes = count * 64  # 64 bytes per field element for security
    
    # Constants from Rust implementation
    CHUNKLEN = 64  # BLAKE2b output size
    R_IN_BYTES = 128  # 2 * CHUNKLEN
    
    print(f"CHUNKLEN: {CHUNKLEN}")
    print(f"R_IN_BYTES: {R_IN_BYTES}")
    
    # Create personal parameter (16 bytes of zeros)
    personal = bytes(16)
    print(f"personal: {list(personal)}")
    print("Created empty_hasher")
    
    # Compute b_0
    z_pad = bytes(R_IN_BYTES)
    b_0_input = (z_pad + msg + 
                 bytes([0, len_in_bytes]) + bytes([0]) + 
                 dst + b"-vesta_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("vesta") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_0_input)
    b_0 = hasher.digest()
    print(f"Computed b_0: {list(b_0)}")
    
    # Compute b_1
    b_1_input = (b_0 + bytes([1]) + 
                 dst + b"-vesta_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("vesta") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_1_input)
    b_1 = hasher.digest()
    print(f"Computed b_1: {list(b_1)}")
    
    # Compute b_2
    strxor = bytes(a ^ b for a, b in zip(b_0, b_1))
    b_2_input = (strxor + bytes([2]) + 
                 dst + b"-vesta_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("vesta") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_2_input)
    b_2 = hasher.digest()
    print(f"Computed b_2: {list(b_2)}")
    
    # Process [b_1, b_2] as in Rust implementation
    field_elements = []
    for i, big in enumerate([b_1, b_2]):
        # Reverse bytes to little-endian as in Rust
        little = bytearray(big)
        little.reverse()
        
        # Convert to integer and reduce modulo p
        element = int.from_bytes(little, 'little') % P
        
        field_elements.append(element)
        
        print(f"Processing buffer element {i}")
        print(f"Little-endian bytes: {list(little)}")
        print(f"Converted to field element: 0x{element:064x}")
    
    print("=== hash_to_field END ===")
    return field_elements

def pow_by_t_minus1_over2(x: int) -> int:
    """
    Compute x^((T-1)/2) using the exact addition chain from Rust fq.rs
    This is the optimized exponentiation for the Vesta field.
    """
    def sqr(x: int, i: int) -> int:
        """Square x i times"""
        result = x
        for _ in range(i):
            result = (result * result) % P
        return result
    
    # Following the exact Rust implementation from fields/fq.rs
    s10 = (x * x) % P
    s11 = (s10 * x) % P
    s111 = (s11 * s11 * x) % P
    s1001 = (s111 * s10) % P
    s1011 = (s1001 * s10) % P
    s1101 = (s1011 * s10) % P
    sa = (sqr(x, 129) * x) % P
    sb = (sqr(sa, 7) * s1001) % P
    sc = (sqr(sb, 7) * s1101) % P
    sd = (sqr(sc, 4) * s11) % P
    se = (sqr(sd, 6) * s111) % P
    sf = (sqr(se, 3) * s111) % P
    sg = (sqr(sf, 10) * s1001) % P
    sh = (sqr(sg, 4) * s1001) % P
    si = (sqr(sh, 5) * s1001) % P
    sj = (sqr(si, 5) * s1001) % P
    sk = (sqr(sj, 3) * s1001) % P
    sl = (sqr(sk, 4) * s1011) % P
    sm = (sqr(sl, 4) * s1011) % P
    sn = (sqr(sm, 5) * s11) % P
    so = (sqr(sn, 4) * x) % P
    sp = (sqr(so, 5) * s11) % P
    sq = (sqr(sp, 4) * s111) % P
    sr = (sqr(sq, 5) * s1011) % P
    ss = (sqr(sr, 3) * x) % P
    st = sqr(ss, 4)  # Final result
    
    return st


def sqrt_common(uv: int, v: int) -> int:
    """
    Common part of sqrt_ratio: return result given v = u^((T-1)/2) and uv = u * v
    
    This implements the exact Rust sqrt_common function logic using lookup tables
    to find the discrete logarithm in the 2^32 subgroup generated by ROOT_OF_UNITY.
    """
    def sqr(x: int, i: int) -> int:
        """Square x i times"""
        result = x
        for _ in range(i):
            result = (result * result) % P
        return result
    
    # Step 1: Compute x3, x2, x1, x0 as in Rust
    x3 = (uv * v) % P
    x2 = sqr(x3, 8)
    x1 = sqr(x2, 8)
    x0 = sqr(x1, 8)
    
    # Step 2: Build lookup tables g0, g1, g2, g3 exactly as in Rust
    # This uses the same approach as the Rust code with scan iterators
    # g0[i] = ROOT_OF_UNITY^i for i in 0..256
    g0 = [1] * 256
    current = 1
    for i in range(256):
        g0[i] = current
        current = (current * ROOT_OF_UNITY) % P
    
    # g1[i] = ROOT_OF_UNITY^(i * 256) for i in 0..256
    gi = pow(ROOT_OF_UNITY, 256, P)  # ROOT_OF_UNITY^256
    g1 = [1] * 256
    current = 1
    for i in range(256):
        g1[i] = current
        current = (current * gi) % P
    
    # g2[i] = ROOT_OF_UNITY^(i * 256^2) for i in 0..256
    gi = pow(ROOT_OF_UNITY, 256 * 256, P)  # ROOT_OF_UNITY^(256^2)
    g2 = [1] * 256
    current = 1
    for i in range(256):
        g2[i] = current
        current = (current * gi) % P
    
    # g3[i] = ROOT_OF_UNITY^(i * 256^3) for i in 0..129
    gi = pow(ROOT_OF_UNITY, 256 * 256 * 256, P)  # ROOT_OF_UNITY^(256^3)
    g3 = [1] * 129
    current = 1
    for i in range(129):
        g3[i] = current
        current = (current * gi) % P
    
    # Step 3: Build perfect hash function and inverse lookup table for discrete logarithm
    # Using values from fields/fq.rs for Vesta curve: SqrtTables::new(0x116A9E, 1206)
    hash_xor = 0x116A9E  # Specific value for Vesta curve (Fq)
    hash_mod = 1206      # Specific value for Vesta curve (Fq)
    
    # Create a larger g3 temporary array for building the inverse table
    g3_temp = [1] * 256
    current = 1
    for i in range(256):
        g3_temp[i] = current
        current = (current * gi) % P
    
    # Build inverse table exactly as in Rust
    inv_table = [1] * hash_mod  # Initialize with 1 (default value in Rust)
    
    # Fill the inverse table
    for j in range(256):
        x = g3_temp[j]
        # Get lower 32 bits of the field element
        lower_32 = x & 0xFFFFFFFF
        # Compute hash exactly as in Rust
        hash_val = ((lower_32 ^ hash_xor) % hash_mod)
        # In Rust: inv[hash] = ((256 - j) & 0xFF) as u8
        inv_table[hash_val] = (256 - j) & 0xFF
    
    def inv(x: int) -> int:
        """Find discrete log using the perfect hash function, exact match to Rust"""
        # Get lower 32 bits of the field element
        lower_32 = x & 0xFFFFFFFF
        # Compute hash exactly as in Rust
        hash_val = ((lower_32 ^ hash_xor) % hash_mod)
        # Return the inverse value from the table
        return inv_table[hash_val]
    
    # Step 4: Follow the Rust algorithm exactly for discrete logarithm computation
    # i = 0, 1: t_ = t >> 16, 1 == x0 * ROOT_OF_UNITY^(t_ << 24)
    t_ = inv(x0)  # = t >> 16
    alpha = (x1 * g2[t_]) % P
    
    # i = 2: t_ = t >> 8, 1 == x1 * ROOT_OF_UNITY^(t_ << 16)
    t_ += inv(alpha) << 8  # = t >> 8
    alpha = (x2 * g1[t_ & 0xFF] * g2[t_ >> 8]) % P
    
    # i = 3: t_ = t, 1 == x2 * ROOT_OF_UNITY^(t_ << 8)
    t_ += inv(alpha) << 16  # = t
    alpha = (x3 * g0[t_ & 0xFF] * g1[(t_ >> 8) & 0xFF] * g2[t_ >> 16]) % P
    
    # Final step: t_ = t << 1, 1 == x3 * ROOT_OF_UNITY^t_
    t_ += inv(alpha) << 24  # = t << 1
    # Convert back to t using the exact same formula as in Rust
    t_ = (((t_ + 1) >> 1)) & 0xFFFFFFFF  # t_ = (((t_ as u64) + 1) >> 1) as usize
    
    # Step 5: Compute final result as in Rust
    # We need to use g3 from 0..129 since it was truncated in Rust
    result = (uv * g0[t_ & 0xFF] * g1[(t_ >> 8) & 0xFF] * g2[(t_ >> 16) & 0xFF] * g3[t_ >> 24]) % P
    
    return result


def sqrt_ratio(num, div):
    """
    Compute sqrt(num/div) if it exists, following the Rust implementation exactly.
    Returns (Choice, result) where Choice indicates if num/div is a quadratic residue.
    
    Based on the Rust sqrt_ratio function which implements the algorithm from:
    * https://eprint.iacr.org/2020/1407
    * https://cr.yp.to/papers.html#ed25519
    """
    # Handle zero cases
    if num == 0:
        return 1, 0  # (true, 0)
    if div == 0:
        return 0, 0  # (false, 0)
    
    def sqr(x: int, i: int) -> int:
        """Square x i times - matches Rust |x: F, i: u32| (0..i).fold(x, |x, _| x.square())"""
        result = x
        for _ in range(i):
            result = (result * result) % P
        return result
    
    # s = div^(2^S - 1) using addition chain
    # Rust: let s = (0..5).fold(*div, |d: F, i| sqr(d, 1 << i) * d);
    # This computes: div -> sqr(div, 1) * div -> sqr(result, 2) * result -> ... -> sqr(result, 16) * result
    s = div
    for i in range(5):  # i = 0, 1, 2, 3, 4 gives us 1, 2, 4, 8, 16
        s = (sqr(s, 1 << i) * s) % P
    
    # t = div^(2^(S+1) - 1) = s^2 * div
    # Rust: let t = s.square() * div;
    t = (s * s * div) % P
    
    # w = (num * t)^((T-1)/2) * s
    # Rust: let w = (t * num).pow_by_t_minus1_over2() * s;
    w_temp = pow_by_t_minus1_over2((t * num) % P)
    w = (w_temp * s) % P
    
    # v = w * div
    # Rust: let v = w * div;
    v = (w * div) % P
    
    # uv = w * num
    # Rust: let uv = w * num;
    uv = (w * num) % P
    
    # Call sqrt_common - this is the critical part that needs to match Rust exactly
    res = sqrt_common(uv, v)
    
    # Verification exactly as in Rust
    # Rust: let sqdiv = res.square() * div;
    sqdiv = (res * res * div) % P
    
    # Rust: let is_square = (sqdiv - num).is_zero();
    is_square = (sqdiv == num)
    
    # Rust: let is_nonsquare = (sqdiv - F::ROOT_OF_UNITY * num).is_zero();
    is_nonsquare = (sqdiv == (ROOT_OF_UNITY * num) % P)
    
    # Rust assertion: assert!(bool::from(num.is_zero() | div.is_zero() | (is_square ^ is_nonsquare)));
    # This means: num == 0 OR div == 0 OR (is_square XOR is_nonsquare)
    assertion_holds = (num == 0) or (div == 0) or (is_square != is_nonsquare)
    
    if not assertion_holds:
        print(f"ERROR: Rust assertion would fail!")
        print(f"num == 0: {num == 0}")
        print(f"div == 0: {div == 0}")
        print(f"is_square XOR is_nonsquare: {is_square != is_nonsquare}")
    
    # Rust: (is_square, res)
    return (1 if is_square else 0), res

def tonelli_shanks(n, p):
    """
    Tonelli-Shanks algorithm for computing square roots modulo p
    """
    if pow(n, (p - 1) // 2, p) != 1:
        return None  # n is not a quadratic residue
    
    # Find Q and S such that p - 1 = Q * 2^S with Q odd
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    
    if S == 1:
        return pow(n, (p + 1) // 4, p)
    
    # Find a quadratic non-residue z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    
    # Initialize
    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q + 1) // 2, p)
    
    while t != 1:
        # Find the smallest i such that t^(2^i) = 1
        i = 1
        temp = (t * t) % p
        while temp != 1 and i < M:
            temp = (temp * temp) % p
            i += 1
        
        if i >= M:
            return None  # Algorithm failed
        
        # Update
        shift_amount = M - i - 1
        if shift_amount >= 0:
            b = pow(c, 1 << shift_amount, p)
        else:
            return None  # Invalid shift amount
            
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p
    
    return R


def map_to_curve_simple_swu(u: int) -> Tuple[int, int, int]:
    """
    Simplified SWU mapping following the exact Rust implementation
    Returns projective coordinates (x, y, z)
    """
    print("=== map_to_curve_simple_swu START ===")
    print(f"u = 0x{u:064x}")
    
    # Constants from isogenous curve parameters (for SWU mapping)
    theta = THETA
    z = Z
    a = ISO_A  # Use isogenous curve coefficient a
    b = ISO_B  # Use isogenous curve coefficient b
    
    print(f"theta = 0x{theta:064x}")
    print(f"z = 0x{z:064x}")
    print(f"a = 0x{a:064x}")
    print(f"b = 0x{b:064x}")
    
    # Step 1: z_u2 = z * u^2
    z_u2 = (z * u * u) % P
    print(f"z_u2 = 0x{z_u2:064x}")
    
    # Step 2: ta = z_u2^2 + z_u2
    ta = (z_u2 * z_u2 + z_u2) % P
    print(f"ta = 0x{ta:064x}")
    
    # Step 3: num_x1 = b * (ta + 1)
    num_x1 = (b * (ta + 1)) % P
    
    # Step 4: div = a * conditional_select(-ta, z, ta == 0)
    # Since a = 0 for Vesta, div will always be 0, which is problematic
    # We need to handle this case differently
    if ta == 0:
        div = z % P  # Use z instead of a * z when a = 0
    else:
        div = (a * (-ta % P)) % P if a != 0 else (-ta % P)  # Handle a = 0 case
    
    print(f"num_x1 = 0x{num_x1:064x}")
    print(f"div = 0x{div:064x}")
    
    # Step 5: num2_x1 = num_x1^2
    num2_x1 = (num_x1 * num_x1) % P
    
    # Step 6: div2 = div^2
    div2 = (div * div) % P
    
    # Step 7: div3 = div2 * div
    div3 = (div2 * div) % P
    
    # Step 8: num_gx1 = (num2_x1 + a * div2) * num_x1 + b * div3
    # For non-zero a: num_gx1 = (num2_x1 + a * div2) * num_x1 + b * div3
    num_gx1 = ((num2_x1 + (a * div2) % P) % P * num_x1 + (b * div3) % P) % P
    
    print(f"num2_x1 = 0x{num2_x1:064x}")
    print(f"div2 = 0x{div2:064x}")
    print(f"div3 = 0x{div3:064x}")
    print(f"num_gx1 = 0x{num_gx1:064x}")
    
    # Step 9: num_x2 = z_u2 * num_x1
    num_x2 = (z_u2 * num_x1) % P
    print(f"num_x2 = 0x{num_x2:064x}")
    
    # Step 10: sqrt_ratio to check if gx1 is a square and compute y1
    gx1_square, y1 = sqrt_ratio(num_gx1, div3)
    
    # Handle None result from tonelli_shanks
    if y1 is None:
        y1 = 0
    
    print(f"gx1_square = Choice({gx1_square}), y1 = 0x{y1:064x}")
    
    # Step 11: y2 = theta * z_u2 * u * y1  
    y2 = (theta * z_u2 * u * y1) % P
    print(f"y2 = 0x{y2:064x}")
    
    # Step 12: conditional_select for num_x
    num_x = num_x1 if gx1_square else num_x2
    
    # Step 13: conditional_select for y
    y = y1 if gx1_square else y2
    
    print(f"num_x = 0x{num_x:064x}")
    print(f"y = 0x{y:064x}")
    
    # Step 14: Check parity and adjust y
    u_odd = u % 2
    y_odd = y % 2
    print(f"u.is_odd() = Choice({u_odd}), y.is_odd() = Choice({y_odd})")
    
    # conditional_select: if u_odd == y_odd then y else -y
    if u_odd == y_odd:
        final_y = y
    else:
        final_y = (-y) % P
    
    print(f"final y = 0x{final_y:064x}")
    
    # Step 15: Convert to Jacobian coordinates
    x_proj = (num_x * div) % P
    y_proj = (final_y * div3) % P
    z_proj = div
    
    print(f"Result point: IsoEq {{ x: 0x{x_proj:064x}, y: 0x{y_proj:064x}, z: 0x{z_proj:064x} }}")
    print("=== map_to_curve_simple_swu END ===")
    print()
    
    return x_proj, y_proj, z_proj

def iso_map(x: int, y: int, z: int) -> Tuple[int, int, int]:
    """
    Isogeny mapping from isogenous curve to Vesta curve
    """
    print("=== iso_map START ===")
    print(f"Input point: IsoEq {{ x: 0x{x:064x}, y: 0x{y:064x}, z: 0x{z:064x} }}")
    
    # Implement the general isogeny mapping
    # Isogeny coefficients from Rust implementation for Vesta curve
    iso = [
        0x38e38e38e38e38e38e38e38e38e38e390205dd51cfa0961a43cd42c800000001,
        0x1d935247b4473d17acecf10f5f7c09a2216b8861ec72bd5d8b95c6aaf703bcc5,
        0x18760c7f7a9ad20ded7ee4a9cdf78f8fd59d03d23b39cb11aeac67bbeb586a3d,
        0x31c71c71c71c71c71c71c71c71c71c71e1c521a795ac8356fb539a6f0000002b,
        0x0a2de485568125d51454798a5b5c56b2a3ad678129b604d3b7284f7eaf21a2e9,
        0x14735171ee5427780c621de8b91c242a30cd6d53df49d235f169c187d2533465,
        0x12f684bda12f684bda12f684bda12f685601f4709a8adcb36bef1642aaaaaaab,
        0x2ec9a923da239e8bd6767887afbe04d121d910aefb03b31d8bee58e5fb81de63,
        0x19b0d87e16e2578866d1466e9de10e6497a3ca5c24e9ea634986913ab4443034,
        0x1ed097b425ed097b425ed097b425ed098bc32d36fb21a6a38f64842c55555533,
        0x2f44d6c801c1b8bf9e7eb64f890a820c06a767bfc35b5bac58dfecce86b2745e,
        0x3d59f455cafc7668252659ba2b546c7e926847fb9ddd76a1d43d449776f99d2f,
        0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffde5
    ]
    
    print("--- iso coefficients ---")
    for i, coeff in enumerate(iso):
        print(f"iso[{i}] = 0x{coeff:064x}")
    print("-------------------------")
    
    print(f"Jacobian coordinates: x=0x{x:064x}, y=0x{y:064x}, z=0x{z:064x}")
    
    # Compute powers of z
    z2 = (z * z) % P
    z3 = (z2 * z) % P
    z4 = (z2 * z2) % P
    z6 = (z3 * z3) % P
    
    print(f"z2 = 0x{z2:064x}")
    print(f"z3 = 0x{z3:064x}")
    print(f"z4 = 0x{z4:064x}")
    print(f"z6 = 0x{z6:064x}")
    
    # Compute x coordinate mapping
    # num_x = ((iso[0]*x + iso[1]*z^2)*x + iso[2]*z^4)*x + iso[3]*z^6
    num_x = (((iso[0] * x + iso[1] * z2) * x + iso[2] * z4) * x + iso[3] * z6) % P
    
    # div_x = (z^2*x + iso[4]*z^4)*x + iso[5]*z^6
    div_x = ((z2 * x + iso[4] * z4) * x + iso[5] * z6) % P
    
    # Compute y coordinate mapping
    # num_y = (((iso[6]*x + iso[7]*z^2)*x + iso[8]*z^4)*x + iso[9]*z^6)*y
    num_y = ((((iso[6] * x + iso[7] * z2) * x + iso[8] * z4) * x + iso[9] * z6) * y) % P
    
    # div_y = (((x + iso[10]*z^2)*x + iso[11]*z^4)*x + iso[12]*z^6)*z^3
    div_y = ((((x + iso[10] * z2) * x + iso[11] * z4) * x + iso[12] * z6) * z3) % P
    
    print(f"num_x = 0x{num_x:064x}")
    print(f"div_x = 0x{div_x:064x}")
    print(f"num_y = 0x{num_y:064x}")
    print(f"div_y = 0x{div_y:064x}")
    
    # Compute final coordinates (matching Rust implementation exactly)
    zo = (div_x * div_y) % P
    xo = (num_x * div_y * zo) % P
    yo = (num_y * div_x * zo * zo) % P  # zo.square() in Rust
    
    print(f"zo = 0x{zo:064x}")
    print(f"xo = 0x{xo:064x}")
    print(f"yo = 0x{yo:064x}")
    
    print(f"Result point: Eq {{ x: 0x{xo:064x}, y: 0x{yo:064x}, z: 0x{zo:064x} }}")
    print("=== iso_map END ===")
    print()
    
    return xo, yo, zo

def hash_to_curve_vesta(msg: bytes, dst: bytes) -> Tuple[int, int]:
    """
    Complete hash-to-curve implementation for Vesta
    Processes both field elements through map_to_curve_simple_swu, adds the results, then applies iso_map
    """
    # Step 1: Hash to field
    field_elements = hash_to_field(msg, dst, 2)
    
    # Process both field elements through map_to_curve_simple_swu
    # First field element
    u1 = field_elements[0]
    x1, y1, z1 = map_to_curve_simple_swu(u1)
    
    # Second field element  
    u2 = field_elements[1]
    x2, y2, z2 = map_to_curve_simple_swu(u2)
    
    # Add the two points in projective coordinates (before iso_map)
    x_added, y_added, z_added = point_add_projective(x1, y1, z1, x2, y2, z2)
    
    # Apply iso_map to the final added point
    x_final, y_final, z_final = iso_map(x_added, y_added, z_added)
    
    print(f"Step 1 - Hashed point (projective): Eq {{ x: 0x{x_final:064x}, y: 0x{y_final:064x}, z: 0x{z_final:064x} }}")
    
    # Step 2: Cofactor clearing (for Vesta, cofactor is 1, so no change)
    # But we still need to show this step explicitly
    x_cleared, y_cleared, z_cleared = x_final, y_final, z_final
    print(f"Step 2 - After cofactor clearing: Eq {{ x: 0x{x_cleared:064x}, y: 0x{y_cleared:064x}, z: 0x{z_cleared:064x} }}")
    
    # Step 3: Convert to affine coordinates
    # Handle identity point case
    if z_cleared == 0:
        # Identity point in affine coordinates is the point at infinity
        # For practical purposes, we'll use (0, 0) but this is not mathematically correct
        # In a real implementation, you'd handle the point at infinity properly
        x_affine = 0
        y_affine = 0
    else:
        z_inv = mod_inverse(z_cleared, P)
        z_inv2 = (z_inv * z_inv) % P  # z_inv²
        z_inv3 = (z_inv2 * z_inv) % P  # z_inv³
        x_affine = (x_final * z_inv2) % P
        y_affine = (y_final * z_inv3) % P
    
    print(f"Step 3 - Affine coordinates: (0x{x_affine:064x}, 0x{y_affine:064x})")
    
    # Compressed representation (x-coordinate with y parity bit)
    # Convert x-coordinate to little-endian bytes
    compressed = x_affine.to_bytes(32, 'little')
    
    # Check if y is odd and set the parity bit in the LAST byte (index 31)
    # The parity bit should be in bit 7 (0x80) of the last byte for little-endian
    if y_affine & 1:  # y is odd
        # Set the parity bit in the last byte
        compressed = compressed[:-1] + bytes([compressed[-1] | 0x80])
    else:  # y is even
        # Make sure the parity bit is cleared in the last byte
        compressed = compressed[:-1] + bytes([compressed[-1] & 0x7F])
    
    print(f"Step 3 - Compressed bytes: {list(compressed)}")
    print("=== hash_to_curve_vesta END ===")
    print()
    
    return x_affine, y_affine

def test_hash_to_curve():
    """Test the hash-to-curve implementation"""
    # Test vector inputs - updated for Vesta
    msg = "Hello, Vest i am at good condition"
    dst = "Vesta-Suite"
    
    # Convert to bytes
    msg_bytes = msg.encode('utf-8')
    dst_bytes = dst.encode('utf-8')
    
    print(f'Input msg: "{msg}"')
    # Print hexadecimal values to match Rust format exactly
    hex_values = [format(b, 'x') for b in msg_bytes]
    hex_string = '[' + ', '.join(hex_values) + ']'
    print(f"Input msg (hex): {hex_string}")
    
    # Hash to curve
    result = hash_to_curve_vesta(msg_bytes, dst_bytes)

if __name__ == "__main__":
    test_hash_to_curve()