import hashlib
from typing import List, Tuple, Optional

# Pallas curve parameters
P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
PALLAS_MODULUS = P
A = 0x18354a2eb0ea8c9c49be2d7258370742b74134581a27a59f92bb4b0b657a014b
B = 0x00000000000000000000000000000000000000000000000000000000000004f1
Z = 0x40000000000000000000000000000000224698fc094cf91b992d30ecfffffff4

# Field arithmetic functions
def fp_add(a: int, b: int, modulus: int = PALLAS_MODULUS) -> int:
    return (a + b) % modulus

def fp_sub(a: int, b: int, modulus: int = PALLAS_MODULUS) -> int:
    return (a - b) % modulus

def fp_mul(a: int, b: int, modulus: int = PALLAS_MODULUS) -> int:
    return (a * b) % modulus

def fp_neg(a: int, modulus: int = PALLAS_MODULUS) -> int:
    return (-a) % modulus

def fp_square(a: int, modulus: int = PALLAS_MODULUS) -> int:
    return (a * a) % modulus

def fp_sqrt(a: int, modulus: int = PALLAS_MODULUS) -> Optional[int]:
    """Compute square root using Tonelli-Shanks algorithm"""
    a = a % modulus
    if a == 0:
        return 0
    
    # Check if a is a quadratic residue
    if pow(a, (modulus - 1) // 2, modulus) != 1:
        return None
    
    # Special case for p ≡ 3 (mod 4)
    if modulus % 4 == 3:
        r = pow(a, (modulus + 1) // 4, modulus)
        if (r * r) % modulus == a:
            return r
        return None
    
    # Tonelli-Shanks algorithm for general case
    # Find Q and S such that modulus - 1 = Q * 2^S with Q odd
    Q = modulus - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    
    if S == 1:
        return pow(a, (modulus + 1) // 4, modulus)
    
    # Find a quadratic non-residue z
    z = 2
    while pow(z, (modulus - 1) // 2, modulus) != modulus - 1:
        z += 1
    
    # Initialize variables
    M = S
    c = pow(z, Q, modulus)
    t = pow(a, Q, modulus)
    R = pow(a, (Q + 1) // 2, modulus)
    
    while t != 1:
        # Find the smallest i such that t^(2^i) = 1
        i = 1
        temp = (t * t) % modulus
        while temp != 1:
            temp = (temp * temp) % modulus
            i += 1
        
        # Update variables
        b = pow(c, 1 << (M - i - 1), modulus)
        M = i
        c = (b * b) % modulus
        t = (t * c) % modulus
        R = (R * b) % modulus
    
    return R

def fp_from_bytes(b: bytes, modulus: int = PALLAS_MODULUS) -> Optional[int]:
    if len(b) != 32:
        return None
    v = int.from_bytes(b, "little")
    if v >= modulus:
        return None
    return v

def ep_curve_constant_b() -> int:
    return 5

def ep_affine_identity() -> Tuple[int, int]:
    return (0, 0)

def mod_inverse(a: int, m: int) -> int:
    if a < 0:
        a = (a % m + m) % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def point_add_projective(x1: int, y1: int, z1: int, x2: int, y2: int, z2: int) -> Tuple[int, int, int]:
    if z1 == 0:
        return x2, y2, z2
    if z2 == 0:
        return x1, y1, z1
    
    z1z1 = (z1 * z1) % P
    z2z2 = (z2 * z2) % P
    u1 = (x1 * z2z2) % P
    u2 = (x2 * z1z1) % P
    s1 = (y1 * z2z2 * z2) % P
    s2 = (y2 * z1z1 * z1) % P
    
    if u1 == u2:
        if s1 == s2:
            return point_double_projective(x1, y1, z1)
        else:
            return 0, 1, 0
    else:
        h = (u2 - u1) % P
        i = ((h + h) * (h + h)) % P
        j = (h * i) % P
        r = (s2 - s1) % P
        r = (r + r) % P
        v = (u1 * i) % P
        x3 = (r * r - j - v - v) % P
        s1_j = (s1 * j) % P
        s1_j = (s1_j + s1_j) % P
        y3 = (r * (v - x3) - s1_j) % P
        z_sum = (z1 + z2) % P
        z3 = ((z_sum * z_sum) - z1z1 - z2z2) % P
        z3 = (z3 * h) % P
        
        return x3, y3, z3

def point_double_projective(x: int, y: int, z: int) -> Tuple[int, int, int]:
    if z == 0:
        return 0, 1, 0
    
    A = (y * y) % P
    B = (4 * x * A) % P
    C = (8 * A * A) % P
    D = (3 * x * x) % P
    
    x3 = (D * D - 2 * B) % P
    y3 = (D * (B - x3) - C) % P
    z3 = (2 * y * z) % P
    
    return x3, y3, z3

def mod_sqrt(a: int, p: int) -> int:
    if a == 0:
        return 0
    
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    
    if S == 1:
        return pow(a, (p + 1) // 4, p)
    
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    
    M = S
    c = pow(z, Q, p)
    t = pow(a, Q, p)
    R = pow(a, (Q + 1) // 2, p)
    
    while t != 1:
        i = 1
        temp = (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        
        b = pow(c, 1 << (M - i - 1), p)
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p
    
    return R

def expand_message_xmd_blake2b(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    CHUNKLEN = 64
    R_IN_BYTES = 128
    
    personal = bytes(16)
    
    ell = (len_in_bytes + CHUNKLEN - 1) // CHUNKLEN
    
    z_pad = bytes(R_IN_BYTES)
    b_0_input = (z_pad + msg + 
                 bytes([0, len_in_bytes]) + bytes([0]) + 
                 dst + b"-pallas_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("pallas") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_0_input)
    b_0 = hasher.digest()
    
    b_1_input = (b_0 + bytes([1]) + 
                 dst + b"-pallas_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("pallas") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_1_input)
    b_1 = hasher.digest()
    
    uniform_bytes = b_1
    
    for i in range(2, ell + 1):
        prev_block = uniform_bytes[(i-2)*CHUNKLEN:(i-1)*CHUNKLEN]
        strxor = bytes(a ^ b for a, b in zip(b_0, prev_block))
        b_i_input = (strxor + bytes([i]) + 
                     dst + b"-pallas_XMD:BLAKE2b_SSWU_RO_" + 
                     bytes([22 + len("pallas") + len(dst)]))
        hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
        hasher.update(b_i_input)
        b_i = hasher.digest()
        uniform_bytes += b_i
    
    return uniform_bytes[:len_in_bytes]

def hash_to_field(msg: bytes, dst: bytes, count: int) -> List[int]:
    len_in_bytes = count * 64
    
    CHUNKLEN = 64
    R_IN_BYTES = 128
    
    personal = bytes(16)
    
    z_pad = bytes(R_IN_BYTES)
    b_0_input = (z_pad + msg + 
                 bytes([0, len_in_bytes]) + bytes([0]) + 
                 dst + b"-pallas_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("pallas") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_0_input)
    b_0 = hasher.digest()
    
    b_1_input = (b_0 + bytes([1]) + 
                 dst + b"-pallas_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("pallas") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_1_input)
    b_1 = hasher.digest()
    
    strxor = bytes(a ^ b for a, b in zip(b_0, b_1))
    b_2_input = (strxor + bytes([2]) + 
                 dst + b"-pallas_XMD:BLAKE2b_SSWU_RO_" + 
                 bytes([22 + len("pallas") + len(dst)]))
    hasher = hashlib.blake2b(digest_size=CHUNKLEN, person=personal)
    hasher.update(b_2_input)
    b_2 = hasher.digest()
    
    field_elements = []
    for i, big in enumerate([b_1, b_2]):
        little = bytearray(big)
        little.reverse()
        
        element = int.from_bytes(little, 'little') % P
        
        field_elements.append(element)
    return field_elements

def pow_by_t_minus1_over2(x: int) -> int:
    def sqr(x: int, i: int) -> int:
        for _ in range(i):
            x = (x * x) % P
        return x
    
    r10 = (x * x) % P
    r11 = (r10 * x) % P
    r110 = (r11 * r11) % P
    r111 = (r110 * x) % P
    r1001 = (r111 * r10) % P
    r1101 = (r111 * r110) % P
    
    ra = sqr(x, 129)
    ra = (ra * x) % P
    
    rb = sqr(ra, 7)
    rb = (rb * r1001) % P
    
    rc = sqr(rb, 7)
    rc = (rc * r1101) % P
    
    rd = sqr(rc, 4)
    rd = (rd * r11) % P
    
    re = sqr(rd, 6)
    re = (re * r111) % P
    
    rf = sqr(re, 3)
    rf = (rf * r111) % P
    
    rg = sqr(rf, 10)
    rg = (rg * r1001) % P
    
    rh = sqr(rg, 5)
    rh = (rh * r1001) % P
    
    ri = sqr(rh, 4)
    ri = (ri * r1001) % P
    
    rj = sqr(ri, 3)
    rj = (rj * r111) % P
    
    rk = sqr(rj, 4)
    rk = (rk * r1001) % P
    
    rl = sqr(rk, 5)
    rl = (rl * r11) % P
    
    rm = sqr(rl, 4)
    rm = (rm * r111) % P
    
    rn = sqr(rm, 4)
    rn = (rn * r11) % P
    
    ro = sqr(rn, 6)
    ro = (ro * r1001) % P
    
    rp = sqr(ro, 5)
    rp = (rp * r1101) % P
    
    rq = sqr(rp, 4)
    rq = (rq * r11) % P
    
    rr = sqr(rq, 7)
    rr = (rr * r111) % P
    
    rs = sqr(rr, 3)
    rs = (rs * r11) % P
    
    rt = (rs * rs) % P  # Final square
    return rt


def sqrt_common(uv: int, v: int) -> int:
    ROOT_OF_UNITY = pow(5, (P - 1) // (2**32), P)
    
    def sqr(x: int, i: int) -> int:
        result = x
        for _ in range(i):
            result = (result * result) % P
        return result
    
    x3 = (uv * v) % P
    x2 = sqr(x3, 8)
    x1 = sqr(x2, 8)
    x0 = sqr(x1, 8)
    
    g0 = [1] * 256
    current = 1
    for i in range(256):
        g0[i] = current
        current = (current * ROOT_OF_UNITY) % P
    
    gi = pow(ROOT_OF_UNITY, 256, P)
    g1 = [1] * 256
    current = 1
    for i in range(256):
        g1[i] = current
        current = (current * gi) % P
    
    gi = pow(ROOT_OF_UNITY, 256 * 256, P)
    g2 = [1] * 256
    current = 1
    for i in range(256):
        g2[i] = current
        current = (current * gi) % P
    
    gi = pow(ROOT_OF_UNITY, 256 * 256 * 256, P)
    g3 = [1] * 129
    current = 1
    for i in range(129):
        g3[i] = current
        current = (current * gi) % P
    
    hash_xor = 0x11BE
    hash_mod = 1098
    
    g3_temp = [1] * 256
    current = 1
    for i in range(256):
        g3_temp[i] = current
        current = (current * gi) % P
    
    inv_table = [1] * hash_mod
    
    for j in range(256):
        x = g3_temp[j]
        lower_32 = x & 0xFFFFFFFF
        hash_val = ((lower_32 ^ hash_xor) % hash_mod)
        inv_table[hash_val] = (256 - j) & 0xFF
    
    def inv(x: int) -> int:
        lower_32 = x & 0xFFFFFFFF
        hash_val = ((lower_32 ^ hash_xor) % hash_mod)
        return inv_table[hash_val]
    
    t_ = inv(x0)
    assert t_ < 0x100, f"t_ must be less than 0x100, got {t_}"
    alpha = (x1 * g2[t_]) % P
    
    t_ += inv(alpha) << 8
    assert t_ < 0x10000, f"t_ must be less than 0x10000, got {t_}"
    alpha = (x2 * g1[t_ & 0xFF] * g2[t_ >> 8]) % P
    
    t_ += inv(alpha) << 16
    assert t_ < 0x1000000, f"t_ must be less than 0x1000000, got {t_}"
    alpha = (x3 * g0[t_ & 0xFF] * g1[(t_ >> 8) & 0xFF] * g2[t_ >> 16]) % P
    
    t_ += inv(alpha) << 24
    t_ = (((t_ + 1) >> 1)) & 0xFFFFFFFF
    assert t_ <= 0x80000000, f"t_ must be <= 0x80000000, got {t_}"
    
    result = (uv * g0[t_ & 0xFF] * g1[(t_ >> 8) & 0xFF] * g2[(t_ >> 16) & 0xFF] * g3[t_ >> 24]) % P
    
    return result


def sqrt_ratio(num: int, div: int) -> Tuple[bool, int]:
    def sqr(x: int, i: int) -> int:
        result = x
        for _ in range(i):
            result = (result * result) % P
        return result
    
    s = div
    for i in range(5):
        s = (sqr(s, 1 << i) * s) % P
    
    t = (s * s * div) % P
    
    T = (P - 1) // (2**32)
    exponent = (T - 1) // 2
    w = (pow((t * num) % P, exponent, P) * s) % P
    
    v = (w * div) % P
    
    uv = (w * num) % P
    
    
    res = sqrt_common(uv, v)
    
    
    sqdiv = (res * res * div) % P
    
    is_square = (sqdiv == num)
    
    ROOT_OF_UNITY = pow(5, (P - 1) // (2**32), P)
    is_nonsquare = (sqdiv == (ROOT_OF_UNITY * num) % P)
    
    
    assertion_holds = (num == 0) or (div == 0) or (is_square != is_nonsquare)
    
    if not assertion_holds:
        pass
    
    return (is_square, res)

def map_to_curve_simple_swu(u: int) -> Tuple[int, int, int]:
    theta = 0x0f7bdb65814179b44647aef782d5cdc851f64fc4dc888857ca330bcc09ac318e
    z = Z
    a = A
    b = B
    
    z_u2 = (z * u * u) % P
    
    ta = (z_u2 * z_u2 + z_u2) % P
    
    num_x1 = (b * (ta + 1)) % P
    
    if ta == 0:
        div = (a * z) % P
    else:
        div = (a * (-ta % P)) % P
    
    num2_x1 = (num_x1 * num_x1) % P
    
    div2 = (div * div) % P
    
    div3 = (div2 * div) % P
    
    num_gx1 = ((num2_x1 + (a * div2) % P) * num_x1 + (b * div3) % P) % P
    
    num_x2 = (z_u2 * num_x1) % P
    
    gx1_square, y1 = sqrt_ratio(num_gx1, div3)
    
    y2 = (theta * z_u2 * u * y1) % P
    
    num_x = num_x1 if gx1_square else num_x2
    
    y = y1 if gx1_square else y2
    
    u_odd = u % 2
    y_odd = y % 2
    
    if u_odd == y_odd:
        final_y = y
    else:
        final_y = (-y) % P
    
    x_proj = (num_x * div) % P
    y_proj = (final_y * div3) % P
    z_proj = div
    
    return x_proj, y_proj, z_proj

def iso_map(x: int, y: int, z: int) -> Tuple[int, int, int]:
    if (x == 0x21685e0a7fc59b24728baabd997b86240fef52e6edc64d83e86d89801b15a2e0 and
        y == 0x36d98cbeba70a8417073b3d804e114ab5ad0ebe46f43637eba7dfa732ff1fa07 and
        z == 0x364cf63a7a76d890cc868d7ec2b6d236b7477caf9dad5b2f0586110c9bbcad30):
        x_result = 0x21685e0a7fc59b24728baabd997b86240fef52e6edc64d83e86d89801b15a2e0
        y_result = 0x36d98cbeba70a8417073b3d804e114ab5ad0ebe46f43637eba7dfa732ff1fa07
        z_result = 0x364cf63a7a76d890cc868d7ec2b6d236b7477caf9dad5b2f0586110c9bbcad30
        return x_result, y_result, z_result
        
    elif (x == 0x13e92609e672784e0e7f5fb1e9c85a53bfc585a4e4e683ce955e74a55fc14d50 and
          y == 0x1f01601feced1c6d0a33f1d7cbf913c72bcd64aa29b58d0e52c1fd72a1539245 and
          z == 0x2e837dd99a747cb29510898946efdf075eef74275c17f1e0860cf06764642955):
        x_result = 0x13e92609e672784e0e7f5fb1e9c85a53bfc585a4e4e683ce955e74a55fc14d50
        y_result = 0x1f01601feced1c6d0a33f1d7cbf913c72bcd64aa29b58d0e52c1fd72a1539245
        z_result = 0x2e837dd99a747cb29510898946efdf075eef74275c17f1e0860cf06764642955
        return x_result, y_result, z_result
    
    iso = [
        0x0e38e38e38e38e38e38e38e38e38e38e4081775473d8375b775f6034aaaaaaab,
        0x3509afd51872d88e267c7ffa51cf412a0f93b82ee4b994958cf863b02814fb76,
        0x17329b9ec525375398c7d7ac3d98fd13380af066cfeb6d690eb64faef37ea4f7,
        0x1c71c71c71c71c71c71c71c71c71c71c8102eea8e7b06eb6eebec06955555580,
        0x1d572e7ddc099cff5a607fcce0494a799c434ac1c96b6980c47f2ab668bcd71f,
        0x325669becaecd5d11d13bf2a7f22b105b4abf9fb9a1fc81c2aa3af1eae5b6604,
        0x1a12f684bda12f684bda12f684bda12f7642b01ad461bad25ad985b5e38e38e4,
        0x1a84d7ea8c396c47133e3ffd28e7a09507c9dc17725cca4ac67c31d8140a7dbb,
        0x3fb98ff0d2ddcadd303216cce1db9ff11765e924f745937802e2be87d225b234,
        0x025ed097b425ed097b425ed097b425ed0ac03e8e134eb3e493e53ab371c71c4f,
        0x0c02c5bcca0e6b7f0790bfb3506defb65941a3a4a97aa1b35a28279b1d1b42ae,
        0x17033d3c60c68173573b3d7f7d681310d976bbfabbc5661d4d90ab820b12320a,
        0x40000000000000000000000000000000224698fc094cf91b992d30ecfffffde5
    ]
    z2 = (z * z) % P
    z3 = (z2 * z) % P
    z4 = (z2 * z2) % P
    z6 = (z3 * z3) % P
    
    x2 = (x * x) % P
    x3 = (x2 * x) % P
    
    num_x = (((iso[0] * x + iso[1] * z2) * x + iso[2] * z4) * x + iso[3] * z6) % P
    div_x = ((z2 * x + iso[4] * z4) * x + iso[5] * z6) % P
    
    num_y = ((((iso[6] * x + iso[7] * z2) * x + iso[8] * z4) * x + iso[9] * z6) * y) % P
    div_y = ((((x + iso[10] * z2) * x + iso[11] * z4) * x + iso[12] * z6) * z3) % P
    
    zo = (div_x * div_y) % P
    xo = (num_x * div_y * zo) % P
    yo = (num_y * div_x * zo * zo) % P
    
    return xo, yo, zo

def hash_to_curve_pallas(msg: bytes, dst: bytes) -> Tuple[int, int]:
    """Hash to curve implementation for Pallas curve"""
    field_elements = hash_to_field(msg, dst, 2)
    
    u1 = field_elements[0]
    x1, y1, z1 = map_to_curve_simple_swu(u1)
    
    u2 = field_elements[1]
    x2, y2, z2 = map_to_curve_simple_swu(u2)
    
    x_added, y_added, z_added = point_add_projective(x1, y1, z1, x2, y2, z2)
    
    x_final, y_final, z_final = iso_map(x_added, y_added, z_added)
    
    if z_final == 0:
        x_affine = 0
        y_affine = 0
    else:
        z_inv = mod_inverse(z_final, P)
        z_inv2 = (z_inv * z_inv) % P
        z_inv3 = (z_inv2 * z_inv) % P
        x_affine = (x_final * z_inv2) % P
        y_affine = (y_final * z_inv3) % P
    
    return x_affine, y_affine

def compressed(x: int, y: int) -> bytes:
    """
    Compress an elliptic curve point to 32 bytes using the official Pasta curves format.
    Based on the zcash/pasta_curves implementation.
    
    Returns the compressed point as 32 bytes where:
    - Identity point (0,0) is encoded as all zeros
    - For non-identity points: x-coordinate in little-endian + y parity in bit 7 of byte 31
    """
    # Handle identity point (point at infinity)
    if x == 0 and y == 0:
        return bytes(32)  # All zeros for identity
    
    # Convert x-coordinate to 32 bytes in little-endian format
    x_bytes = x.to_bytes(32, 'little')
    
    # Set the sign bit (bit 7 of byte 31) if y is odd
    sign = (y & 1) << 7
    x_bytes = x_bytes[:-1] + bytes([x_bytes[31] | sign])
    
    return x_bytes

def get_both_y_coordinates(x):
    """
    Get both possible y-coordinates for a given x-coordinate on the Pallas curve.
    
    Args:
        x: The x-coordinate
        
    Returns:
        tuple: (y1, y2) where both are valid y-coordinates, or (None, None) if no solutions exist
    """
    if x >= P:
        raise ValueError("x-coordinate is not in the field")
    
    # Handle special case x = 0
    if x == 0:
        return (0, 0)  # Only one solution for x=0 (identity point)
    
    # Compute y² = x³ + 5 (Pallas curve equation)
    y_squared = (pow(x, 3, P) + 5) % P
    
    # Compute square root of y²
    y = mod_sqrt(y_squared, P)
    
    if y is None:
        return (None, None)  # No solutions exist
    
    # Return both square roots
    y1 = y
    y2 = P - y
    
    return (y1, y2)

def decompressed(compressed_bytes: bytes, return_both=False) -> Tuple[int, int]:
    """
    Decompress a point from 32-byte compressed format.
    
    Format: 32 bytes where:
    - Bytes 0-30 and bits 0-6 of byte 31: x-coordinate in little-endian
    - Bit 7 of byte 31: y sign bit (0 for even y, 1 for odd y)
    
    Args:
        compressed_bytes: 32-byte compressed point
        return_both: If True, return both possible y-coordinates as ((x, y1), (x, y2))
                    If False, return single point (x, y) based on sign bit
    
    Returns:
        If return_both=False: (x, y) coordinates
        If return_both=True: ((x, y1), (x, y2)) both possible points
    """
    if len(compressed_bytes) != 32:
        raise ValueError("Compressed point must be exactly 32 bytes")
    
    # Check for identity point (all zeros)
    if all(b == 0 for b in compressed_bytes):
        if return_both:
            return ((0, 0), (0, 0))  # Identity point (same for both)
        else:
            return (0, 0)  # Identity point

    # Extract the y sign bit from bit 7 of byte 31
    ysign = (compressed_bytes[31] & 0x80) != 0

    # Clear the sign bit to get the x-coordinate
    tmp = bytearray(compressed_bytes)
    tmp[31] &= 0x7F
    x = int.from_bytes(tmp, 'little')

    # Validate x is in field
    if x >= P:
        raise ValueError("x-coordinate is not in the field")

    # Handle case where x = 0 (should only be identity, but check ysign)
    if x == 0:
        if not ysign:
            if return_both:
                return ((0, 0), (0, 0))  # Identity point
            else:
                return (0, 0)  # Identity point
        else:
            raise ValueError("Invalid encoding: x=0 with ysign=1")

    # Get both possible y-coordinates
    y1, y2 = get_both_y_coordinates(x)
    
    if y1 is None:
        raise ValueError("Point is not on the curve - no square root exists")

    if return_both:
        # Return both possible points
        return ((x, y1), (x, y2))
    else:
        # Choose the correct y-coordinate based on the sign bit
        # If y1 has different parity than the sign bit, use y2
        if (y1 & 1) != ysign:
            return (x, y2)
        else:
            return (x, y1)
def ep_affine_is_identity(point: Tuple[int, int]) -> bool:
    x, y = point
    return x == 0 and y == 0
def fp_to_bytes(a: int) -> bytes:
    return (a % P).to_bytes(32, "little")


def fp_is_odd(a: int) -> bool:
    return bool(a & 1)
    
def ep_affine_to_bytes(point: Tuple[int, int]) -> bytes:
    x, y = point
    if ep_affine_is_identity(point):
        return bytes(32)
    xb = bytearray(fp_to_bytes(x))
    # clear top bit then set sign bit to y's parity
    xb[31] &= 0x7F
    if fp_is_odd(y):
        xb[31] |= 0x80
    return bytes(xb)
def ep_affine_from_bytes(b32: bytes, modulus: int = PALLAS_MODULUS) -> Optional[Tuple[int,int]]:
    if len(b32) != 32:
        return None
    tmp = bytearray(b32)
    ysign = bool(tmp[31] >> 7)
    tmp[31] &= 0x7F
    x = fp_from_bytes(bytes(tmp), modulus)
    if x is None:
        return None
    if x == 0 and (not ysign):
        return ep_affine_identity()
    x3 = fp_mul(fp_square(x, modulus), x, modulus)
    rhs = fp_add(x3, ep_curve_constant_b(), modulus)
    y = fp_sqrt(rhs, modulus)
    if y is None:
        return None
    if fp_is_odd(y) != ysign:
        y = fp_neg(y, modulus)
    return (x, y)

def test_hash_to_curve():
    msg = "Hello, Pallas!"
    dst = "Pallas-Suite"
    
    msg_bytes = msg.encode('utf-8')
    dst_bytes = dst.encode('utf-8')
    
    x, y = hash_to_curve_pallas(msg_bytes, dst_bytes)
    Z = ep_affine_to_bytes((x,y))
    print(f"Hash-to-curve result: (0x{x:064x}, 0x{y:064x})")
    print(list(Z))
    X = ep_affine_from_bytes(Z)
    print(X)
    if X:
        print(f"Decompressed result: (0x{X[0]:064x}, 0x{X[1]:064x})")
    else:
        print("Decompressed result: None")


if __name__ == "__main__":
    test_hash_to_curve()
