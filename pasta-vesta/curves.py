# pallas_vesta_consolidated_fixed.py
import secrets
import hashlib
from typing import Optional, Tuple, List, Union

# --- Field Constants ---
PALLAS_MODULUS = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
VESTA_MODULUS = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

# --- Field Element Functions ---
def fp_zero() -> int:
    return 0

def fp_one() -> int:
    return 1

def fp_from_int(value: int, modulus: int = PALLAS_MODULUS) -> int:
    return value % modulus

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

def fp_invert(a: int, modulus: int = PALLAS_MODULUS) -> Optional[int]:
    a = a % modulus
    if a == 0:
        return None
    # Use Fermat's little theorem (modulus is prime)
    return pow(a, modulus - 2, modulus)

def fp_is_zero(a: int) -> bool:
    return a % 1 == 0 and a == 0

def fp_is_odd(a: int) -> bool:
    return bool(a & 1)

def fp_sqrt(a: int, modulus: int = PALLAS_MODULUS) -> Optional[int]:
    """Tonelli-Shanks square root. Pallas/Vesta have p ≡ 1 (mod 4) so the
    simple (p+1)/4 shortcut does not apply; the full algorithm is required."""
    a = a % modulus
    if a == 0:
        return 0
    if pow(a, (modulus - 1) // 2, modulus) != 1:
        return None
    if modulus % 4 == 3:
        r = pow(a, (modulus + 1) // 4, modulus)
        return r if (r * r) % modulus == a else None
    # Tonelli-Shanks for p ≡ 1 (mod 4)
    Q, S = modulus - 1, 0
    while Q % 2 == 0:
        Q //= 2
        S += 1
    z = 2
    while pow(z, (modulus - 1) // 2, modulus) != modulus - 1:
        z += 1
    M = S
    c = pow(z, Q, modulus)
    t = pow(a, Q, modulus)
    R = pow(a, (Q + 1) // 2, modulus)
    while t != 1:
        i, tmp = 1, (t * t) % modulus
        while tmp != 1:
            tmp = (tmp * tmp) % modulus
            i += 1
        b = pow(c, 1 << (M - i - 1), modulus)
        M, c, t, R = i, (b * b) % modulus, (t * b * b) % modulus, (R * b) % modulus
    return R

def fp_to_bytes(a: int, modulus: int = PALLAS_MODULUS) -> bytes:
    return (a % modulus).to_bytes(32, "little")

def fp_from_bytes(b: bytes, modulus: int = PALLAS_MODULUS) -> Optional[int]:
    if len(b) != 32:
        return None
    v = int.from_bytes(b, "little")
    if v >= modulus:
        return None
    return v

def fp_random(modulus: int = PALLAS_MODULUS) -> int:
    # return a uniformly random field element (not cryptographically perfect sampling into prime field exact distribution,
    # but suitable for tests). Use secrets.randbelow(modulus) for better distribution if desired.
    return secrets.randbits(256) % modulus

# --- Curve Constants ---
def ep_curve_constant_b() -> int:
    return 5

def eq_curve_constant_b() -> int:
    return 5

# --- Point Functions (Jacobian projective) ---
PointProj = Tuple[int, int, int]  # (X, Y, Z)

def ep_identity() -> PointProj:
    return (0, 0, 0)

def ep_is_identity(point: PointProj) -> bool:
    _, _, z = point
    return z == 0

def ep_generator(modulus: int = PALLAS_MODULUS) -> PointProj:
    # Pallas/Vesta generator affine: x = -1, y = 2
    neg_one = (modulus - 1) % modulus
    two = 2 % modulus
    return (neg_one, two, 1)

# --- Correct Jacobian doubling (a = 0) ---
def ep_double(point: PointProj, modulus: int = PALLAS_MODULUS) -> PointProj:
    X1, Y1, Z1 = point
    if ep_is_identity(point):
        return ep_identity()

    # A = X1^2
    A = fp_square(X1, modulus)
    # B = Y1^2
    B = fp_square(Y1, modulus)
    # C = B^2
    C = fp_square(B, modulus)
    # D = 2 * ((X1 + B)^2 - A - C)
    X1_plus_B = fp_add(X1, B, modulus)
    D = fp_sub(fp_sub(fp_square(X1_plus_B, modulus), A, modulus), C, modulus)
    D = fp_add(D, D, modulus)
    # E = 3 * A
    E = (3 * A) % modulus
    # F = E^2
    F = fp_square(E, modulus)
    # X3 = F - 2*D
    X3 = fp_sub(fp_sub(F, D, modulus), D, modulus)
    # Y3 = E*(D - X3) - 8*C
    # compute 8*C
    fourC = fp_add(C, C, modulus)
    fourC = fp_add(fourC, fourC, modulus)  # 4*C
    eightC = fp_add(fourC, fourC, modulus)  # 8*C
    Y3 = fp_sub(fp_mul(E, fp_sub(D, X3, modulus), modulus), eightC, modulus)
    # Z3 = 2*Y1*Z1
    Z3 = fp_mul(fp_add(Y1, Y1, modulus), Z1, modulus)

    return (X3 % modulus, Y3 % modulus, Z3 % modulus)

# --- Correct Jacobian addition ---
def ep_add(a: PointProj, b: PointProj, modulus: int = PALLAS_MODULUS) -> PointProj:
    if ep_is_identity(a):
        return b
    if ep_is_identity(b):
        return a

    X1, Y1, Z1 = a
    X2, Y2, Z2 = b

    Z1Z1 = fp_square(Z1, modulus)
    Z2Z2 = fp_square(Z2, modulus)
    U1 = fp_mul(X1, Z2Z2, modulus)              # U1 = X1 * Z2^2
    U2 = fp_mul(X2, Z1Z1, modulus)              # U2 = X2 * Z1^2
    S1 = fp_mul(fp_mul(Y1, Z2Z2, modulus), Z2, modulus)  # S1 = Y1 * Z2^3
    S2 = fp_mul(fp_mul(Y2, Z1Z1, modulus), Z1, modulus)  # S2 = Y2 * Z1^3

    if U1 == U2:
        if S1 == S2:
            return ep_double(a, modulus)
        else:
            return ep_identity()

    H = fp_sub(U2, U1, modulus)                 # H = U2 - U1
    I = fp_square(fp_add(H, H, modulus), modulus) # I = (2*H)^2
    J = fp_mul(H, I, modulus)                    # J = H * I
    r = fp_sub(S2, S1, modulus)
    r = fp_add(r, r, modulus)                    # r = 2*(S2 - S1)
    V = fp_mul(U1, I, modulus)                   # V = U1 * I

    X3 = fp_sub(fp_sub(fp_square(r, modulus), J, modulus), fp_add(V, V, modulus), modulus)
    Y3 = fp_sub(fp_mul(r, fp_sub(V, X3, modulus), modulus), fp_mul(fp_add(S1, S1, modulus), J, modulus), modulus)
    Z1_plus_Z2 = fp_add(Z1, Z2, modulus)
    Z3 = fp_mul(fp_sub(fp_sub(fp_square(Z1_plus_Z2, modulus), Z1Z1, modulus), Z2Z2, modulus), H, modulus)

    return (X3 % modulus, Y3 % modulus, Z3 % modulus)

def ep_neg(point: PointProj, modulus: int = PALLAS_MODULUS) -> PointProj:
    X, Y, Z = point
    return (X, fp_neg(Y, modulus), Z)

# scalar multiplication: accept int or bytes (little-endian)
def ep_scalar_mul(point: PointProj, scalar: Union[int, bytes], modulus: int = PALLAS_MODULUS) -> PointProj:
    if isinstance(scalar, bytes):
        # assume little-endian bytes by default (match common conventions)
        s_int = int.from_bytes(scalar, "little")
    else:
        s_int = int(scalar)

    if s_int == 0:
        return ep_identity()

    acc = ep_identity()
    # process from most-significant bit downwards
    for i in range(s_int.bit_length() - 1, -1, -1):
        acc = ep_double(acc, modulus)
        if (s_int >> i) & 1:
            acc = ep_add(acc, point, modulus)
    return acc

# --- Affine helpers and serialization ---
def ep_to_affine(point: PointProj, modulus: int = PALLAS_MODULUS) -> Tuple[int, int]:
    X, Y, Z = point
    if ep_is_identity(point):
        return (0, 0)
    zinv = fp_invert(Z, modulus)
    if zinv is None:
        return (0, 0)
    zinv2 = fp_square(zinv, modulus)
    x_affine = fp_mul(X, zinv2, modulus)
    zinv3 = fp_mul(zinv2, zinv, modulus)
    y_affine = fp_mul(Y, zinv3, modulus)
    return (x_affine % modulus, y_affine % modulus)

def ep_affine_identity() -> Tuple[int, int]:
    return (0, 0)

def ep_affine_is_identity(point: Tuple[int, int]) -> bool:
    x, y = point
    return x == 0 and y == 0

def ep_affine_to_curve(point: Tuple[int, int], modulus: int = PALLAS_MODULUS) -> PointProj:
    x, y = point
    if ep_affine_is_identity(point):
        return ep_identity()
    return (x % modulus, y % modulus, 1)

def ep_affine_to_bytes(point: Tuple[int, int], modulus: int = PALLAS_MODULUS) -> bytes:
    x, y = point
    if ep_affine_is_identity(point):
        return bytes(32)
    xb = bytearray(fp_to_bytes(x, modulus))
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

# --- Vesta wrappers ---
def eq_generator() -> PointProj:
    return ep_generator(VESTA_MODULUS)

def eq_double(point: PointProj) -> PointProj:
    return ep_double(point, VESTA_MODULUS)

def eq_add(a: PointProj, b: PointProj) -> PointProj:
    return ep_add(a, b, VESTA_MODULUS)

def eq_neg(point: PointProj) -> PointProj:
    return ep_neg(point, VESTA_MODULUS)

def eq_scalar_mul(point: PointProj, scalar: Union[int, bytes]) -> PointProj:
    return ep_scalar_mul(point, scalar, VESTA_MODULUS)

def eq_to_affine(point: PointProj) -> Tuple[int, int]:
    return ep_to_affine(point, VESTA_MODULUS)

def eq_affine_to_bytes(point: Tuple[int, int]) -> bytes:
    return ep_affine_to_bytes(point, VESTA_MODULUS)

def eq_affine_from_bytes(b32: bytes) -> Optional[Tuple[int,int]]:
    return ep_affine_from_bytes(b32, VESTA_MODULUS)