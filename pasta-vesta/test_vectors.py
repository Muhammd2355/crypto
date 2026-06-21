"""
Test vectors for Pallas and Vesta curve implementations.

Pallas: y^2 = x^3 + 5  over Fp, where
  p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
  r = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

Vesta: y^2 = x^3 + 5  over Fq = Fp[r], where
  q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
  r_v = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001

They form a 2-cycle: Pallas scalar field == Vesta base field and vice-versa.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from curves import (
    PALLAS_MODULUS, VESTA_MODULUS,
    ep_generator, ep_scalar_mul, ep_to_affine, ep_is_identity,
    eq_generator, eq_scalar_mul, eq_to_affine,
    ep_affine_to_bytes, eq_affine_to_bytes,
    ep_affine_from_bytes, eq_affine_from_bytes,
)
from hash_to_curve_pallas import hash_to_curve_pallas
from hash_to_curve_vesta import hash_to_curve_vesta

P = PALLAS_MODULUS
Q = VESTA_MODULUS

# ── Pallas generator ────────────────────────────────────────────────────────
PALLAS_GX = P - 1   # -1 mod p
PALLAS_GY = 2

# ── Vesta generator ─────────────────────────────────────────────────────────
VESTA_GX = Q - 1    # -1 mod q
VESTA_GY = 2

# ── 42*G test vectors (computed from this implementation) ───────────────────
PALLAS_42G_X = 0x0b261644865ca437ab190a8a5f7bd4f7519442cceb5702f51c6df26c79ed12f3
PALLAS_42G_Y = 0x22bdb304381804f4c9840948ce2d19077795e9767fd7b886051dd1613f63df4c

VESTA_42G_X = 0x368c7f1dafabb07518bc4cfa87f92ef98a33020567335f2091c42055de88a043
VESTA_42G_Y = 0x06e48f14acdcdc44d8058fca19d531af968cedcd1da27f4517f3d06887683477

# ── hash-to-curve test vectors (DST: z.cash:test-{curve}-v1) ────────────────
# Pallas
PALLAS_H2C = [
    {
        "msg": b"",
        "dst": b"z.cash:test-pallas-v1",
        "x": 0x1c163bae29cfcb7b6084452cca2ad6d3d7d563b13b6d2840e9d1b5e4769b7adc,
        "y": 0x1b6efd9102c1c07b6cf79ea3ea93f63eda7a8b108afff8602bad94442a254fd9,
    },
    {
        "msg": b"abc",
        "dst": b"z.cash:test-pallas-v1",
        "x": 0x056bc039e66c26d427e0c96b20611d02a7d7dc7134ef46d33aafe21cdbd410e8,
        "y": 0x29110373fe46680ddc78efc8e545ea7de9288b792f2e5a8fa205d0c162eef5fd,
    },
    {
        "msg": b"abcdef0123456789",
        "dst": b"z.cash:test-pallas-v1",
        "x": 0x3dcdcecfd32676e15928129ff382a5b9a24a4c446753536913c39078f8b32825,
        "y": 0x36b981b2f5f94133f0de18f23fd01baa5645031daee1cab06fd9e3102255011c,
    },
]

# Vesta
VESTA_H2C = [
    {
        "msg": b"",
        "dst": b"z.cash:test-vesta-v1",
        "x": 0x0c3c2c4151eeaf8376b851812a889c921d72571987434c0bf7e2db0d0f44e058,
        "y": 0x101f54072d7340aeb32f854733506551d93004993f0a0ea05ccd5c96aedec8a9,
    },
    {
        "msg": b"abc",
        "dst": b"z.cash:test-vesta-v1",
        "x": 0x11ad0ab7898e4dcacaabb99e65aa125b2ae11ec4ad56abe7d8d444f5ed0bc2e2,
        "y": 0x1441bbd63507584518626e68ba876beb2abe7ef55249ca2c72c189f31caf3b48,
    },
    {
        "msg": b"abcdef0123456789",
        "dst": b"z.cash:test-vesta-v1",
        "x": 0x300c08d5bc06ff616a977b1a85e458ad37475fc6ac2582d3d95f28e440bc07cd,
        "y": 0x29030270e1b463203538a2e1c62169cd6fb1049621f61c1727057b2f29f9de5c,
    },
]


def _on_pallas(x, y):
    return (y * y) % P == (pow(x, 3, P) + 5) % P


def _on_vesta(x, y):
    return (y * y) % Q == (pow(x, 3, Q) + 5) % Q


def test_generators():
    assert _on_pallas(PALLAS_GX, PALLAS_GY), "Pallas generator not on curve"
    assert _on_vesta(VESTA_GX, VESTA_GY), "Vesta generator not on curve"
    print("PASS  generators are on their respective curves")


def test_group_orders():
    G_p = (PALLAS_GX, PALLAS_GY, 1)
    r_p = Q  # Pallas scalar field order == Vesta base field modulus
    assert ep_is_identity(ep_scalar_mul(G_p, r_p, P)), "Pallas: r*G != identity"

    G_v = (VESTA_GX, VESTA_GY, 1)
    r_v = P  # Vesta scalar field order == Pallas base field modulus
    assert ep_is_identity(ep_scalar_mul(G_v, r_v, Q)), "Vesta: r*G != identity"
    print("PASS  group orders are correct (r*G = identity)")


def test_42G():
    G_p = (PALLAS_GX, PALLAS_GY, 1)
    x, y = ep_to_affine(ep_scalar_mul(G_p, 42, P), P)
    assert x == PALLAS_42G_X and y == PALLAS_42G_Y, f"Pallas 42*G mismatch: got ({x:#x}, {y:#x})"
    assert _on_pallas(x, y), "Pallas 42*G not on curve"

    G_v = (VESTA_GX, VESTA_GY, 1)
    xv, yv = ep_to_affine(ep_scalar_mul(G_v, 42, Q), Q)
    assert xv == VESTA_42G_X and yv == VESTA_42G_Y, f"Vesta 42*G mismatch: got ({xv:#x}, {yv:#x})"
    assert _on_vesta(xv, yv), "Vesta 42*G not on curve"
    print("PASS  42*G matches test vectors for both curves")


def test_point_serialization():
    G_p = (PALLAS_GX, PALLAS_GY, 1)
    pt = ep_to_affine(ep_scalar_mul(G_p, 42, P), P)
    compressed = ep_affine_to_bytes(pt)
    recovered = ep_affine_from_bytes(compressed)
    assert recovered == pt, f"Pallas round-trip serialization failed"

    G_v = (VESTA_GX, VESTA_GY, 1)
    pt_v = ep_to_affine(ep_scalar_mul(G_v, 42, Q), Q)
    compressed_v = eq_affine_to_bytes(pt_v)
    recovered_v = eq_affine_from_bytes(compressed_v)
    assert recovered_v == pt_v, f"Vesta round-trip serialization failed"
    print("PASS  point compression/decompression round-trips correctly")


def test_hash_to_curve_pallas():
    for tv in PALLAS_H2C:
        x, y = hash_to_curve_pallas(tv["msg"], tv["dst"])
        assert x == tv["x"] and y == tv["y"], (
            f"Pallas h2c mismatch for msg={tv['msg']!r}\n"
            f"  expected ({tv['x']:#x}, {tv['y']:#x})\n"
            f"  got      ({x:#x}, {y:#x})"
        )
        assert _on_pallas(x, y), "Pallas h2c point not on curve"
    print(f"PASS  Pallas hash-to-curve matches {len(PALLAS_H2C)} test vectors")


def test_hash_to_curve_vesta():
    for tv in VESTA_H2C:
        x, y = hash_to_curve_vesta(tv["msg"], tv["dst"])
        assert x == tv["x"] and y == tv["y"], (
            f"Vesta h2c mismatch for msg={tv['msg']!r}\n"
            f"  expected ({tv['x']:#x}, {tv['y']:#x})\n"
            f"  got      ({x:#x}, {y:#x})"
        )
        assert _on_vesta(x, y), "Vesta h2c point not on curve"
    print(f"PASS  Vesta hash-to-curve matches {len(VESTA_H2C)} test vectors")


if __name__ == "__main__":
    print("=" * 60)
    print("Pasta / Vesta curve test vectors")
    print("=" * 60)
    failures = 0
    for fn in [
        test_generators,
        test_group_orders,
        test_42G,
        test_point_serialization,
        test_hash_to_curve_pallas,
        test_hash_to_curve_vesta,
    ]:
        try:
            fn()
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
            failures += 1
        except Exception as e:
            print(f"ERROR {fn.__name__}: {e}")
            failures += 1

    print("=" * 60)
    if failures == 0:
        print("ALL TESTS PASSED")
    else:
        print(f"{failures} TEST(S) FAILED")
        sys.exit(1)
