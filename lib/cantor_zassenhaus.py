from lib.finite_field import FFPoly
from lib.polynomial import Poly, rand_poly

# Cantor-Zassenhaus algorithm for factoring polynomials over finite fields
def cantor_zassenhaus(f: Poly, p: Poly) -> tuple:

    q = 2 ** 128
    d = len(f) - 1
    h = rand_poly(d - 1)

    g = h.square_and_multiply(((q-1)//3), f)

    # Subtract 1
    g[0] = g[0] - FFPoly(1)

    q = p.gcd(g)

    if q != Poly([1]) and q != p:
        k1 = q
        k2 = p // q
        return k1, k2
    else:
        return None, None
