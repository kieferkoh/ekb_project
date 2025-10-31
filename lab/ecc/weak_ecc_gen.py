# weak_ecc_gen.py - toy ECC
from ecdsa import ellipticcurve, numbertheory, curves
from ecdsa.ecdsa import Public_key, Private_key, generator_secp256k1
import time
import secrets

def safe_int_from_form(name, default=None):
    if name is None or name.strip() == "":
        return default
    return int(name.strip(), 0)  # allow hex like 0x...


def brute_force_d_mod_r(curve_fp, G_point, Q_point, r_limit):
    """
    Brute force k in [0..r-1] such that k*G == Q on the given elliptic curve.
    curve_fp: instance of CurveFp
    G_point, Q_point: instances of ellipticcurve.Point
    r_limit: integer order to brute force (must be small)
    Returns k or None and steps/time.
    """
    start = time.time()
    steps = 0
    # naive multiply via repeated addition (use Point.__mul__ which uses fast double-and-add)
    for k in range(r_limit):
        steps += 1
        if k * G_point == Q_point:
            elapsed = time.time() - start
            return k, steps, elapsed
    return None, steps, time.time() - start

def make_toy_curve_and_key():
    """
    Produce a toy curve over small prime p, a, b and a generator G with small order r.
    We'll choose tiny fixed values for demo (p prime small).
    """
    # Tiny toy curve that works for demonstration (not cryptographically secure)
    # These small values are chosen for demo; you can change them if desired.
    p = 233  # small prime
    a = 1
    b = 1
    # We will search for a small order point G on this curve
    curve = ellipticcurve.CurveFp(p, a, b)

    # brute force points to find one with small order r (e.g., <= 50)
    max_order = 50
    found = None
    for x in range(1, p):
        for y in range(1, p):
            try:
                P = ellipticcurve.Point(curve, x, y, 0)  # temporary order 0
            except Exception:
                continue
            # compute order by repeated addition (naive)
            R = P
            for r in range(1, max_order+1):
                if R.x() == P.x() and R.y() == P.y() and r == 1:
                    pass
                if R == ellipticcurve.INFINITY:
                    order = r
                    break
                R = R + P
            else:
                continue
            if 2 <= order <= max_order:
                found = (x, y, order)
                break
        if found:
            break

    if not found:
        raise RuntimeError("Could not find small-order point on this toy curve; adjust parameters")

    Gx, Gy, r = found
    G = ellipticcurve.Point(curve, Gx, Gy, r)
    # pick a secret d in range [1, r-1]
    d = secrets.randbelow(r-1) + 1
    Q = d * G
    return {
        "p": p, "a": a, "b": b,
        "Gx": Gx, "Gy": Gy, "r": r,
        "d": d, "Qx": Q.x(), "Qy": Q.y()
    }
