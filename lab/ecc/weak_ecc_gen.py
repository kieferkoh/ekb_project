# weak_ecc_gen.py - toy ECC
from ecdsa import ellipticcurve, numbertheory
from ecdsa.ecdsa import Public_key, Private_key, generator_secp256k1
import secrets, time, math

def safe_int_from_form(name, default=None):
    if name is None or name.strip() == "":
        return default
    return int(name.strip(), 0)  # allow hex like 0x...


# ---- your original brute-force stays unchanged ----
def brute_force_d_mod_r(curve_fp, G_point, Q_point, r_limit):
    start = time.time()
    steps = 0
    for k in range(r_limit):
        steps += 1
        if k * G_point == Q_point:
            elapsed = time.time() - start
            return k, steps, elapsed
    return None, steps, time.time() - start

def _rand_point_on_curve(curve, p, max_tries=2000):
    # sample x, take sqrt(rhs) via Tonelli–Shanks
    for _ in range(max_tries):
        x = secrets.randbelow(p-1) + 1
        rhs = (x*x*x + curve.a()*x + curve.b()) % p
        try:
            y = numbertheory.square_root_mod_prime(rhs, p)
            if secrets.randbits(1):  # random sign
                y = (p - y) % p
            return int(x), int(y)
        except Exception:
            continue
    return None, None

def _order_naive(P, max_steps, max_seconds=0.05):
    # repeated addition with strict caps
    start = time.time()
    if P == ellipticcurve.INFINITY:
        return 1
    R = P
    for r in range(1, max_steps+1):
        if R == ellipticcurve.INFINITY:
            return r
        if (time.time() - start) > max_seconds:
            return None
        R = R + P
    return None

def _factor_multiset(n):
    f, d = {}, 2
    while d*d <= n:
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        f[n] = f.get(n, 0) + 1
    return f

def _is_probable_prime(n):
    if n < 2: return False
    small = [2,3,5,7,11,13,17,19,23,29]
    for p in small:
        if n == p: return True
        if n % p == 0: return False
    # tiny Miller–Rabin for 32-bit scale
    d, s = n-1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for a in [2, 7, 61]:
        if a % n == 0: 
            continue
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(s-1):
            x = (x*x) % n
            if x == n-1:
                break
        else:
            return False
    return True


def make_toy_curve_and_key(
    difficulty: str = "medium",
    prefer_prime: bool = False,
    min_r: int | None = None,
    max_r: int | None = None,
):
    """
    BOUNDED demo generator:
    - small field p so point ops are cheap
    - strict time budgets so the route always returns
    - returns (p,a,b,Gx,Gy,r,Qx,Qy) + hints
    """
    # 1) small p for demo speed (<< 2^64 safety ceiling)
    p = 40961            # feel free to use 233 for ultra-fast
    a, b = 1, 1
    curve = ellipticcurve.CurveFp(p, a, b)

    # 2) difficulty bands (tune as desired)
    presets = {
        "easy":   (20,   120),     # brute force ok
        "medium": (200,  900),     # BSGS shows benefit
        "hard":   (1200, 4000),    # PH (if composite) or BSGS needed
    }
    lo, hi = presets.get(difficulty, presets["medium"])
    if min_r is not None: lo = min_r
    if max_r is not None: hi = max_r

    # 3) budgets (fast responses)
    OVERALL_DEADLINE = time.time() + 0.8     # total ~0.8s
    MAX_TRIES        = 2000                  # sampling attempts
    PER_TRY_STEPS    = max(hi + 100, 600)    # cap order loop
    PER_TRY_SECONDS  = 0.006                 # ~6ms per order attempt

    # (Optional) pre-vetted fallback catalog for instant results
    catalog = [
        # Example placeholders; add real tuples you've verified:
        # (difficulty, p, a, b, Gx, Gy, r)
        # ("easy",   233, 1, 1,  3, 10,  37),
        # ("medium", 233, 1, 1,  7, 57,  289),
        # ("hard",   233, 1, 1,  5, 83, 1309),
    ]

    # Try random search within budgets
    tries = 0
    while tries < MAX_TRIES and time.time() < OVERALL_DEADLINE:
        tries += 1
        x, y = _rand_point_on_curve(curve, p, max_tries=4)
        if x is None:
            continue
        try:
            P = ellipticcurve.Point(curve, x, y, 0)
        except Exception:
            continue

        r = _order_naive(P, max_steps=PER_TRY_STEPS, max_seconds=PER_TRY_SECONDS)
        if r is None or r < lo or r > hi:
            continue

        # optional property of r
        info = {}
        if prefer_prime:
            if not _is_probable_prime(r):
                continue
            info = {"prime": True}
            hint = "Use BSGS / Pollard-rho (≈√r steps)."
        else:
            fac = _factor_multiset(r)
            info = fac
            big = max(fac) if fac else 1
            hint = f"Pohlig–Hellman on factors {fac} (then BSGS on largest)."

        # found target
        d = secrets.randbelow(r-1) + 1
        Q = d * P
        return {
            "p": p, "a": a, "b": b,
            "Gx": x, "Gy": y,
            "r": r,
            "r_factors": info,
            "d": d,
            "Qx": int(Q.x()), "Qy": int(Q.y()),
            "attack_hint": hint,
            "est_ops_sqrt_r": int(2 ** (math.log2(r) / 2)),
        }

    # Fallback to catalog if present
    for diff, cp, ca, cb, gx, gy, rr in catalog:
        if diff != difficulty: 
            continue
        curve2 = ellipticcurve.CurveFp(cp, ca, cb)
        P2 = ellipticcurve.Point(curve2, gx, gy, rr)
        d   = secrets.randbelow(rr-1) + 1
        Q2  = d * P2
        info = {"prime": True} if _is_probable_prime(rr) else _factor_multiset(rr)
        hint = ("Use BSGS / Pollard-rho (≈√r steps)." 
                if "prime" in info else f"Pohlig–Hellman on factors {info}.")
        return {
            "p": cp, "a": ca, "b": cb,
            "Gx": gx, "Gy": gy,
            "r": rr,
            "r_factors": info,
            "d": d,
            "Qx": int(Q2.x()), "Qy": int(Q2.y()),
            "attack_hint": hint,
            "est_ops_sqrt_r": int(2 ** (math.log2(rr) / 2)),
        }

    # Out of budget — tell the client cleanly
    raise RuntimeError("Toy generation timed out; lower difficulty or widen r-range.")