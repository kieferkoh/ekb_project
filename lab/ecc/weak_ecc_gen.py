# weak_ecc_gen.py - toy ECC
from ecdsa import ellipticcurve, numbertheory
from ecdsa.ecdsa import Public_key, Private_key, generator_secp256k1
import secrets, time, math

def safe_int_from_form(name, default=None):
    if name is None or name.strip() == "":
        return default
    return int(name.strip(), 0)  # allow hex like 0x...

def brute_force_d_mod_r(curve_fp, G_point, Q_point, r_limit):
    start = time.time()
    steps = 0
    for k in range(r_limit):
        steps += 1
        if k * G_point == Q_point:
            elapsed = time.time() - start
            return k, steps, elapsed
    return None, steps, time.time() - start

def make_toy_curve_and_key(
    difficulty: str = "medium",
    prefer_prime: bool = False,
    min_r: int | None = None,
    max_r: int | None = None,
):
    import time, math, secrets
    from ecdsa import ellipticcurve, numbertheory

    # --- small p keeps ops snappy; stay well under your 64-bit lab ceiling
    p = 40961
    a, b = 1, 1
    curve = ellipticcurve.CurveFp(p, a, b)

    # --- difficulty presets; overridden by min_r/max_r if provided
    presets = {"easy": (20, 120), "medium": (200, 900), "hard": (1200, 4000)}
    lo, hi = presets.get(difficulty, presets["medium"])
    if min_r is not None: lo = min_r
    if max_r is not None: hi = max_r

    # --- tight budgets so route always returns
    overall_deadline = time.time() + 0.8
    MAX_TRIES       = 2000
    PER_TRY_STEPS   = max(hi + 80, 600)
    PER_TRY_SECONDS = 0.006

    def rand_point():
        for _ in range(8):
            x = secrets.randbelow(p-1) + 1
            rhs = (x*x*x + a*x + b) % p
            try:
                y = numbertheory.square_root_mod_prime(rhs, p)
                if secrets.randbits(1): y = (p - y) % p
                return int(x), int(y)
            except Exception:
                continue
        return None, None

    def order_bounded(P):
        start = time.time()
        if P == ellipticcurve.INFINITY: return 1
        R = P
        for r in range(1, PER_TRY_STEPS + 1):
            if R == ellipticcurve.INFINITY: return r
            if time.time() - start > PER_TRY_SECONDS: return None
            R = R + P
        return None

    def factor_multiset(n: int) -> dict[int,int]:
        f, d = {}, 2
        while d*d <= n:
            while n % d == 0:
                f[d] = f.get(d, 0) + 1
                n //= d
            d += 1 if d == 2 else 2
        if n > 1: f[n] = f.get(n, 0) + 1
        return f

    def pick_prime_factor_in_band(facs: dict[int,int], lo: int, hi: int) -> int | None:
        # collect prime factors in [lo, hi]; prefer the largest (hardest)
        candidates = [p for p in facs.keys() if lo <= p <= hi]
        if candidates:
            return max(candidates)
        # otherwise, allow near-miss: the largest prime factor, if at least ~lo/2
        if facs:
            q = max(facs.keys())
            if q >= max(2, lo // 2):
                return q
        return None

    tries = 0
    while tries < MAX_TRIES and time.time() < overall_deadline:
        tries += 1
        x, y = rand_point()
        if x is None: 
            continue

        try:
            P = ellipticcurve.Point(curve, x, y, 0)
        except Exception:
            continue

        r = order_bounded(P)
        if r is None:
            continue

        facs = factor_multiset(r)
        if prefer_prime:
            # Extract a prime-order subgroup q | r in desired band
            q = pick_prime_factor_in_band(facs, lo, hi)
            if q is None:
                continue
            # cofactor h = r / q; G has order exactly q
            h = r // q
            G = h * P
            # quick sanity (cheap): q*G should be ∞, and G != ∞
            if G == ellipticcurve.INFINITY or (q * G) != ellipticcurve.INFINITY:
                continue
            info = {"prime": True}
            used_r = q
        else:
            # accept full order in band
            if not (lo <= r <= hi):
                continue
            G = P
            info = facs
            used_r = r

        # build keypair on chosen generator G
        d = secrets.randbelow(used_r - 1) + 1
        Q = d * G
        hint = (
            "Use BSGS/Pollard-rho (≈√r steps)."
            if ("prime" in info)
            else f"Pohlig–Hellman on factors {info} (then BSGS on largest)."
        )

        return {
            "p": p, "a": a, "b": b,
            "Gx": int(G.x()), "Gy": int(G.y()),
            "r": int(used_r),
            "r_factors": info,
            "d": int(d),
            "Qx": int(Q.x()), "Qy": int(Q.y()),
            "attack_hint": hint,
            "est_ops_sqrt_r": int(2 ** (math.log2(used_r) / 2)),
        }

    # graceful failure (caught by your route and shown to the UI)
    raise RuntimeError("Toy generation timed out; try a wider band or lower difficulty.")