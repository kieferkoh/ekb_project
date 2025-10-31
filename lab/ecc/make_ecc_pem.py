"""
mae_ecc_pen.py  -- MAE: Modular Attack & Enumeration toolkit for toy ECC (edu/demo only)

Functions:
- find_point_order(curve, P, max_search=10000)
- brute_force_dlog(curve, G, Q, order_bound)
- bsgs_dlog(curve, G, Q, order_bound)
- analyze_point(curve, G, Q, order_search=5000, dlog_bound=100000)

SAFETY:
- Refuses to operate on prime fields with bit-length > 64.
- For discrete log, enforces `order_bound` to avoid huge computations.
- Intended for local lab/demo only. Do not use against real-world curves.

Dependencies: ecdsa (ellipticcurve.Point)
"""

from ecdsa import ellipticcurve
import math
import time
from collections import defaultdict


class SafetyError(Exception):
    pass


def _check_field_size(curve_fp, max_bits=64):
    p = curve_fp.p()
    if p.bit_length() > max_bits:
        raise SafetyError(f"Field prime bit-length {p.bit_length()} > {max_bits}. Refusing to run.")


def find_point_order(curve_fp, P, max_search=10000):
    """
    Find the order r of point P by naive repeated-addition up to max_search.
    Returns (r, steps, elapsed_seconds) on success, or (None, steps, elapsed_seconds) if not found.
    """
    _check_field_size(curve_fp)

    if P == ellipticcurve.INFINITY:
        return 1, 0, 0.0

    start = time.time()
    R = P
    steps = 1
    while steps <= max_search:
        if R == ellipticcurve.INFINITY:
            elapsed = time.time() - start
            return steps, steps, elapsed  # found order = steps
        R = R + P
        steps += 1
    elapsed = time.time() - start
    return None, steps-1, elapsed


def brute_force_dlog(curve_fp, G, Q, order_bound=10000):
    """
    Naive discrete log: find k in [0..order_bound-1] such that k*G == Q.
    Returns (k, steps, elapsed) or (None, steps, elapsed).
    """
    _check_field_size(curve_fp)

    start = time.time()
    R = ellipticcurve.INFINITY
    steps = 0
    # iterate k from 0..order_bound-1
    for k in range(0, order_bound):
        if R == Q:
            elapsed = time.time() - start
            return k, steps, elapsed
        R = R + G
        steps += 1
    # final check
    if R == Q:
        elapsed = time.time() - start
        return order_bound, steps, elapsed
    elapsed = time.time() - start
    return None, steps, elapsed


def bsgs_dlog(curve_fp, G, Q, order_bound=100000):
    """
    Baby-step Giant-step discrete log solver for ECDLP in small groups.
    Solves k such that k*G == Q assuming k < order_bound.

    Returns (k, memory, steps, elapsed) where:
      - k is the discrete log or None
      - memory is size of baby-step table created
      - steps is rough operations done (baby + giant)
      - elapsed is runtime seconds
    """
    _check_field_size(curve_fp)

    # limit memory/time to reasonable bounds
    if order_bound > 200000:
        raise SafetyError("order_bound > 200000 disallowed in demo (too expensive).")

    start = time.time()
    m = int(math.ceil(math.sqrt(order_bound)))
    baby_table = dict()
    # baby steps: store j*G for j in [0,m-1]
    R = ellipticcurve.INFINITY
    for j in range(m):
        # store point coords as tuple
        baby_table[(None if R == ellipticcurve.INFINITY else (int(R.x()), int(R.y())))] = j
        R = R + G

    # compute G^-m = ( -m * G )? Actually we compute factor = m*G and then use Q - i*(m*G)
    factor = m * G  # mG

    # giant steps: for i in 0..m
    S = Q
    steps = 0
    for i in range(m+1):
        key = (None if S == ellipticcurve.INFINITY else (int(S.x()), int(S.y())))
        if key in baby_table:
            j = baby_table[key]
            k = i * m + j
            elapsed = time.time() - start
            return k, len(baby_table), steps + i, elapsed
        # S = S - factor  (i.e., Q - (i+1)*m*G)
        S = S - factor
        steps += 1

    elapsed = time.time() - start
    return None, len(baby_table), steps, elapsed


def analyze_point(curve_fp, G, Q, order_search=5000, dlog_bound=100000):
    """
    Run a sequence of checks:
    1) Find order r of G (naive up to order_search).
    2) If r is small, brute-force d mod r.
    3) If not found and r <= dlog_bound, try BSGS.

    Returns a dict with findings and timings.
    """
    _check_field_size(curve_fp)

    out = {"status": "ok", "messages": []}

    # 1) order of G
    r, steps_order, t_order = find_point_order(curve_fp, G, max_search=order_search)
    out["order_search"] = {"order": r, "steps": steps_order, "time": t_order}
    if r is None:
        out["messages"].append(f"Order of G not found within {order_search} steps (field size safe).")
    else:
        out["messages"].append(f"Found order r = {r} (in {steps_order} steps, {t_order:.4f}s).")

    # 2) if small order, brute-force
    if r is not None and r <= 100000:
        k, steps_bf, t_bf = brute_force_dlog(curve_fp, G, Q, order_bound=r)
        out["bruteforce"] = {"k": k, "steps": steps_bf, "time": t_bf}
        if k is not None:
            out["messages"].append(f"Brute-force succeeded: d mod r = {k} (r={r})")
            return out
        else:
            out["messages"].append(f"Brute-force (mod r={r}) failed after {steps_bf} steps.")
    else:
        out["messages"].append("Skipping brute-force mod r (order unknown or too large).")

    # 3) try BSGS within dlog_bound
    if dlog_bound <= 200000:
        k_bsgs, mem, steps_bsgs, t_bsgs = bsgs_dlog(curve_fp, G, Q, order_bound=dlog_bound)
        out["bsgs"] = {"k": k_bsgs, "memory": mem, "steps": steps_bsgs, "time": t_bsgs}
        if k_bsgs is not None:
            out["messages"].append(f"BSGS succeeded: d = {k_bsgs} (within bound {dlog_bound})")
        else:
            out["messages"].append("BSGS did not find discrete log within bound.")
    else:
        out["messages"].append("Skipping BSGS: dlog_bound too large.")

    return out


# Simple CLI demo when run standalone
if __name__ == "__main__":
    # Demo: use tiny toy curve and point for illustration
    # WARNING: This demo uses tiny numbers only
    from ecdsa import ellipticcurve
    p = 233
    a = 1
    b = 1
    curve = ellipticcurve.CurveFp(p, a, b)

    # pick a small-order point known from exploration (adjust if necessary)
    # If this fails to be a valid point, change x,y to values that are on-curve.
    # We'll search for any non-trivial point with small order
    found = None
    for x in range(1, p):
        for y in range(1, p):
            try:
                P = ellipticcurve.Point(curve, x, y, 0)
            except Exception:
                continue
            r, _, _ = find_point_order(curve, P, max_search=500)
            if r and 2 <= r <= 100:
                found = (P, r)
                break
        if found:
            break

    if not found:
        print("Could not find small-order point on toy curve. Try adjusting parameters.")
    else:
        P, r = found
        # choose secret d
        import secrets
        d = secrets.randbelow(r-1) + 1
        Q = d * P
        print("Toy curve p,a,b:", p, a, b)
        print("Point G:", (int(P.x()), int(P.y())), "order r =", r)
        print("Secret d (hidden):", d)
        # analyze
        res = analyze_point(curve, P, Q, order_search=500, dlog_bound=5000)
        import pprint
        pprint.pprint(res)
