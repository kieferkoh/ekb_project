# app.py
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify
from fermat_factor import fermat_factor
from weak_rsa_gen import gen_weak_rsa
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.backends import default_backend
import math
import time

# ECC imports
from ecdsa import ellipticcurve, numbertheory
from ecdsa.util import number_to_string, string_to_number
import secrets

app = Flask(__name__)
app.secret_key = "replace-in-lab"

# -----------------------
# Helpers (ECC - toy)
# -----------------------
def safe_int_from_form(name, default=None):
    v = request.form.get(name)
    if v is None or v.strip() == "":
        return default
    return int(v.strip(), 0)  # allow hex like 0x...

def is_too_large_bitlen(n, limit=64):
    return n.bit_length() > limit

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

# -----------------------
# Routes
# -----------------------
@app.route("/")
def index():
    # index.html should include forms to POST to /upload_rsa, /upload_ecc, /attack_toy_ecc and a link to /generate_toy_ecc
    return render_template("index.html")

# --- RSA endpoint (existing) ---
@app.route("/upload_rsa", methods=["POST"])
def upload_rsa():
    pem_data = request.form.get("pem")
    accept = request.form.get("accept")
    if accept != "on":
        flash("You must confirm ownership of the key (lab only).")
        return redirect(url_for("index"))
    try:
        key = serialization.load_pem_public_key(pem_data.encode(), backend=default_backend())
    except Exception as e:
        flash("Failed to parse PEM: "+str(e))
        return redirect(url_for("index"))
    # inspect key size
    try:
        n = key.public_numbers().n
    except AttributeError:
        flash("Not an RSA public key.")
        return redirect(url_for("index"))
    if n.bit_length() > 64:
        flash("Key too large for lab demo (bitlen {}). Refusing to attempt factoring.".format(n.bit_length()))
        return redirect(url_for("index"))
    # safe: run fermat
    res = fermat_factor(n, max_steps=200000)
    if res is None:
        flash("Fermat did not find factors within step limit; increase steps on your own lab machine")
    else:
        p,q,steps,elapsed = res
        flash(f"Found factors p={p}, q={q} in {steps} steps, {elapsed:.3f}s")
    return redirect(url_for("index"))

# --- ECC endpoints (new) ---
@app.route("/upload_ecc", methods=["POST"])
def upload_ecc():
    """
    Accept a PEM-encoded EC public key, parse it, and (safely) attempt a toy brute-force
    if the curve key_size <= 64. Otherwise refuse.
    """
    pem_data = request.form.get("pem")
    accept = request.form.get("accept")
    if accept != "on":
        flash("You must confirm ownership of the key (lab only).")
        return redirect(url_for("index"))
    try:
        key = serialization.load_pem_public_key(pem_data.encode(), backend=default_backend())
    except Exception as e:
        flash("Failed to parse PEM: "+str(e))
        return redirect(url_for("index"))

    # Check if it's an EC public key and inspect curve size
    try:
        curve = key.curve  # cryptography object has .key_size
        key_size = getattr(curve, "key_size", None)
        if key_size is None:
            flash("Could not determine curve key size; refusing to proceed.")
            return redirect(url_for("index"))
        if key_size > 64:
            flash(f"EC key size {key_size} bits is too large for lab demo. Refusing to run attacks.")
            return redirect(url_for("index"))
        # If small, try to bruteforce d modulo small order if order known (cryptography may not expose order)
        public_numbers = key.public_numbers()
        Qx = public_numbers.x
        Qy = public_numbers.y
        # cryptography doesn't generally provide curve parameters/order for custom curves here.
        flash(f"Parsed EC public key (tiny curve allowed): Qx={Qx}, Qy={Qy}, curve_size={key_size} bits. Note: automatic attack for generic EC PEM is limited in this demo.")
        # We don't attempt automatic attack here unless you also provide curve params (use /attack_toy_ecc for that)
        return redirect(url_for("index"))
    except AttributeError:
        flash("Not an EC public key.")
        return redirect(url_for("index"))

@app.route("/generate_toy_ecc", methods=["GET"])
def generate_toy_ecc():
    """
    Returns a JSON with toy curve parameters and keypair that the UI can use as a canned example.
    """
    try:
        data = make_toy_curve_and_key()
        # hide private key by default in UI; include it if needed for demonstration
        return jsonify({
            "status": "ok",
            "toy": {
                "p": data["p"], "a": data["a"], "b": data["b"],
                "Gx": data["Gx"], "Gy": data["Gy"], "r": data["r"],
                "Qx": data["Qx"], "Qy": data["Qy"]
            },
            "note": "This is a canned toy curve & public key. Use /attack_toy_ecc to run the demo attack. Keep experiments local."
        })
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route("/attack_toy_ecc", methods=["POST"])
def attack_toy_ecc():
    """
    Accept toy ECC parameters from a form and brute force d mod r.
    Required form fields: p,a,b,Gx,Gy,r,Qx,Qy
    Safety: refuse if p.bit_length() > 64 or r > 10_000 (safety/time).
    """
    try:
        p = safe_int_from_form("p")
        a = safe_int_from_form("a")
        b = safe_int_from_form("b")
        Gx = safe_int_from_form("Gx")
        Gy = safe_int_from_form("Gy")
        r = safe_int_from_form("r")
        Qx = safe_int_from_form("Qx")
        Qy = safe_int_from_form("Qy")
        if None in (p,a,b,Gx,Gy,r,Qx,Qy):
            flash("Missing toy ECC parameters; please provide p,a,b,Gx,Gy,r,Qx,Qy")
            return redirect(url_for("index"))

        if is_too_large_bitlen(p, limit=64):
            flash("Field size too large for lab demo (p.bit_length() > 64). Refusing.")
            return redirect(url_for("index"))

        if r > 10000:
            flash("Order r too large for naive brute force in demo (r > 10000). Refusing.")
            return redirect(url_for("index"))

        # construct curve and points using ecdsa
        curve = ellipticcurve.CurveFp(p, a, b)
        G = ellipticcurve.Point(curve, Gx, Gy, r)
        Q = ellipticcurve.Point(curve, Qx, Qy, r)

        k, steps, elapsed = brute_force_d_mod_r(curve, G, Q, r)
        if k is None:
            flash(f"Brute-force did not find d mod r within r ({r}) steps. Steps tried: {steps}, elapsed {elapsed:.3f}s")
        else:
            flash(f"Found d mod r = {k} (r={r}) in {steps} steps, {elapsed:.3f}s")
        return redirect(url_for("index"))
    except Exception as e:
        flash("Error during ECC attack: " + str(e))
        return redirect(url_for("index"))

# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    # In production you should use gunicorn/uwsgi and not debug=True
    app.run(debug=True, host="127.0.0.1", port=5000)
