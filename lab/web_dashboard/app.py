# app.py
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify
from lab.rsa.fermat_factor import fermat_factor
from lab.rsa.weak_rsa_gen import gen_weak_rsa
from lab.ecc.weak_ecc_gen import safe_int_from_form, brute_force_d_mod_r, make_toy_curve_and_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_public_key
)
import math
import time

# ECC imports
from ecdsa import ellipticcurve, numbertheory
from ecdsa.util import number_to_string, string_to_number
import secrets

app = Flask(__name__)
app.secret_key = "replace-in-lab"


def is_too_large_bitlen(n, limit=128):
    return n.bit_length() > limit

def wants_json():
    return (
        request.headers.get("Accept","").lower().startswith("application/json")
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )
def _build_public_pem(n: int, e: int = 65537) -> bytes:
    pubnums = rsa_mod.RSAPublicNumbers(e, n)
    pubkey = pubnums.public_key()
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _fmt_scientific(x):
    # format huge numbers cleanly for display
    from math import log10, floor
    if x == 0:
        return "0"
    exp = floor(log10(x))
    mant = x / (10 ** exp)
    return f"{mant:.2f}e{exp}"

def estimate_dlog_cost(bits, ops_per_sec_list=(1e9, 1e12)):
    """
    bits: order bits (≈ curve key_size for named NIST curves)
    Returns printable numbers for Pollard-rho/BSGS at various throughputs.
    """
    import math
    sqrt_ops = 2 ** (bits / 2.0)  # ~ operations for rho or BSGS
    mem_ops  = sqrt_ops          # memory footprint for BSGS entries (points)
    estimates = []
    for r in ops_per_sec_list:
        seconds = sqrt_ops / r
        years   = seconds / (60*60*24*365.2425)
        estimates.append({
            "rate_ops_per_sec": r,
            "seconds": seconds,
            "years": years
        })
    return {
        "sqrt_ops": sqrt_ops,
        "sqrt_ops_fmt": _fmt_scientific(sqrt_ops),
        "bsgs_mem_points": mem_ops,
        "bsgs_mem_points_fmt": _fmt_scientific(mem_ops),
        "rates": estimates
    }

# -----------------------
# Routes
# -----------------------
@app.route("/")
def index():
    # index.html should include forms to POST to /upload_rsa, /upload_ecc, /attack_toy_ecc and a link to /generate_toy_ecc
    return render_template("index.html")

# --- RSA endpoint (existing) ---
@app.route("/generate_toy_rsa_pub", methods=["GET"])
def generate_toy_rsa_pub():
    """
    Return ONLY a toy RSA public key PEM.
    Query params:
      mode=weak|strong (default strong)
      bits=<int>        (default 32; keep <=64 for the lab)
      closeness=<int>   (weak mode; default 16)
      min_gap=<int>     (strong mode; default 4096)
      e=<int>           (default 65537)
    """
    mode = request.args.get("mode", "strong").lower()
    bits = int(request.args.get("bits", 32))
    e    = int(request.args.get("e", 65537))

    # Lab safety: keep primes tiny; your upload route already rejects >64 bits anyway
    if bits < 8 or bits > 64:
        return ("Toy generator: bits must be between 8 and 64.", 400,
                {"Content-Type": "text/plain; charset=utf-8"})

    try:
        if mode == "weak":
            closeness = int(request.args.get("closeness", 16))
            # import here to avoid circulars at import time
            from lab.rsa.weak_rsa_gen import gen_weak_rsa
            key = gen_weak_rsa(bits=bits, closeness=closeness)
        else:
            min_gap = int(request.args.get("min_gap", 4096))
            from lab.rsa.weak_rsa_gen import gen_strong_rsa
            key = gen_strong_rsa(bits=bits, min_gap=min_gap, e=e)

        n = int(key["n"])
        e = int(key["e"])
        pub_pem = _build_public_pem(n, e).decode()

        # Return text/plain PEM so the frontend can paste straight into <textarea>
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store"
        }
        return (pub_pem, 200, headers)

    except Exception as ex:
        return (f"Error generating toy RSA: {ex}", 500,
                {"Content-Type": "text/plain; charset=utf-8"})


@app.post("/upload_rsa")
def upload_rsa():
    pem_data = request.form.get("pem", "")
    accept = request.form.get("accept")

    def respond(msg, ok=True, code=200):
        if wants_json():
            return jsonify({"status": "ok" if ok else "error", "message": msg}), code
        # fallback: flash + redirect
        flash(msg)
        return redirect(url_for("index"))


    try:
        key = load_pem_public_key(pem_data.encode())
        numbers = key.public_numbers()
        n = int(numbers.n)
        e = int(numbers.e)
    except Exception as e:
        return respond(f"Failed to parse PEM: {e}", ok=False, code=400)

    # Optional safety gate
    # if n.bit_length() > 64:
    #     return respond(f"Key too large ({n.bit_length()} bits). No factoring attempted.", ok=True, code=200)

    res = fermat_factor(n, max_steps=2_000_000_000_000)
    if res is None:
        return respond("Fermat did not find factors within step limit.", ok=True, code=200)

    p, q, steps, elapsed = res
    return respond(f"Found factors p={p}, q={q}, q-p = {q-p} in {steps} steps, {elapsed:.3f}s", ok=True, code=200)

# --- ECC endpoints (new) ---


@app.route("/generate_named_ecc_pem", methods=["GET"])
def generate_named_ecc_pem():
    print("test")
    # Generate standard, interoperable ECC keys (P-256)
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()

    pem_priv = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pem_pub  = pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    # Return as JSON so the UI can display/copy them
    return jsonify({
        "status": "ok",
        "curve": "secp256r1 (P-256)",
        "private_key_pem": pem_priv.decode(),
        "public_key_pem": pem_pub.decode(),
        "note": "These are standard PEMs on a named curve. Your demo attack should refuse to run (key_size = 256 > 64)."
    })

@app.route("/upload_ecc", methods=["POST"])
def upload_ecc():
    pem_data = request.form.get("pem", "")
    from cryptography.hazmat.primitives import serialization
    try:
        key = serialization.load_pem_public_key(pem_data.encode())
    except Exception as e:
        msg = "Failed to parse PEM: " + str(e)
        if wants_json(): return jsonify({"status":"error","message":msg}), 400
        flash(msg); return redirect(url_for("index"))

    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    if not isinstance(key, _ec.EllipticCurvePublicKey):
        msg = "Not an EC public key."
        if wants_json(): return jsonify({"status":"error","message":msg}), 400
        flash(msg); return redirect(url_for("index"))

    curve = key.curve
    bits  = getattr(curve, "key_size", None)  # 256 for SECP256R1, 384 for SECP384R1, etc.
    if bits is None:
        msg = "Could not determine curve key size; refusing to proceed."
        if wants_json(): return jsonify({"status":"error","message":msg}), 400
        flash(msg); return redirect(url_for("index"))

    pn = key.public_numbers()
    Qx, Qy = pn.x, pn.y

    # Build the infeasibility message
    est = estimate_dlog_cost(bits)
    msg = "Conclusion: infeasible. The lab will refuse any attack on curves > 64 bits."

    if wants_json():
        return jsonify({
            "status": "ok",
            "message": msg,
            "curve_bits": bits,
            "curve_name": type(curve).__name__,
            "Qx": Qx, "Qy": Qy,
            "estimates": est
        })

    flash(msg)
    return redirect(url_for("index"))

@app.route("/generate_toy_ecc", methods=["GET"])
def generate_toy_ecc():
    try:
        difficulty = request.args.get("difficulty", "medium")  # <-- read choice
        data = make_toy_curve_and_key(difficulty=difficulty, prefer_prime=False)   # <-- pass through
        return jsonify({
            "status": "ok",
            "toy": {
                "p": data["p"], "a": data["a"], "b": data["b"],
                "Gx": int(data["Gx"]), "Gy": int(data["Gy"]),
                "r": int(data["r"]),
                "Qx": int(data["Qx"]), "Qy": int(data["Qy"]),
                # nice-to-have fields for the hint (if your generator returns them)
                "attack_hint": data.get("attack_hint"),
                "r_factors": data.get("r_factors"),
            }
        })
    except ValueError as e: 
        return jsonify({"status":"error","msg":str(e)}), 400



@app.route("/attack_toy_ecc", methods=["POST"])
def attack_toy_ecc():
    try:
        def safe_int(v):
            try:
                return int(v, 0) if isinstance(v, str) else int(v)
            except Exception:
                return None

        fields = ("p","a","b","Gx","Gy","r","Qx","Qy")
        vals = {k: safe_int(request.form.get(k)) for k in fields}
        if any(vals[k] is None for k in fields):
            msg = "Missing toy ECC parameters; provide p,a,b,Gx,Gy,r,Qx,Qy"
            if wants_json(): return jsonify({"status":"error","message":msg}), 400
            flash(msg); return redirect(url_for("index"))

        p,a,b,Gx,Gy,r,Qx,Qy = (vals[k] for k in fields)

        if int(p).bit_length() > 64:
            msg = "Field size too large for demo (p.bit_length() > 64). Refusing."
            if wants_json(): return jsonify({"status":"error","message":msg}), 400
            flash(msg); return redirect(url_for("index"))

        if r > 10_000:
            msg = "Order r too large for naive brute force in demo (r > 10000). Refusing."
            if wants_json(): return jsonify({"status":"error","message":msg}), 400
            flash(msg); return redirect(url_for("index"))

        curve = ellipticcurve.CurveFp(p, a, b)
        G = ellipticcurve.Point(curve, Gx, Gy, r)
        Q = ellipticcurve.Point(curve, Qx, Qy, r)

        # Run attack
        k, steps, elapsed = brute_force_d_mod_r(curve, G, Q, r)

        if wants_json():
            # Send structured result + a human message
            if k is None:
                return jsonify({
                    "status":"ok",
                    "message": f"Brute-force failed within r={r}. Tried {steps} steps in {elapsed:.3f}s.",
                    "result": {"found": False, "r": r, "steps": steps, "elapsed": elapsed}
                })
            else:
                return jsonify({
                    "status":"ok",
                    "message": f"Found d mod r = {k} (r={r}) in {steps} steps, {elapsed:.3f}s.",
                    "result": {"found": True, "k": k, "r": r, "steps": steps, "elapsed": elapsed}
                })

        # Non-AJAX fallback
        if k is None:
            flash(f"Brute-force failed within r={r}. Tried {steps} steps in {elapsed:.3f}s.")
        else:
            flash(f"Found d mod r = {k} (r={r}) in {steps} steps, {elapsed:.3f}s.")
        return redirect(url_for("index"))

    except Exception as e:
        if wants_json():
            return jsonify({"status":"error","message":"Error during ECC attack: " + str(e)}), 500
        flash("Error during ECC attack: " + str(e))
        return redirect(url_for("index"))

# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    # In production you should use gunicorn/uwsgi and not debug=True
    app.run(debug=True, host="127.0.0.1", port=5000)
    print(app.url_map)

