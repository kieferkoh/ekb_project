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
    """
    Accept a PEM-encoded EC public key, parse it, and (safely) attempt a toy brute-force
    if the curve key_size <= 64. Otherwise refuse.
    """
    pem_data = request.form.get("pem")
    accept = request.form.get("accept")
    try:
        key = load_pem_public_key(pem_data.encode())
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
        # if key_size > 64:
        #     flash(f"EC key size {key_size} bits is too large for lab demo. Refusing to run attacks.")
        #     return redirect(url_for("index"))
        # If small, try to bruteforce d modulo small order if order known (cryptography may not expose order)
        public_numbers = key.public_numbers()
        Qx = public_numbers.x
        Qy = public_numbers.y
        # cryptography doesn't generally provide curve parameters/order for custom curves here.
        msg = f"Parsed EC public key: Qx={Qx}, Qy={Qy}, curve_size={key_size} bits. Note: automatic attack for generic EC PEM is limited in this demo."
        if wants_json():  # ← AJAX path
            return jsonify({"status": "ok", "message": msg})
        flash(msg)
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
