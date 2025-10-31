# app.py
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify
from ..rsa.fermat_factor import fermat_factor
from ..rsa.weak_rsa_gen import gen_weak_rsa
from ..ecc.weak_ecc_gen import safe_int_from_form, brute_force_d_mod_r, make_toy_curve_and_key
from cryptography.hazmat.backends import default_backend
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


def is_too_large_bitlen(n, limit=64):
    return n.bit_length() > limit

def wants_json():
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
           request.accept_mimetypes.best == 'application/json'

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
    try:
        key = load_pem_public_key(pem_data.encode())
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
        if wants_json():  # ← AJAX path
            return jsonify({"status": "ok", 
                            "message": f"Found factors p={res[0]}, q={res[1]} in {res[2]} steps, {res[3]:.3f}s",})
        p,q,steps,elapsed = res
        flash(f"Found factors p={p}, q={q} in {steps} steps, {elapsed:.3f}s")
    return redirect(url_for("index"))

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
