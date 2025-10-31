# app.py
from flask import Flask, request, render_template, flash, redirect, url_for
from fermat_factor import fermat_factor
from weak_rsa_gen import gen_weak_rsa
import cryptography.hazmat.primitives.serialization as serialization
from cryptography.hazmat.backends import default_backend
import math

app = Flask(__name__)
app.secret_key = "replace-in-lab"

@app.route("/")
def index():
    return render_template("index.html")

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

# add ECC endpoints similarly with safety checks.

if __name__ == "__main__":
    app.run(debug=True)

