from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_from_directory
from datetime import datetime
import tenseal as ts
import os
import logging
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "your-secret-key"

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

logging.basicConfig(filename="login.log", level=logging.INFO, format="%(asctime)s - %(message)s")

context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=8192, plain_modulus=1032193)
context.generate_galois_keys()
context.generate_relin_keys()
context_bytes = context.serialize(save_secret_key=True)

user_db = {}  # username -> {"clicks": encrypted_clicks, "image": filename}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def encrypt_clicks(clicks, ctx):
    enc = []
    for point in clicks:
        if isinstance(point, list) and len(point) == 2:
            x, y = map(int, point)
            vec = ts.bfv_vector(ctx, [x, y])
            enc.append(vec)
    return enc

def is_authenticated(enc_input, enc_stored, ctx, tolerance=20):
    if len(enc_input) != len(enc_stored):
        return False
    for input_vec, stored_vec in zip(enc_input, enc_stored):
        diff = stored_vec - input_vec
        decrypted = diff.decrypt()
        dist = (decrypted[0] ** 2 + decrypted[1] ** 2) ** 0.5
        if dist > tolerance:
            return False
    return True

def log_attempt(username, ip, result):
    logging.info(f"{username} - {ip} - {result}")

@app.route("/")
def home():
    return render_template("base.html")

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    image_file = user_db.get(username, {}).get("image", None)
    return render_template("dashboard.html", username=username, image_file=image_file)

@app.route("/get_user_image/<username>")
def get_user_image(username):
    user = user_db.get(username)
    if user and "image" in user:
        return jsonify({"image_filename": user["image"]})
    return jsonify({"message": "User not found or no image"}), 404


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("home"))

@app.route("/register_clicks", methods=["POST"])
def register_clicks():
    data = request.get_json()
    username = data.get("username", "").strip()
    clicks = data.get("clicks", [])
    image_filename = data.get("image_filename", "")

    if not username or not isinstance(clicks, list) or not image_filename:
        return jsonify({"message": "Invalid input"}), 400

    if username in user_db:
        return jsonify({"message": "Username already registered"}), 400

    ctx = ts.context_from(context_bytes)
    encrypted_clicks = encrypt_clicks(clicks, ctx)
    user_db[username] = {"clicks": encrypted_clicks, "image": image_filename}

    return jsonify({"message": f"User '{username}' registered successfully!"})

@app.route("/login_clicks", methods=["POST"])
def login_clicks():
    data = request.get_json()
    username = data.get("username", "").strip()
    clicks = data.get("clicks", [])
    ip = request.remote_addr

    if username not in user_db:
        log_attempt(username, ip, "failed (username not found)")
        return jsonify({"message": "User not found"}), 400

    ctx = ts.context_from(context_bytes)
    encrypted_input = encrypt_clicks(clicks, ctx)
    encrypted_stored = user_db[username]["clicks"]

    if is_authenticated(encrypted_input, encrypted_stored, ctx):
        session["username"] = username
        log_attempt(username, ip, "success")
        return jsonify({"message": "Login successful!"})
    else:
        log_attempt(username, ip, "failed (click mismatch)")
        return jsonify({"message": "Login failed. Incorrect clicks."}), 401

@app.route("/upload_image", methods=["POST"])
def upload_image():
    if 'image' not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        return jsonify({"filename": filename})
    return jsonify({"message": "Invalid file type"}), 400

if __name__ == "__main__":
    app.run(debug=True)
