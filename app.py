from flask import Flask, render_template, request, send_file
from encoder import load_image, encode_image
from decoder import decode_image
from crypto_utils import generate_key_from_password, encrypt_message, decrypt_message
import os
from utils import text_to_bits
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encode", methods=["GET", "POST"])
def encode():
    if request.method == "POST":
        file = request.files["image"]
        message = request.form["message"]
        password = request.form["password"]
        if file and message and password:
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            img = load_image(filepath)
            key, salt = generate_key_from_password(password)
            enc_msg = encrypt_message(message, key)
            out_path = os.path.join(UPLOAD_FOLDER, "encoded_" + filename)
            full_message = salt.hex() + ":" + enc_msg
            message_bits = text_to_bits(full_message)
            encode_image(img, message_bits, out_path)

            return send_file(out_path, as_attachment=True)
    return render_template("encode.html")

@app.route("/decode", methods=["GET", "POST"])
def decode():
    if request.method == "POST":
        file = request.files["image"]
        password = request.form["password"]
        if file and password:
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            try:
                enc_msg_full = decode_image(filepath)
                salt_hex, enc_msg = enc_msg_full.split(":", 1)
                salt = bytes.fromhex(salt_hex)
                key, _ = generate_key_from_password(password, salt=salt)
                message = decrypt_message(enc_msg, key)
                return render_template("result.html", message=message)
            except:
                return render_template("result.html", message="Incorrect password or corrupted image!")
    return render_template("decode.html")

if __name__ == "__main__":
    app.run(debug=True)
