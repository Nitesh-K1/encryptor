from flask import Flask, render_template, request, send_file
from encoder import load_image, encode_image
from decoder import decode_image
from crypto_utils import generate_key_from_password, encrypt_message, decrypt_message
import os
from utils import text_to_bits
from werkzeug.utils import secure_filename
from base64 import b64encode, b64decode
import base64

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
        hidden_file = request.files.get("hidden_file")
        password = request.form["password"]

        if not file or not password:
            return render_template("encode.html")

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        img = load_image(filepath)

        key, salt = generate_key_from_password(password)
        has_message = message.strip() != ""
        has_file = hidden_file and hidden_file.filename != ""
        
        if not has_message and not has_file:
            return render_template("encode.html")

        if has_message and has_file:
            payload_type = "BOTH"
            enc_msg_text = encrypt_message(message, key)
            file_bytes = hidden_file.read()
            file_b64 = base64.b64encode(file_bytes).decode()
            enc_file = encrypt_message(file_b64, key)
            payload = enc_msg_text + "::" + hidden_file.filename + "::" + enc_file
        elif has_message:
            payload_type = "TEXT"
            enc_msg = encrypt_message(message, key)
            payload = enc_msg
        elif has_file:
            payload_type = "FILE"
            file_bytes = hidden_file.read()
            file_b64 = base64.b64encode(file_bytes).decode()
            enc_msg = encrypt_message(file_b64, key)
            payload = hidden_file.filename + "::" + enc_msg
        else:
            return "No message or file provided!"

        full_payload = payload_type + ":" + salt.hex() + ":" + payload

        message_bits = text_to_bits(full_payload)
        out_path = os.path.join(UPLOAD_FOLDER, "encoded_" + filename)
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
                raw = decode_image(filepath)
    
                parts = raw.split(":", 2)
                if len(parts) < 3:
                    return render_template("result.html", message="Corrupted data!", file_url=None)

                data_type = parts[0]
                salt_hex = parts[1]
                payload = parts[2]

                salt = bytes.fromhex(salt_hex)
                key, _ = generate_key_from_password(password, salt=salt)

                if data_type == "TEXT":
                    message = decrypt_message(payload, key)
                    return render_template("result.html", message=message, file_url=None)

                elif data_type == "FILE":
                    original_name, enc_file = payload.split("::", 1)
                    decrypted_b64 = decrypt_message(enc_file, key)
                    file_bytes = base64.b64decode(decrypted_b64)

                    decoded_dir = os.path.join("static", "decoded")
                    os.makedirs(decoded_dir, exist_ok=True)

                    out_path = os.path.join(decoded_dir, original_name)
                    with open(out_path, "wb") as f:
                        f.write(file_bytes)

                    file_url = "/static/decoded/" + original_name
                    return render_template("result.html", message=None, file_url=file_url)

                elif data_type == "BOTH":
                    enc_msg_text, original_name, enc_file = payload.split("::", 2)
                    message = decrypt_message(enc_msg_text, key)
                    decrypted_b64 = decrypt_message(enc_file, key)
                    file_bytes = base64.b64decode(decrypted_b64)

                    decoded_dir = os.path.join("static", "decoded")
                    os.makedirs(decoded_dir, exist_ok=True)

                    out_path = os.path.join(decoded_dir, original_name)
                    with open(out_path, "wb") as f:
                        f.write(file_bytes)

                    file_url = "/static/decoded/" + original_name
                    return render_template("result.html", message=message, file_url=file_url)

                else:
                    return render_template("result.html", message="Unknown format!", file_url=None)

            except Exception as e:
                return render_template("result.html", message="Incorrect password or corrupted image!", file_url=None)

    return render_template("decode.html")


if __name__ == "__main__":
    app.run(debug=True)