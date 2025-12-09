Image Encryptor (Flask Steganography + AES Encryption)

A secure image-based message encryption system built with Flask, LSB steganography, and AES-GCM encryption.
This application allows users to:

✔ Encrypt a message using a password
✔ Convert the encrypted output into binary bits
✔ Hide the encrypted bits inside an image (LSB)
✔ Download the encoded image
✔ Upload an encoded image + password to reveal the hidden message

 Features
 1. AES-GCM Encryption

Your message is encrypted using a key derived from the password via PBKDF2.

Strong encryption

Random salt per message

Tamper detection

 2. LSB Steganography

The encrypted message is hidden inside the Least Significant Bits of the image's RGB pixels.

The app uses a binary bit stream (0/1) so the image visibly does not change.

 3. Encode Message into Image

Upload an image → enter message → enter password → download encoded image.

 4. Decode Message from Image

Upload encoded image → enter password → extract + decrypt hidden message.

 5. Clean Code Architecture

encoder.py → LSB encoding

decoder.py → LSB decoding

crypto_utils.py → Encryption logic

utils.py → Text/bit conversion

Flask routes in app.py

 Project Structure
project/
│── app.py
│── encoder.py
│── decoder.py
│── crypto_utils.py
│── utils.py
│── requirements.txt
│── uploads/              # (ignored by Git)
│── templates/
│   ├── index.html
│   ├── encode.html
│   ├── decode.html
│   └── result.html
│── static/
│── .gitignore
│── README.md

 Installation
1. Clone the repository
git clone https://github.com/your-username/image-encryptor.git
cd image-encryptor

2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate   # Windows

3. Install dependencies
pip install -r requirements.txt

 Run the Application
python app.py


App runs at:

http://127.0.0.1:5000

 How It Works (Technical Flow)
Encoding

User enters message + password

generate_key_from_password() creates AES key using salt

encrypt_message() → encrypted text

salt + ":" + encrypted_text combined

text_to_bits() → converts full data to binary

encode_image() hides bits inside RGB LSB bits

User downloads encoded image

Decoding

User uploads encoded image + password

decode_image() extracts bits

bits_to_text() reconstructs encrypted string

Salt is separated

AES key is regenerated using the same salt

Decrypted message is shown

 Security Notes

No passwords are stored

Each message uses unique salt

AES-GCM ensures message authenticity

.gitignore prevents uploading sensitive files (uploads, env, etc.)

 License

MIT License — free to use, modify, and distribute.
