from flask import Flask, request, jsonify, render_template
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random

app = Flask(__name__)

# RSA Encryption & Decryption
def rsa_demo(message):
    key = RSA.generate(1024)
    public_key = key.publickey()
    
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_msg = cipher.encrypt(message.encode())
    
    decipher = PKCS1_OAEP.new(key)
    decrypted_msg = decipher.decrypt(encrypted_msg)
    
    return encrypted_msg.hex(), decrypted_msg.decode()

# Diffie-Hellman Key Exchange with User-Provided Private Keys
def diffie_hellman_demo(a, b):
    p = 23  # Prime number
    g = 5   # Primitive root
    
    A = (g ** a) % p
    B = (g ** b) % p
    
    shared_secret_A = (B ** a) % p
    shared_secret_B = (A ** b) % p
    
    return shared_secret_A if shared_secret_A == shared_secret_B else "Key Mismatch"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/rsa", methods=["POST"])
def rsa():
    data = request.get_json()
    message = data.get("message", "")
    
    encrypted, decrypted = rsa_demo(message)
    return jsonify({"encrypted": encrypted, "decrypted": decrypted})

@app.route("/diffie-hellman", methods=["POST"])
def diffie_hellman():
    data = request.get_json()
    a = int(data.get("private_key_a", random.randint(1, 22)))
    b = int(data.get("private_key_b", random.randint(1, 22)))
    
    secret = diffie_hellman_demo(a, b)
    return jsonify({"shared_secret": secret})

if __name__ == "__main__":
    app.run(debug=True)
