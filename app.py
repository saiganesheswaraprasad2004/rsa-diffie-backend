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

# Diffie-Hellman Key Exchange
def diffie_hellman_demo():
    p = 23  # Prime number
    g = 5   # Primitive root
    
    a = random.randint(1, p-1)
    b = random.randint(1, p-1)
    
    A = (g ** a) % p
    B = (g ** b) % p
    
    shared_secret_A = (B ** a) % p
    shared_secret_B = (A ** b) % p
    
    return shared_secret_A

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/rsa", methods=["POST"])
def rsa():
    data = request.get_json()
    message = data.get("message", "")
    encrypted, decrypted = rsa_demo(message)
    return jsonify({"encrypted": encrypted, "decrypted": decrypted})

@app.route("/diffie-hellman", methods=["GET"])
def diffie_hellman():
    secret = diffie_hellman_demo()
    return jsonify({"shared_secret": secret})

if __name__ == "__main__":
    app.run(debug=True)
