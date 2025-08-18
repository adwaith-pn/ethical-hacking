from flask import Flask, send_from_directory
import os
from flask import request, jsonify
from cryptography.fernet import Fernet
import json

app = Flask(__name__)

# Serve main HTML dashboard
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# Serve encrypted log file
@app.route('/logs')
def logs():
    return send_from_directory('.', 'logs.enc')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    key = data['key'].encode()
    cipher = Fernet(key)
    try:
        decrypted = cipher.decrypt(data['ciphertext'].encode())
        return decrypted.decode()
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True, port=5000)

