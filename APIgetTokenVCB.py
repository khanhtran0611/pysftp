from flask import Flask, request, jsonify
import time
import json
import jwt  # PyJWT
from pathlib import Path

app = Flask(__name__)

# Load client credentials từ file
with open("clients.json") as f:
    CLIENTS = json.load(f)

# Đọc private key từ file
private_key = Path("private.pem").read_text()
JWT_ALGORITHM = "RS256"
JWT_EXPIRATION_SECONDS = 3600

@app.route("/api/VCBPayment/GetToken", methods=["POST"])
def get_token():
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    grant_type = request.form.get("grant_type")
    print(CLIENTS)
    print(request.form)
    if grant_type != "client_credentials":
        return jsonify({
            "error": "unsupported_grant_type",
            "error_description": "Only client_credentials is supported."
        }), 400

    if client_id not in CLIENTS or CLIENTS[client_id] != client_secret:
        return jsonify({
            "error": "invalid_client",
            "error_description": f"A valid OAuth client could not be found for client_id: {client_id}"
        }), 401

    payload = {
        "sub": client_id,
        "aud": client_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRATION_SECONDS,
        "scope": "default"
    }

    token = jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)

    return jsonify({
        "access_token": token,
        "scope": "default",
        "token_type": "Bearer",
        "expires_in": JWT_EXPIRATION_SECONDS
    })

@app.route("/", methods=["GET"])
def hello():
    return jsonify({"message": "VCB Token Server running."})

if __name__ == "__main__":
    app.run(port=5000, debug=True)
