import os
import sqlite3
from flask import Flask, request, jsonify
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta, timezone

# Flask app setup
app = Flask(__name__)

# Initialize rate limiter explicitly
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"]
)

# AES encryption key
AES_KEY = os.environ.get("NOT_MY_KEY", b"secure_key_for_aes_32_bytes_padding")[:32]

# Database path
DB_PATH = "totally_not_my_privateKeys.db"

def get_db_connection():
    """Establish a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def encrypt_key(data):
    """Encrypt a private key using AES encryption."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    iv = cipher.iv
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv + encrypted

@app.route("/", methods=["GET"])
def home():
    """Health check endpoint."""
    return "JWKS Server Project 3 - Running!"

@app.route("/store_key", methods=["POST"])
def store_key():
    """Store an encrypted private key with an expiration time."""
    try:
        data = request.json
        private_key = data.get("private_key")

        if not private_key:
            return jsonify({"error": "private_key is required"}), 400

        # Encrypt the private key
        encrypted_key = encrypt_key(private_key)
        expiry = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())

        # Insert into database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (sqlite3.Binary(encrypted_key), expiry)
        )
        conn.commit()
        kid = cursor.lastrowid
        conn.close()

        return jsonify({"message": "Key stored successfully", "kid": kid}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_keys", methods=["GET"])
def get_keys():
    """Retrieve all encrypted private keys from the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT kid, key, exp FROM keys;")
        keys = cursor.fetchall()
        conn.close()

        keys_list = [
            {
                "kid": row["kid"],
                "key": b64encode(row["key"]).decode(),
                "exp": row["exp"]
            }
            for row in keys
        ]

        return jsonify({"keys": keys_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/register", methods=["POST"])
def register_user():
    """Register a new user with a hashed password."""
    try:
        data = request.json
        username = data.get("username")
        email = data.get("email")

        if not username or not email:
            return jsonify({"error": "username and email are required"}), 400

        password = str(os.urandom(16).hex())
        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email),
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "User registered successfully", "username": username, "password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth", methods=["POST"])
@limiter.limit("10 per second")
def authenticate_user():
    """Authenticate a user and log the attempt."""
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "username and password are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            conn.close()
            return jsonify({"error": "Invalid username or password"}), 401

        # Log the authentication attempt
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (request.remote_addr, user["id"])
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "Authentication successful"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=8080, debug=True)
