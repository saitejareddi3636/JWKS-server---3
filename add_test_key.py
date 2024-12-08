import sqlite3
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

AES_KEY = os.environ.get("NOT_MY_KEY", "default_secure_key_16")[:16].encode()

def encrypt_key(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    iv = cipher.iv
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return b64encode(encrypted).decode(), b64encode(iv).decode()

if __name__ == "__main__":
    conn = sqlite3.connect("totally_not_my_privateKeys.db")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_key TEXT NOT NULL,
            iv TEXT NOT NULL,
            kid TEXT NOT NULL UNIQUE
        )
        """
    )
    conn.commit()

    encrypted_key, iv = encrypt_key("test_private_key")
    conn.execute("INSERT INTO keys (encrypted_key, iv, kid) VALUES (?, ?, ?)", (encrypted_key, iv, "testKeyID"))
    conn.commit()
    conn.close()
