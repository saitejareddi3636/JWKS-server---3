import pytest
import sqlite3
from main import app, get_db_connection

@pytest.fixture
def client():
    """
    Create a test client for the Flask application.
    Set up a clean database for each test.
    """
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            conn = get_db_connection()
            try:
                conn.executescript(
                    """
                    DROP TABLE IF EXISTS keys;
                    CREATE TABLE keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        encrypted_key TEXT NOT NULL,
                        iv TEXT NOT NULL,
                        kid TEXT NOT NULL UNIQUE
                    );
                    DROP TABLE IF EXISTS users;
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        email TEXT UNIQUE
                    );
                    DROP TABLE IF EXISTS auth_logs;
                    CREATE TABLE auth_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_ip TEXT NOT NULL,
                        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        user_id INTEGER
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()
        yield client


def test_store_key(client):
    """
    Test the /store_key endpoint.
    """
    response = client.post("/store_key", json={"private_key": "test_key"})
    assert response.status_code == 201
    data = response.get_json()
    assert "kid" in data
    assert data["message"] == "Key stored successfully"


def test_get_keys(client):
    """
    Test the /get_keys endpoint.
    """
    client.post("/store_key", json={"private_key": "test_key"})
    response = client.get("/get_keys")
    assert response.status_code == 200
    data = response.get_json()
    assert len(data["keys"]) == 1
    assert "kid" in data["keys"][0]


def test_register_user(client):
    """
    Test the /register endpoint.
    """
    response = client.post(
        "/register", json={"username": "test_user", "email": "test_user@example.com"}
    )
    assert response.status_code == 201
    data = response.get_json()
    assert "password" in data
    assert data["message"] == "User registered successfully"


def test_auth_user(client):
    """
    Test the /auth endpoint.
    """
    response = client.post(
        "/register", json={"username": "test_user", "email": "test_user@example.com"}
    )
    data = response.get_json()
    password = data["password"]

    auth_response = client.post(
        "/auth", json={"username": "test_user", "password": password}
    )
    assert auth_response.status_code == 200
    auth_data = auth_response.get_json()
    assert auth_data["message"] == "Authentication successful"

    # Test invalid password
    invalid_auth_response = client.post(
        "/auth", json={"username": "test_user", "password": "invalid_password"}
    )
    assert invalid_auth_response.status_code == 401
    invalid_auth_data = invalid_auth_response.get_json()
    assert invalid_auth_data["error"] == "Invalid username or password"
