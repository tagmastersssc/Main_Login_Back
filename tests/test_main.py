import os
import sqlite3
import sys
from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import main  # noqa: E402


def override_get_db():
    conn = sqlite3.connect("test.db")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("  # noqa: E501
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE,"
        "email TEXT UNIQUE,"
        "password TEXT,"
        "reset_token TEXT"  # noqa: E501
        ")"
    )
    try:
        yield conn
    finally:
        conn.close()


main.app.dependency_overrides[main.get_db] = override_get_db
client = TestClient(main.app)


def test_register_login_and_reset():
    resp = client.post(
        "/register",
        json={"username": "alice", "email": "a@example.com", "password": "secret"},
    )
    assert resp.status_code == 200

    resp = client.post(
        "/login", json={"username": "alice", "password": "secret"}
    )
    assert resp.status_code == 200
    token = resp.json()["token"]
    assert token

    resp = client.post("/forgot-password", json={"email": "a@example.com"})
    assert resp.status_code == 200
    reset_token = resp.json()["reset_token"]

    resp = client.post(
        "/reset-password",
        json={"token": reset_token, "new_password": "newsecret"},
    )
    assert resp.status_code == 200

    resp = client.post(
        "/login", json={"username": "alice", "password": "newsecret"}
    )
    assert resp.status_code == 200