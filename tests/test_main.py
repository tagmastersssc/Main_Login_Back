import os
import shutil
import sqlite3
import sys
from pathlib import Path
from fastapi.testclient import TestClient

TEST_DB_PATH = "test.db"
OUTBOX_PATH = Path("outbox")

if os.path.exists(TEST_DB_PATH):
    os.remove(TEST_DB_PATH)

if OUTBOX_PATH.exists():
    shutil.rmtree(OUTBOX_PATH)

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import main  # noqa: E402


def override_get_db():
    conn = sqlite3.connect(TEST_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("  # noqa: E501
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE,"
        "email TEXT UNIQUE,"
        "password TEXT,"
        "first_name TEXT,"
        "last_name TEXT,"
        "reset_token TEXT"  # noqa: E501
        ")"
    )
    main._ensure_user_columns(conn)
    try:
        yield conn
    finally:
        conn.close()


main.app.dependency_overrides[main.get_db] = override_get_db
client = TestClient(main.app)


def test_register_login_and_reset():
    resp = client.post(
        "/register",
        json={
            "email": "a@example.com",
            "password": "secret",
            "first_name": "Ana",
            "last_name": "Ramírez",
        },
    )
    assert resp.status_code == 200

    resp = client.post(
        "/login", json={"email": "a@example.com", "password": "secret"}
    )
    assert resp.status_code == 200
    data = resp.json()
    token = data["token"]
    assert token
    assert data["first_name"] == "Ana"
    assert data["last_name"] == "Ramírez"

    resp = client.post("/forgot-password", json={"email": "a@example.com"})
    assert resp.status_code == 200
    assert resp.json()["message"]

    outbox_file = OUTBOX_PATH / (
        f"reset_{main._sanitize_email_for_filename('a@example.com')}.txt"
    )
    assert outbox_file.exists()
    contents = outbox_file.read_text(encoding="utf-8")
    reset_token = "".join(ch for ch in contents if ch.isdigit())[-6:]
    assert len(reset_token) == 6

    resp = client.post(
        "/reset-password",
        json={"code": reset_token, "new_password": "newsecret"},
    )
    assert resp.status_code == 200

    resp = client.post(
        "/login", json={"email": "a@example.com", "password": "newsecret"}
    )
    assert resp.status_code == 200