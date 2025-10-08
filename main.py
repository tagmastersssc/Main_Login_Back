from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import hashlib
import secrets
from pathlib import Path
from typing import Generator

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect("users.db")
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
    _ensure_user_columns(conn)
    try:
        yield conn
    finally:
        conn.close()


def _ensure_user_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "first_name" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
    if "last_name" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN last_name TEXT")


class RegisterRequest(BaseModel):
    email: str
    password: str
    first_name: str
    last_name: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    code: str
    new_password: str


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@app.post("/register")
def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    email = req.email.strip().lower()
    first_name = req.first_name.strip()
    last_name = req.last_name.strip()

    if not first_name or not last_name:
        raise HTTPException(status_code=400, detail="Nombre y apellido son obligatorios")

    if not email:
        raise HTTPException(status_code=400, detail="El correo es obligatorio")

    hashed = hash_password(req.password)
    try:
        db.execute(
            "INSERT INTO users (username, email, password, first_name, last_name) "
            "VALUES (?, ?, ?, ?, ?)",
            (email, email, hashed, first_name, last_name),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")
    return {"message": "User created"}


@app.post("/login")
def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = req.email.strip().lower()
    cur = db.execute(
        "SELECT password, first_name, last_name FROM users WHERE email = ?",
        (email,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    hashed = hash_password(req.password)
    if row["password"] != hashed:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = secrets.token_urlsafe(32)
    keys = row.keys()
    first_name = row["first_name"] if "first_name" in keys else None
    last_name = row["last_name"] if "last_name" in keys else None
    return {
        "token": token,
        "first_name": first_name,
        "last_name": last_name,
    }


@app.post("/forgot-password")
def forgot_password(
    req: ForgotPasswordRequest, db: sqlite3.Connection = Depends(get_db)
):
    email = req.email.strip().lower()
    cur = db.execute("SELECT id FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Email not found")
    token = f"{secrets.randbelow(1_000_000):06d}"
    db.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, row["id"]))
    db.commit()
    _send_reset_code_via_email(email, token)
    return {"message": "Hemos enviado un código de verificación a tu correo."}


@app.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: sqlite3.Connection = Depends(get_db)):
    cur = db.execute("SELECT id FROM users WHERE reset_token = ?", (req.code,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Código de recuperación invalido")
    hashed = hash_password(req.new_password)
    db.execute(
        "UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
        (hashed, row["id"]),
    )
    db.commit()
    return {"message": "Password updated"}


OUTBOX_DIR = Path("outbox")


def _sanitize_email_for_filename(email: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in email.lower())


def _send_reset_code_via_email(email: str, code: str) -> None:
    """Simulate sending the reset code via email by writing to the outbox."""
    OUTBOX_DIR.mkdir(exist_ok=True)
    filename = OUTBOX_DIR / f"reset_{_sanitize_email_for_filename(email)}.txt"
    filename.write_text(
        (
            "Has solicitado restablecer tu contraseña en BilAI.\n"
            f"Código de verificación: {code}\n"
            "Ingresa este código de seis dígitos para continuar con el proceso.\n"
        ),
        encoding="utf-8",
    )