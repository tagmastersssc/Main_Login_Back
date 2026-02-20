from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import hashlib
import secrets
from pathlib import Path
from typing import Generator
import os

app = FastAPI()

def _parse_allowed_origins() -> list[str]:
    raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
    origins = [item.strip() for item in raw_origins.split(",") if item.strip()]
    return origins or ["*"]

allowed_origins = _parse_allowed_origins()
allow_credentials = "*" not in allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db() -> Generator[sqlite3.Connection, None, None]:
    db_path = os.getenv("DATABASE_PATH", "users.db")
    conn = sqlite3.connect(db_path)
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
    _ensure_clients_table(conn)
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


def _ensure_clients_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS clients ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "tax_id TEXT UNIQUE,"
        "full_name TEXT NOT NULL,"
        "email TEXT NOT NULL"
        ")"
    )
    seed_clients(conn)


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


class ClientResponse(BaseModel):
    tax_id: str
    name: str
    email: str


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
        raise HTTPException(status_code=400, detail="Invalid token")
    hashed = hash_password(req.new_password)
    db.execute(
        "UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
        (hashed, row["id"]),
    )
    db.commit()
    return {"message": "Password updated"}


@app.get("/clients/{tax_id}", response_model=ClientResponse)
def get_client(tax_id: str, db: sqlite3.Connection = Depends(get_db)):
    normalized = tax_id.strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="La cédula o NIT es obligatoria")
    cur = db.execute(
        "SELECT tax_id, full_name, email FROM clients WHERE tax_id = ?",
        (normalized,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    return {
        "tax_id": row["tax_id"],
        "name": row["full_name"],
        "email": row["email"],
    }


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


def seed_clients(conn: sqlite3.Connection) -> None:
    cur = conn.execute("SELECT COUNT(*) FROM clients")
    count = cur.fetchone()[0]
    if count:
        return
    sample_clients = [
        ("1014262008", "Wilbert Rozo", "wilberth.rozo@example.com"),
        ("1000285691", "Eduardo Vargas", "eduardo.vargas@example.com"),
        ("1192891795", "santiago Ramos", "santiago.ramos@example.com"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO clients (tax_id, full_name, email) VALUES (?, ?, ?)",
        sample_clients,
    )
    conn.commit()
