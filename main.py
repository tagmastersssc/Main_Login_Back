from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import hashlib
import secrets
from typing import Generator

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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
        "reset_token TEXT"  # noqa: E501
        ")"
    )
    try:
        yield conn
    finally:
        conn.close()


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@app.post("/register")
def register(req: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    email = req.email.strip().lower()
    hashed = hash_password(req.password)
    try:
        db.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (email, email, hashed),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    return {"message": "Usuario creado"}


@app.post("/login")
def login(req: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    email = req.email.strip().lower()
    cur = db.execute("SELECT password FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Dirección de email o contraseña incorrectas.")
    hashed = hash_password(req.password)
    if row["password"] != hashed:
        raise HTTPException(status_code=400, detail="Dirección de email o contraseña incorrectas.")
    token = secrets.token_urlsafe(32)
    return {"token": token}


@app.post("/forgot-password")
def forgot_password(
    req: ForgotPasswordRequest, db: sqlite3.Connection = Depends(get_db)
):
    email = req.email.strip().lower()
    cur = db.execute("SELECT id FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Dirección de email no encontrada.")
    token = secrets.token_urlsafe(32)
    db.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, row["id"]))
    db.commit()
    return {"reset_token": token}


@app.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: sqlite3.Connection = Depends(get_db)):
    cur = db.execute("SELECT id FROM users WHERE reset_token = ?", (req.token,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Invalid token")
    hashed = hash_password(req.new_password)
    db.execute(
        "UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
        (hashed, row["id"]),
    )
    db.commit()
    return {"message": "Contraseña actualizada"}