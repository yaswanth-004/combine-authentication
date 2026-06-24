"""
database.py — PostgreSQL user store (Neon / any Postgres URL)

Falls back to SQLite for local development.
On Vercel, set DATABASE_URL env var to your Neon/Postgres connection string.
"""
import os
import sqlite3
import smtplib
from email.mime.text import MIMEText

DATABASE_URL = os.environ.get("DATABASE_URL", "")
USE_POSTGRES  = bool(DATABASE_URL)

# ── SQLite fallback (local dev) ──────────────────────────────────────────────
SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "users.db")

def _pg():
    import psycopg2, psycopg2.extras
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def _sqlite():
    os.makedirs(os.path.dirname(SQLITE_PATH), exist_ok=True)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Init ─────────────────────────────────────────────────────────────────────

def init_db():
    if USE_POSTGRES:
        conn = _pg()
        cur  = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email         TEXT PRIMARY KEY,
                username      TEXT NOT NULL,
                picture       TEXT DEFAULT '',
                access_token  TEXT NOT NULL,
                refresh_token TEXT NOT NULL DEFAULT '',
                expires_at    TEXT NOT NULL,
                created_at    TIMESTAMPTZ DEFAULT NOW(),
                updated_at    TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        conn.commit()
        cur.close(); conn.close()
        print("[DB] ✅ PostgreSQL users table ready")
    else:
        conn = _sqlite()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email         TEXT PRIMARY KEY,
                username      TEXT NOT NULL,
                picture       TEXT DEFAULT '',
                access_token  TEXT NOT NULL,
                refresh_token TEXT NOT NULL DEFAULT '',
                expires_at    TEXT NOT NULL,
                created_at    TEXT DEFAULT (datetime('now','utc')),
                updated_at    TEXT DEFAULT (datetime('now','utc'))
            )
        """)
        conn.commit(); conn.close()
        print("[DB] ✅ SQLite users table ready (local)")

# ── Save / upsert user ───────────────────────────────────────────────────────

def save_user(email, username, picture, access_token, refresh_token, expires_at):
    if USE_POSTGRES:
        conn = _pg(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (email, username, picture, access_token, refresh_token, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (email) DO UPDATE SET
                username      = EXCLUDED.username,
                picture       = EXCLUDED.picture,
                access_token  = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                expires_at    = EXCLUDED.expires_at,
                updated_at    = NOW()
        """, (email, username, picture, access_token, refresh_token, expires_at))
        conn.commit(); cur.close(); conn.close()
    else:
        conn = _sqlite()
        conn.execute("""
            INSERT INTO users (email, username, picture, access_token, refresh_token, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                username=excluded.username, picture=excluded.picture,
                access_token=excluded.access_token, refresh_token=excluded.refresh_token,
                expires_at=excluded.expires_at, updated_at=datetime('now','utc')
        """, (email, username, picture, access_token, refresh_token, expires_at))
        conn.commit(); conn.close()
    print(f"[DB] ✅ User saved: {email}")

# ── Get user ─────────────────────────────────────────────────────────────────

def get_user_by_email(email):
    try:
        if USE_POSTGRES:
            import psycopg2.extras
            conn = _pg(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            cur.close(); conn.close()
            return dict(row) if row else None
        else:
            conn = _sqlite()
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            conn.close()
            return dict(row) if row else None
    except Exception as e:
        print(f"[DB ERROR] get_user_by_email: {e}")
        return None

# ── Get all users ─────────────────────────────────────────────────────────────

def get_all_users():
    try:
        if USE_POSTGRES:
            import psycopg2.extras
            conn = _pg(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM users")
            rows = cur.fetchall()
            cur.close(); conn.close()
            return [dict(r) for r in rows]
        else:
            conn = _sqlite()
            rows = conn.execute("SELECT * FROM users").fetchall()
            conn.close()
            return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB ERROR] get_all_users: {e}")
        return []

# ── Update tokens ─────────────────────────────────────────────────────────────

def update_tokens(email, access_token, refresh_token, expires_at):
    if USE_POSTGRES:
        conn = _pg(); cur = conn.cursor()
        cur.execute("""
            UPDATE users SET access_token=%s, refresh_token=%s, expires_at=%s, updated_at=NOW()
            WHERE email=%s
        """, (access_token, refresh_token, expires_at, email))
        conn.commit(); cur.close(); conn.close()
    else:
        conn = _sqlite()
        conn.execute("""
            UPDATE users SET access_token=?, refresh_token=?, expires_at=?,
            updated_at=datetime('now','utc') WHERE email=?
        """, (access_token, refresh_token, expires_at, email))
        conn.commit(); conn.close()
    print(f"[DB] ✅ Tokens updated: {email}")

# ── Send expiry email ─────────────────────────────────────────────────────────

def send_session_expired_email(email, username):
    host     = os.environ.get("SMTP_HOST", "")
    port     = int(os.environ.get("SMTP_PORT", "587"))
    user     = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    from_addr= os.environ.get("FROM_EMAIL", user)
    app_url  = os.environ.get("APP_BASE_URL", "https://combine-authentication-a4vl.vercel.app")

    if not all([host, user, password]):
        print(f"[email] SMTP not configured — skipping for {email}")
        return

    msg = MIMEText(f"Hi {username},\n\nYour session has expired.\nLog in again: {app_url}/login\n\n— Auth Learning Hub")
    msg["Subject"] = "Your session has expired"
    msg["From"]    = from_addr
    msg["To"]      = email

    try:
        with smtplib.SMTP(host, port) as smtp:
            smtp.ehlo(); smtp.starttls(); smtp.login(user, password); smtp.send_message(msg)
        print(f"[email] ✅ Sent to {email}")
    except Exception as e:
        print(f"[email] ❌ Failed: {e}")
