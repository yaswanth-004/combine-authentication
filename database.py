"""
database.py — SQLite user store with token management

Schema
------
email         — primary key (unique per user)
username      — display name from Google / Auth0
picture       — profile photo URL from Google
access_token  — JWT; short-lived (1 day)
refresh_token — long-lived; used to silently renew access_token
expires_at    — ISO-8601 UTC; when current access_token expires
created_at    — first login
updated_at    — last token refresh

VERCEL FIX: Uses /tmp on Vercel (writable), instance/ locally
"""
import os
import sqlite3
import smtplib
from email.mime.text import MIMEText

# ========== DATABASE PATH - VERCEL COMPATIBLE ==========
if os.getenv('VERCEL'):
    # Vercel has read-only filesystem, use /tmp (writable)
    DB_PATH = '/tmp/users.db'
    print("[DB] Using Vercel mode: /tmp/users.db")
else:
    # Local development
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "users.db")
    print(f"[DB] Using local mode: {DB_PATH}")


def _connect():
    """Connect to database, create folder only if NOT on Vercel"""
    try:
        # Only create directories if NOT on Vercel (local development)
        if not os.getenv('VERCEL'):
            os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    
    except Exception as e:
        print(f"[DB ERROR] Connection failed: {e}")
        raise


def init_db():
    """Initialize database tables"""
    try:
        conn = _connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email         TEXT PRIMARY KEY,
                username      TEXT NOT NULL,
                picture       TEXT DEFAULT '',
                access_token  TEXT NOT NULL,
                refresh_token TEXT NOT NULL DEFAULT '',
                expires_at    TEXT NOT NULL,
                created_at    TEXT DEFAULT (datetime('now', 'utc')),
                updated_at    TEXT DEFAULT (datetime('now', 'utc'))
            )
        """)
        conn.commit()
        conn.close()
        print("[DB] ✅ users table ready")
    
    except Exception as e:
        print(f"[DB ERROR] Failed to initialize: {e}")
        raise


def save_user(email, username, picture, access_token, refresh_token, expires_at):
    """Save or update user with tokens"""
    try:
        conn = _connect()
        conn.execute("""
            INSERT INTO users (email, username, picture, access_token, refresh_token, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                username      = excluded.username,
                picture       = excluded.picture,
                access_token  = excluded.access_token,
                refresh_token = excluded.refresh_token,
                expires_at    = excluded.expires_at,
                updated_at    = datetime('now', 'utc')
        """, (email, username, picture, access_token, refresh_token, expires_at))
        conn.commit()
        conn.close()
        print(f"[DB] ✅ User saved: {email}")
    
    except Exception as e:
        print(f"[DB ERROR] Failed to save user {email}: {e}")
        raise


def get_user_by_email(email):
    """Get user by email"""
    try:
        conn = _connect()
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        return dict(row) if row else None
    
    except Exception as e:
        print(f"[DB ERROR] Failed to get user {email}: {e}")
        return None


def get_all_users():
    """Get all users from database"""
    try:
        conn = _connect()
        rows = conn.execute("SELECT * FROM users").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    
    except Exception as e:
        print(f"[DB ERROR] Failed to get all users: {e}")
        return []


def update_tokens(email, access_token, refresh_token, expires_at):
    """Update user tokens"""
    try:
        conn = _connect()
        conn.execute("""
            UPDATE users
            SET access_token  = ?,
                refresh_token = ?,
                expires_at    = ?,
                updated_at    = datetime('now', 'utc')
            WHERE email = ?
        """, (access_token, refresh_token, expires_at, email))
        conn.commit()
        conn.close()
        print(f"[DB] ✅ Tokens updated for: {email}")
    
    except Exception as e:
        print(f"[DB ERROR] Failed to update tokens for {email}: {e}")
        raise


def send_session_expired_email(email, username):
    """Send email when user session expires"""
    host      = os.environ.get("SMTP_HOST", "")
    port      = int(os.environ.get("SMTP_PORT", "587"))
    user      = os.environ.get("SMTP_USER", "")
    password  = os.environ.get("SMTP_PASSWORD", "")
    from_addr = os.environ.get("FROM_EMAIL", user)
    app_url   = os.environ.get("APP_BASE_URL", "https://combine-authentication.vercel.app")

    if not all([host, user, password]):
        print(f"[email] SMTP not configured — skipping email to {email}")
        return

    body = f"""Hi {username},

Your session on Auth Learning Hub has expired (1-day refresh token lifetime reached).

Please log in again here:
{app_url}/login

— Auth Learning Hub
"""
    msg = MIMEText(body, "plain")
    msg["Subject"] = "Your session has expired — please log in again"
    msg["From"]    = from_addr
    msg["To"]      = email

    try:
        with smtplib.SMTP(host, port) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(msg)
        print(f"[email] ✅ Sent session-expired notice to {email}")
    
    except Exception as exc:
        print(f"[email] ❌ Failed to send to {email}: {exc}")
