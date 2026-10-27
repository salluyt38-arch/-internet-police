import hashlib
import os
import secrets
import time
from .database import get_connection, log_audit

ROLES = {
    "ADMIN": "Admin",
    "ANALYST": "Analyst",
    "READONLY": "ReadOnly"
}

# Role hierarchy: Admin (3) > Analyst (2) > ReadOnly (1)
ROLE_HIERARCHY = {
    "Admin": 3,
    "Analyst": 2,
    "ReadOnly": 1
}

# In-memory active session tokens: token -> {username, role, expires_at, ip}
ACTIVE_SESSIONS = {}
SESSION_TTL_SECONDS = 86400  # 24 hours

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}:{hashed}", salt

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        salt, _ = stored_hash.split(":", 1)
        expected, _ = hash_password(password, salt)
        return secrets.compare_digest(stored_hash, expected)
    except Exception:
        return False

def init_default_users():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]
    if count == 0:
        default_users = [
            ("admin", "AdminSecure2026!", ROLES["ADMIN"]),
            ("analyst", "AnalystSafe2026!", ROLES["ANALYST"]),
            ("viewer", "ViewerReadOnly2026!", ROLES["READONLY"])
        ]
        now = time.time()
        for u, p, r in default_users:
            pwd_hash, _ = hash_password(p)
            c.execute(
                "INSERT INTO users (username, password_hash, role, created_at, last_login) VALUES (?, ?, ?, ?, ?)",
                (u, pwd_hash, r, now, 0)
            )
        conn.commit()
    conn.close()

def authenticate_user(username: str, password: str, client_ip: str = "127.0.0.1") -> dict:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username.strip(),))
    row = c.fetchone()
    
    if not row or not verify_password(row["password_hash"], password):
        conn.close()
        log_audit(username or "unknown", "None", "AUTH_LOGIN", "/api/auth/login", "DENIED", client_ip, "Invalid credentials")
        return {"success": False, "error": "Invalid username or password"}

    role = row["role"]
    c.execute("UPDATE users SET last_login = ? WHERE username = ?", (time.time(), username))
    conn.commit()
    conn.close()

    token = f"ip_sess_{secrets.token_urlsafe(32)}"
    expires_at = time.time() + SESSION_TTL_SECONDS
    ACTIVE_SESSIONS[token] = {
        "username": username,
        "role": role,
        "expires_at": expires_at,
        "ip": client_ip
    }

    log_audit(username, role, "AUTH_LOGIN", "/api/auth/login", "SUCCESS", client_ip, f"User authenticated with role {role}")
    return {
        "success": True,
        "token": token,
        "username": username,
        "role": role,
        "expires_at": expires_at
    }

def verify_token(token: str) -> dict | None:
    if not token:
        return None
    session = ACTIVE_SESSIONS.get(token)
    if not session:
        return None
    if time.time() > session["expires_at"]:
        del ACTIVE_SESSIONS[token]
        return None
    return session

def check_permission(user_role: str, min_required_role: str) -> bool:
    user_level = ROLE_HIERARCHY.get(user_role, 0)
    required_level = ROLE_HIERARCHY.get(min_required_role, 3)
    return user_level >= required_level

def list_users() -> list[dict]:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at, last_login FROM users ORDER BY id ASC")
    users = [dict(r) for r in c.fetchall()]
    conn.close()
    return users
