import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "internet_police.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    # Security Intercept Logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            client_ip TEXT,
            subsystem TEXT,  -- DNS, WAF, DLP, THREAT, POLICE
            target TEXT,
            action TEXT,     -- BLOCKED, ALLOWED, ALERT
            risk_level TEXT, -- LOW, MEDIUM, HIGH, CRITICAL
            details TEXT
        )
    ''')
    
    # 9:00 PM Daily Nightly Dispatches (Summaries)
    c.execute('''
        CREATE TABLE IF NOT EXISTS dispatches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dispatch_date TEXT,
            timestamp REAL,
            total_events INTEGER,
            ads_blocked INTEGER,
            threats_blocked INTEGER,
            dlp_leaks_prevented INTEGER,
            summary_text TEXT
        )
    ''')

    # Device Permissions Granted by User
    c.execute('''
        CREATE TABLE IF NOT EXISTS permissions (
            name TEXT PRIMARY KEY,
            is_granted INTEGER DEFAULT 0,
            granted_at REAL
        )
    ''')

    # Key-Value App Settings
    c.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    # Custom Blocklist & Allowlist
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            reason TEXT,
            added_at REAL,
            is_enabled INTEGER DEFAULT 1
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            reason TEXT,
            added_at REAL
        )
    ''')

    # Seed initial settings
    defaults = [
        ("setup_completed", "0"),
        ("ai_provider", "groq"),
        ("ai_api_key", ""),
        ("voice_enabled", "1"),
        ("voice_accent", "hi-IN"),
        ("theme", "ios17-titanium"),
        ("nightly_dispatch_time", "21:00"),
        ("quad9_doh", "https://dns.quad9.net/dns-query"),
        ("dns_port", "5353"),
        ("web_port", "8080"),
        ("wazuh_host", "https://127.0.0.1:55000"),
        ("wazuh_user", "wazuh-wui"),
        ("wazuh_pass", ""),
        ("allowed_targets", "localhost, 127.0.0.1, ::1, example.com, scanme.nmap.org")
    ]
    for k, v in defaults:
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

    # STIX 2.1 Threat Indicators
    c.execute('''
        CREATE TABLE IF NOT EXISTS stix_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stix_id TEXT UNIQUE,
            type TEXT,            -- ipv4-addr, domain-name, url, file-hash, vulnerability
            value TEXT,
            confidence INTEGER,   -- 0 to 100
            severity TEXT,        -- LOW, MEDIUM, HIGH, CRITICAL
            mitre_technique TEXT, -- e.g. T1566.002, T1059.001
            description TEXT,
            source TEXT,
            created_at REAL,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # Authorized Scans Record
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE,
            target TEXT,
            scan_type TEXT,
            status TEXT,          -- PENDING, RUNNING, COMPLETED, FAILED, BLOCKED
            risk_score INTEGER,
            findings_json TEXT,
            remediation_json TEXT,
            performed_by TEXT,
            created_at REAL
        )
    ''')

    # Human-in-the-Loop (HITL) Approvals Queue
    c.execute('''
        CREATE TABLE IF NOT EXISTS hitl_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT UNIQUE,
            action_type TEXT,     -- SCAN_TARGET, BLOCK_IP, LOCK_WORKSTATION, FLUSH_DNS
            target TEXT,
            risk_level TEXT,      -- LOW, MEDIUM, HIGH, CRITICAL
            details TEXT,
            status TEXT,          -- PENDING, APPROVED, REJECTED
            requested_by TEXT,
            resolved_by TEXT,
            created_at REAL,
            resolved_at REAL
        )
    ''')

    # Immutable Audit Trail
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            actor TEXT,
            role TEXT,
            action TEXT,
            resource TEXT,
            result TEXT,          -- SUCCESS, DENIED, FAILED
            ip_address TEXT,
            details TEXT
        )
    ''')

    # User Accounts & RBAC
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,            -- Admin, Analyst, ReadOnly
            created_at REAL,
            last_login REAL
        )
    ''')

    conn.commit()
    conn.close()

def log_event(client_ip, subsystem, target, action, risk_level, details):
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO security_logs (timestamp, client_ip, subsystem, target, action, risk_level, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (time.time(), client_ip, subsystem, target, action, risk_level, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB Log Error] {e}")

def get_stats():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM security_logs")
    total_events = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM security_logs WHERE action = 'BLOCKED' AND subsystem = 'DNS'")
    blocked_ads = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM security_logs WHERE action = 'BLOCKED' AND subsystem IN ('THREAT', 'POLICE')")
    blocked_threats = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM security_logs WHERE subsystem = 'DLP'")
    dlp_alerts = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM security_logs WHERE action = 'BLOCKED' AND subsystem = 'WAF'")
    waf_blocks = c.fetchone()[0]
    conn.close()
    return {
        "total_events": total_events,
        "blocked_ads": blocked_ads,
        "blocked_threats": blocked_threats,
        "dlp_alerts": dlp_alerts,
        "waf_blocks": waf_blocks
    }

def get_recent_logs(limit=50):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_setting(key, default=""):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key, value):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()

def save_permission(name, is_granted):
    conn = get_connection()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO permissions (name, is_granted, granted_at) VALUES (?, ?, ?)",
              (name, 1 if is_granted else 0, time.time()))
    conn.commit()
    conn.close()

def are_all_permissions_granted():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM permissions WHERE is_granted = 1")
    count = c.fetchone()[0]
    conn.close()
    return count >= 4

def log_audit(actor, role, action, resource, result, ip_address, details):
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO audit_trail (timestamp, actor, role, action, resource, result, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (time.time(), actor, role, action, resource, result, ip_address, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB Audit Error] {e}")

def get_recent_audits(limit=50):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_trail ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

