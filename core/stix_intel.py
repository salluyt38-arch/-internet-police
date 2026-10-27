import time
import secrets
import json
from .database import get_connection, log_audit

DEFAULT_STIX_INDICATORS = [
    {
        "type": "domain-name",
        "value": "cryptominer-pool.buzz",
        "confidence": 95,
        "severity": "CRITICAL",
        "mitre_technique": "T1496 - Resource Hijacking",
        "description": "Known XMRig cryptomining mining pool endpoint",
        "source": "Internet Police Community Feed"
    },
    {
        "type": "ipv4-addr",
        "value": "185.220.101.5",
        "confidence": 85,
        "severity": "HIGH",
        "mitre_technique": "T1090.003 - Tor Proxying",
        "description": "Tor exit node implicated in automated credential stuffing",
        "source": "Abuse.ch Feodo Tracker"
    },
    {
        "type": "url",
        "value": "http://secure-update-login.top/auth.php",
        "confidence": 90,
        "severity": "CRITICAL",
        "mitre_technique": "T1566.002 - Spearphishing Link",
        "description": "Credential harvester masquerading as corporate SSO portal",
        "source": "OpenPhish Community"
    },
    {
        "type": "file-hash",
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "confidence": 40,
        "severity": "LOW",
        "mitre_technique": "T1027 - Obfuscated Files",
        "description": "Empty SHA256 baseline test hash indicator",
        "source": "Baseline Integrity Check"
    },
    {
        "type": "vulnerability",
        "value": "CVE-2021-44228",
        "confidence": 100,
        "severity": "CRITICAL",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "description": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "source": "NIST NVD"
    }
]

class STIXIntelManager:
    """
    STIX 2.1 Aligned Threat Intelligence Indicator Manager.
    Provides local IOC ingestion, deduplication, MITRE ATT&CK correlation,
    and fast matching without requiring a resource-heavy OpenCTI/OpenSearch cluster.
    """
    def __init__(self):
        self._ensure_seeded()

    def _ensure_seeded(self):
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM stix_iocs")
        count = c.fetchone()[0]
        if count == 0:
            now = time.time()
            for ioc in DEFAULT_STIX_INDICATORS:
                stix_id = f"indicator--{secrets.token_hex(8)}"
                c.execute('''
                    INSERT INTO stix_iocs (stix_id, type, value, confidence, severity, mitre_technique, description, source, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ''', (
                    stix_id, ioc["type"], ioc["value"].lower().strip(), ioc["confidence"],
                    ioc["severity"], ioc["mitre_technique"], ioc["description"], ioc["source"], now
                ))
            conn.commit()
        conn.close()

    def add_indicator(self, ioc_type: str, value: str, confidence: int = 80, severity: str = "HIGH",
                      mitre_technique: str = "T1071 - Application Layer Protocol",
                      description: str = "User added indicator", source: str = "Local Analyst",
                      added_by: str = "Analyst") -> dict:
        clean_val = value.lower().strip()
        conn = get_connection()
        c = conn.cursor()
        
        # Deduplication check
        c.execute("SELECT id, stix_id FROM stix_iocs WHERE value = ?", (clean_val,))
        existing = c.fetchone()
        if existing:
            conn.close()
            return {"success": False, "error": f"Indicator '{value}' already exists in threat intelligence store.", "stix_id": existing["stix_id"]}

        stix_id = f"indicator--{secrets.token_hex(8)}"
        now = time.time()
        c.execute('''
            INSERT INTO stix_iocs (stix_id, type, value, confidence, severity, mitre_technique, description, source, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ''', (stix_id, ioc_type, clean_val, confidence, severity, mitre_technique, description, source, now))
        conn.commit()
        conn.close()

        log_audit(added_by, "Analyst", "IOC_ADDED", f"{ioc_type}:{clean_val}", "SUCCESS", "127.0.0.1", f"Added STIX indicator {stix_id}")
        return {
            "success": True,
            "stix_id": stix_id,
            "type": ioc_type,
            "value": clean_val,
            "confidence": confidence,
            "severity": severity,
            "mitre_technique": mitre_technique
        }

    def lookup(self, target: str) -> dict | None:
        clean = target.lower().strip()
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM stix_iocs WHERE value = ? AND is_active = 1", (clean,))
        row = c.fetchone()
        conn.close()
        if row:
            res = dict(row)
            res["stix_pattern"] = f"[{res['type']}:value = '{res['value']}']"
            return res
        return None

    def list_indicators(self, ioc_type: str = None, search: str = None, limit: int = 50) -> list[dict]:
        conn = get_connection()
        c = conn.cursor()
        query = "SELECT * FROM stix_iocs WHERE is_active = 1"
        params = []
        if ioc_type:
            query += " AND type = ?"
            params.append(ioc_type)
        if search:
            query += " AND (value LIKE ? OR description LIKE ? OR mitre_technique LIKE ?)"
            s_term = f"%{search}%"
            params.extend([s_term, s_term, s_term])
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        c.execute(query, tuple(params))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows
