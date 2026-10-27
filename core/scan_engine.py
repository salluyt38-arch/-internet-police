import socket
import ssl
import urllib.request
import urllib.parse
import json
import time
import secrets
import datetime
from .database import get_setting, get_connection, log_audit, log_event

SAFE_PROBE_PORTS = [80, 443, 8080, 8443]

class AuthorizedScanEngine:
    """
    Authorized Defensive Security Assessment Engine.
    Inspired by AIRecon. Enforces strict target authorization allowlists,
    safe non-destructive reconnaissance (DNS, SSL/TLS, Security Headers, Policy files),
    and rejects arbitrary scans, fuzzing, or destructive exploits.
    """
    def __init__(self):
        pass

    def get_allowed_targets(self) -> list[str]:
        raw = get_setting("allowed_targets", "localhost, 127.0.0.1, ::1, example.com, scanme.nmap.org")
        return [t.strip().lower() for t in raw.split(",") if t.strip()]

    def is_target_allowed(self, target: str) -> bool:
        target = target.strip().lower()
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            target = parsed.hostname or target

        # Remove port if present
        if ":" in target and not target.startswith("::"):
            target = target.split(":")[0]

        allowed = self.get_allowed_targets()
        for pattern in allowed:
            if target == pattern or target.endswith(f".{pattern}"):
                return True
        return False

    def perform_scan(self, target: str, authorized: bool, performed_by: str = "Admin", client_ip: str = "127.0.0.1") -> dict:
        scan_id = f"scan_{secrets.token_hex(6)}"
        now = time.time()

        if not authorized:
            log_audit(performed_by, "Analyst", "SCAN_REJECTED", target, "DENIED", client_ip, "Authorization confirmation was not provided")
            return {
                "scan_id": scan_id,
                "status": "BLOCKED",
                "error": "Scan rejected: You must affirmatively confirm written authorization to assess this target."
            }

        # Normalize target
        clean_target = target.strip()
        hostname = clean_target
        if "://" in clean_target:
            parsed = urllib.parse.urlparse(clean_target)
            hostname = parsed.hostname or clean_target
        if ":" in hostname and not hostname.startswith("::"):
            hostname = hostname.split(":")[0]

        if not self.is_target_allowed(hostname):
            log_audit(performed_by, "Analyst", "SCAN_BLOCKED_UNAUTHORIZED", hostname, "DENIED", client_ip, "Target is not in the configured authorization allowlist")
            return {
                "scan_id": scan_id,
                "status": "BLOCKED",
                "target": hostname,
                "error": f"UNAUTHORIZED TARGET: '{hostname}' is not in the authorized targets allowlist. Update settings to allow assessment."
            }

        log_audit(performed_by, "Admin", "SCAN_STARTED", hostname, "SUCCESS", client_ip, f"Authorized defensive scan started: {scan_id}")

        findings = {
            "dns": self._check_dns(hostname),
            "ssl_tls": self._check_ssl(hostname),
            "http_headers": self._check_http_headers(hostname),
            "safe_ports": self._check_safe_ports(hostname),
            "policy_files": self._check_policy_files(hostname)
        }

        # Calculate Posture Score & Remediation
        risk_score, remediations = self._calculate_posture(findings)

        result_data = {
            "scan_id": scan_id,
            "target": hostname,
            "scan_type": "Defensive Posture & Non-Destructive Reconnaissance",
            "status": "COMPLETED",
            "risk_score": risk_score,
            "findings": findings,
            "remediations": remediations,
            "performed_by": performed_by,
            "timestamp": now
        }

        # Persist to database
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute('''
                INSERT INTO scan_records (scan_id, target, scan_type, status, risk_score, findings_json, remediation_json, performed_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id, hostname, "Defensive Recon", "COMPLETED", risk_score,
                json.dumps(findings), json.dumps(remediations), performed_by, now
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Scan DB Error] {e}")

        log_event(client_ip, "POLICE", hostname, "ALLOWED", "LOW", f"Completed authorized assessment {scan_id}. Posture Score: {risk_score}/100")
        return result_data

    def _check_dns(self, hostname: str) -> dict:
        records = {"ipv4": [], "ipv6": [], "status": "UNKNOWN"}
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip = item[4][0]
                if ":" in ip:
                    if ip not in records["ipv6"]:
                        records["ipv6"].append(ip)
                else:
                    if ip not in records["ipv4"]:
                        records["ipv4"].append(ip)
            records["status"] = "RESOLVED"
        except Exception as e:
            records["status"] = f"FAILED: {str(e)}"
        return records

    def _check_ssl(self, hostname: str) -> dict:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    not_after = cert.get("notAfter", "")
                    days_left = None
                    if not_after:
                        exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_date - datetime.datetime.utcnow()).days

                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))

                    return {
                        "supported": True,
                        "version": version,
                        "cipher": cipher[0] if cipher else "Unknown",
                        "days_until_expiry": days_left,
                        "issuer_cn": issuer.get("commonName", "Unknown"),
                        "subject_cn": subject.get("commonName", "Unknown"),
                        "expired": days_left is not None and days_left <= 0
                    }
        except Exception as e:
            return {"supported": False, "error": str(e)}

    def _check_http_headers(self, hostname: str) -> dict:
        headers_to_test = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        results = {"status_code": None, "headers_found": {}, "missing_headers": []}

        # Try HTTPS then HTTP
        target_url = f"https://{hostname}"
        req = urllib.request.Request(target_url, headers={"User-Agent": "InternetPolice-DefensiveAudit/2.0"})
        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                results["status_code"] = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                for h in headers_to_test:
                    val = resp_headers.get(h.lower())
                    if val:
                        results["headers_found"][h] = val
                    else:
                        results["missing_headers"].append(h)
        except Exception:
            # Fallback to HTTP
            try:
                target_url = f"http://{hostname}"
                req = urllib.request.Request(target_url, headers={"User-Agent": "InternetPolice-DefensiveAudit/2.0"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    results["status_code"] = resp.status
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    for h in headers_to_test:
                        val = resp_headers.get(h.lower())
                        if val:
                            results["headers_found"][h] = val
                        else:
                            results["missing_headers"].append(h)
            except Exception as e:
                results["error"] = str(e)
                results["missing_headers"] = headers_to_test

        return results

    def _check_safe_ports(self, hostname: str) -> list[dict]:
        open_ports = []
        for port in SAFE_PROBE_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            res = s.connect_ex((hostname, port))
            s.close()
            service_name = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}.get(port, "TCP")
            open_ports.append({
                "port": port,
                "service": service_name,
                "is_open": res == 0
            })
        return open_ports

    def _check_policy_files(self, hostname: str) -> dict:
        results = {"security_txt": False, "robots_txt": False}
        for path, key in [("/.well-known/security.txt", "security_txt"), ("/robots.txt", "robots_txt")]:
            try:
                req = urllib.request.Request(f"https://{hostname}{path}", headers={"User-Agent": "InternetPolice-DefensiveAudit/2.0"})
                with urllib.request.urlopen(req, timeout=2.5) as resp:
                    if resp.status == 200:
                        results[key] = True
            except Exception:
                results[key] = False
        return results

    def _calculate_posture(self, findings: dict) -> tuple[int, list[str]]:
        score = 100
        remediations = []

        # SSL evaluation
        ssl_info = findings.get("ssl_tls", {})
        if not ssl_info.get("supported"):
            score -= 25
            remediations.append("Enable TLS 1.3 encryption on port 443 with a trusted certificate.")
        elif ssl_info.get("expired"):
            score -= 30
            remediations.append("Renew expired SSL/TLS certificate immediately.")
        elif ssl_info.get("days_until_expiry", 999) < 14:
            score -= 10
            remediations.append(f"SSL certificate expires in {ssl_info.get('days_until_expiry')} days. Plan certificate renewal.")

        # HTTP Security Headers
        missing = findings.get("http_headers", {}).get("missing_headers", [])
        if "Strict-Transport-Security" in missing:
            score -= 10
            remediations.append("Configure 'Strict-Transport-Security' (HSTS) with max-age=31536000.")
        if "Content-Security-Policy" in missing:
            score -= 15
            remediations.append("Implement a robust 'Content-Security-Policy' (CSP) to mitigate XSS and data exfiltration.")
        if "X-Frame-Options" in missing:
            score -= 5
            remediations.append("Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.")
        if "X-Content-Type-Options" in missing:
            score -= 5
            remediations.append("Set 'X-Content-Type-Options: nosniff' to block MIME sniffing.")

        # Policy files
        policies = findings.get("policy_files", {})
        if not policies.get("security_txt"):
            score -= 5
            remediations.append("Publish RFC 9116 security.txt at /.well-known/security.txt for coordinated vulnerability disclosure.")

        return max(0, score), remediations

    def list_history(self, limit: int = 25) -> list[dict]:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM scan_records ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        for r in rows:
            if r.get("findings_json"):
                try:
                    r["findings"] = json.loads(r["findings_json"])
                except Exception:
                    pass
            if r.get("remediation_json"):
                try:
                    r["remediations"] = json.loads(r["remediation_json"])
                except Exception:
                    pass
        return rows
