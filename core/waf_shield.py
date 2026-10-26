import time
import re
from collections import defaultdict

class WAFShield:
    """
    Internet Police Layer-7 Web Application Firewall & Anti-DDoS Shield.
    """
    def __init__(self, max_req_per_min=120):
        self.max_req = max_req_per_min
        self.history = defaultdict(list)
        self.banned_ips = {}
        
        self.signatures = [
            ("SQL_INJECTION", re.compile(r'(union\s+select|select.+from|drop\s+table|insert\s+into|information_schema|waitfor\s+delay|\'\s*or\s*\'?1\'?=\'?1)', re.IGNORECASE), "CRITICAL"),
            ("CROSS_SITE_SCRIPTING", re.compile(r'(<script[^>]*>|javascript:|onerror\s*=|onload\s*=|alert\(|document\.cookie|eval\()', re.IGNORECASE), "HIGH"),
            ("PATH_TRAVERSAL", re.compile(r'(?:\.\.[/\\])+|(etc/passwd|winnt/system32|windows/system32)', re.IGNORECASE), "CRITICAL"),
            ("COMMAND_INJECTION", re.compile(r'(;\s*(?:cat|ls|rm|curl|wget|bash|powershell|cmd\.exe|whoami)|\$\([^\)]+\)|`[^`]+`)', re.IGNORECASE), "CRITICAL"),
            ("SUSPICIOUS_TOOLS", re.compile(r'(sqlmap|nikto|nmap|masscan|havij|acunetix)', re.IGNORECASE), "HIGH")
        ]

    def check_rate_limit(self, client_ip):
        now = time.time()
        if client_ip in self.banned_ips:
            if now < self.banned_ips[client_ip]:
                return True, "IP Banned by Internet Police for DDoS Flooding"
            else:
                del self.banned_ips[client_ip]

        self.history[client_ip] = [t for t in self.history[client_ip] if now - t < 60]
        self.history[client_ip].append(now)

        if len(self.history[client_ip]) > self.max_req:
            self.banned_ips[client_ip] = now + 300
            return True, "Rate limit exceeded (DDoS Quarantine 5min)"

        return False, "CLEAN"

    def inspect(self, client_ip, path, body="", headers=None):
        rate_blocked, reason = self.check_rate_limit(client_ip)
        if rate_blocked:
            return {"blocked": True, "type": "DDOS_FLOOD", "risk": "CRITICAL", "reason": reason}

        payload = f"{path} {body}"
        if headers and "User-Agent" in headers:
            payload += f" {headers['User-Agent']}"

        for threat_type, pattern, risk in self.signatures:
            m = pattern.search(payload)
            if m:
                return {
                    "blocked": True,
                    "type": threat_type,
                    "risk": risk,
                    "reason": f"Attack pattern detected: '{m.group(0)[:40]}'"
                }

        return {"blocked": False, "type": "CLEAN", "risk": "SAFE"}
