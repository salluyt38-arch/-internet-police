import math
import urllib.request
import urllib.parse
import json
import base64
import time
import re
from .database import get_setting
from .stix_intel import STIXIntelManager

SUSPICIOUS_TLDS = {"top", "work", "click", "buzz", "gq", "cf", "tk", "ml", "ga", "fit", "surf", "rest", "zip", "mov"}

class ThreatMatrix:
    """
    Threat Intelligence & Reputation Engine (Module B).
    Evaluates suspicious URLs, domains, IP addresses, and file hashes.
    Distinguishes CONFIRMED_MALICIOUS from SUSPICIOUS, SAFE, and UNKNOWN.
    Never marks an indicator malicious based solely on AI conjecture.
    """
    def __init__(self):
        self.stix = STIXIntelManager()

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    def detect_target_type(self, target: str) -> str:
        target = target.strip()
        if re.match(r"^[a-fA-F0-9]{32}$", target):
            return "md5"
        if re.match(r"^[a-fA-F0-9]{40}$", target):
            return "sha1"
        if re.match(r"^[a-fA-F0-9]{64}$", target):
            return "sha256"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            return "ipv4"
        if "://" in target:
            return "url"
        return "domain"

    def scan_target(self, target: str) -> dict:
        target_clean = target.strip()
        t_type = self.detect_target_type(target_clean)

        # 1. First correlate against local STIX 2.1 Threat Intel
        stix_match = self.stix.lookup(target_clean)
        if stix_match:
            return {
                "target": target_clean,
                "type": t_type,
                "reputation_status": "CONFIRMED_MALICIOUS",
                "risk_level": stix_match["severity"],
                "confidence": stix_match["confidence"],
                "source": f"STIX 2.1 IOC Database ({stix_match['source']})",
                "mitre_technique": stix_match.get("mitre_technique", "Unknown"),
                "details": stix_match["description"],
                "timestamp": time.time(),
                "limitations": "Direct indicator match in curated threat database."
            }

        # 2. Type-specific evaluations
        if t_type in ("md5", "sha1", "sha256"):
            return self._scan_hash(target_clean, t_type)
        elif t_type == "ipv4":
            return self._scan_ip(target_clean)
        elif t_type == "url":
            return self.scan_virustotal_url(target_clean)
        else:
            return self.scan_domain(target_clean)

    def _scan_hash(self, hash_val: str, h_type: str) -> dict:
        # Check against known baseline hashes or VT
        vt_key = get_setting("vt_api_key", "").strip()
        if vt_key:
            endpoint = f"https://www.virustotal.com/api/v3/files/{hash_val}"
            headers = {"x-apikey": vt_key, "Accept": "application/json"}
            try:
                req = urllib.request.Request(endpoint, headers=headers)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        mal = stats.get("malicious", 0)
                        rep = "CONFIRMED_MALICIOUS" if mal > 3 else ("SUSPICIOUS" if mal > 0 else "SAFE")
                        return {
                            "target": hash_val,
                            "type": h_type,
                            "reputation_status": rep,
                            "risk_level": "CRITICAL" if mal > 3 else ("HIGH" if mal > 0 else "LOW"),
                            "confidence": 95 if mal > 0 else 70,
                            "source": "VirusTotal v3 Live Multi-Engine",
                            "details": f"{mal} security vendors flagged this file hash as malicious.",
                            "timestamp": time.time(),
                            "limitations": "Subject to VirusTotal community scan records."
                        }
            except Exception:
                pass

        # Offline / Unknown
        return {
            "target": hash_val,
            "type": h_type,
            "reputation_status": "UNKNOWN",
            "risk_level": "LOW",
            "confidence": 20,
            "source": "Local Hash Reputation Engine",
            "details": f"No definitive malware match in local database for {h_type.upper()} hash.",
            "timestamp": time.time(),
            "limitations": "Configure VirusTotal API key in Settings for live sandbox hash lookups."
        }

    def _scan_ip(self, ip_str: str) -> dict:
        # Private / loopback check
        parts = ip_str.split(".")
        if len(parts) == 4:
            first = int(parts[0]) if parts[0].isdigit() else 0
            second = int(parts[1]) if parts[1].isdigit() else 0
            if first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168) or first == 127:
                return {
                    "target": ip_str,
                    "type": "ipv4",
                    "reputation_status": "SAFE",
                    "risk_level": "LOW",
                    "confidence": 100,
                    "source": "RFC 1918 Private Address Validator",
                    "details": "Private / Local loopback IP address. Not routable on the public internet.",
                    "timestamp": time.time(),
                    "limitations": "Local address space."
                }

        return {
            "target": ip_str,
            "type": "ipv4",
            "reputation_status": "UNKNOWN",
            "risk_level": "LOW",
            "confidence": 30,
            "source": "Local IP Heuristic Shield",
            "details": "Public IP not flagged in active local STIX indicators.",
            "timestamp": time.time(),
            "limitations": "Check requires external threat intelligence feeds for full ASN/BGP reputation."
        }

    def scan_domain(self, domain: str) -> dict:
        domain = domain.strip().lower()
        score = 0
        flags = []

        if domain.startswith("xn--"):
            score += 45
            flags.append("Punycode / IDN Homograph spoofing")

        parts = domain.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in SUSPICIOUS_TLDS:
                score += 30
                flags.append(f"Suspicious Top-Level Domain (.{tld})")
            if len(parts) > 4:
                score += 20
                flags.append("High subdomain nesting (DNS tunneling risk)")

        sld = parts[0] if parts else domain
        entropy = self.calculate_entropy(sld)
        if len(sld) >= 8 and entropy > 3.3:
            score += 35
            flags.append(f"High Shannon entropy ({entropy:.2f}) - DGA algorithmic domain")

        digit_count = sum(c.isdigit() for c in sld)
        if len(sld) > 6 and (digit_count / len(sld)) > 0.35:
            score += 20
            flags.append(f"Excessive numeric density ({digit_count}/{len(sld)})")

        if score >= 50:
            rep = "SUSPICIOUS"
            risk = "CRITICAL"
        elif score >= 25:
            rep = "SUSPICIOUS"
            risk = "HIGH"
        elif score >= 10:
            rep = "SUSPICIOUS"
            risk = "MEDIUM"
        else:
            rep = "SAFE"
            risk = "LOW"

        return {
            "target": domain,
            "type": "domain",
            "reputation_status": rep,
            "risk_level": risk,
            "threat_score": min(score, 100),
            "confidence": 85 if flags else 60,
            "source": "Internet Police Heuristic & Entropy Matrix",
            "indicators": flags if flags else ["Standard domain structure", "No DGA entropy anomalies detected"],
            "details": f"Analyzed domain structure across {len(parts)} segments. Entropy: {entropy:.2f}.",
            "timestamp": time.time(),
            "limitations": "Heuristic structural analysis. Does not perform dynamic sandbox payload execution."
        }

    def scan_virustotal_url(self, url: str) -> dict:
        api_key = get_setting("vt_api_key", "").strip()
        if not api_key:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc or url
            res = self.scan_domain(domain)
            res["target"] = url
            res["type"] = "url"
            res["limitations"] = "Offline heuristic analysis. VirusTotal API key not configured."
            return res

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        try:
            req = urllib.request.Request(endpoint, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    rep = "CONFIRMED_MALICIOUS" if malicious > 2 else ("SUSPICIOUS" if malicious > 0 else "SAFE")
                    return {
                        "target": url,
                        "type": "url",
                        "reputation_status": rep,
                        "source": "VirusTotal v3 Live Multi-Engine",
                        "malicious": malicious,
                        "risk_level": "CRITICAL" if malicious > 2 else ("HIGH" if malicious > 0 else "LOW"),
                        "confidence": 95 if malicious > 0 else 80,
                        "details": f"{malicious} antivirus and web-reputation scanners flagged this URL.",
                        "timestamp": time.time(),
                        "limitations": "VirusTotal live community scan result."
                    }
        except Exception:
            pass

        parsed = urllib.parse.urlparse(url)
        return self.scan_domain(parsed.netloc or url)
