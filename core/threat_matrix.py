import math
import urllib.request
import urllib.parse
import json
import base64
from .database import get_setting

SUSPICIOUS_TLDS = {"top", "work", "click", "buzz", "gq", "cf", "tk", "ml", "ga", "fit", "surf", "rest", "zip", "mov"}

class ThreatMatrix:
    def __init__(self):
        pass

    def calculate_entropy(self, text):
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    def scan_domain(self, domain):
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
            flags.append(f"Excessive numeric density in domain ({digit_count}/{len(sld)})")

        risk = "LOW"
        if score >= 55:
            risk = "CRITICAL"
        elif score >= 30:
            risk = "HIGH"
        elif score >= 15:
            risk = "MEDIUM"

        return {
            "target": domain,
            "threat_score": min(score, 100),
            "risk_level": risk,
            "is_malicious": score >= 40,
            "indicators": flags
        }

    def scan_virustotal_url(self, url):
        api_key = get_setting("vt_api_key", "").strip()
        if not api_key:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc or url
            res = self.scan_domain(domain)
            res["source"] = "Internet Police Heuristic Matrix (Offline)"
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
                    return {
                        "target": url,
                        "source": "VirusTotal v3 Live",
                        "malicious": malicious,
                        "risk_level": "CRITICAL" if malicious > 0 else "SAFE",
                        "is_malicious": malicious > 0
                    }
        except Exception as e:
            return self.scan_domain(url)
