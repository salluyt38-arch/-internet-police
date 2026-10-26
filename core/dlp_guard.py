import re

class DLPGuard:
    """
    Internet Police Data Loss Prevention (DLP) Guard.
    Prevents unauthorized exfiltration of Personally Identifiable Information (PII),
    financial accounts, and national identity credentials.
    """
    def __init__(self):
        self.patterns = {
            "PAN_CARD": (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'), "CRITICAL", "Indian PAN Card Number detected"),
            "AADHAAR_NUMBER": (re.compile(r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b'), "CRITICAL", "Indian Aadhaar Number format detected"),
            "AWS_SECRET_KEY": (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), "CRITICAL", "AWS Access Key ID exposed"),
            "PRIVATE_KEY": (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), "CRITICAL", "Cryptographic Private Key detected"),
            "GITHUB_TOKEN": (re.compile(r'\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b'), "CRITICAL", "GitHub Personal Access Token leaked"),
            "GENERIC_API_KEY": (re.compile(r'(?:api_key|apikey|secret_key|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{24,})', re.IGNORECASE), "HIGH", "Exposed Secret Token"),
            "EMAIL_ADDRESS": (re.compile(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b'), "LOW", "Email address exposed"),
            "PHONE_NUMBER": (re.compile(r'\b(?:\+91[- ]?)?[6789]\d{9}\b'), "MEDIUM", "Indian Mobile Number detected")
        }
        self.cc_regex = re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b|\b\d{15,16}\b')

    def luhn_checksum(self, card_number):
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) not in [13, 14, 15, 16, 19]:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for idx, digit in enumerate(reverse_digits):
            if idx % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    def scan(self, text):
        if not text:
            return {"has_leak": False, "violations": [], "sanitized_text": ""}

        violations = []
        highest_risk = "SAFE"
        masked_text = text

        # 1. Credit Card Check with Luhn Validation
        for match in self.cc_regex.finditer(text):
            raw = match.group(0)
            cleaned = "".join(filter(str.isdigit, raw))
            if self.luhn_checksum(cleaned):
                masked = f"XXXX-XXXX-XXXX-{cleaned[-4:]}"
                masked_text = masked_text.replace(raw, masked)
                violations.append({
                    "type": "PAYMENT_CARD",
                    "risk": "CRITICAL",
                    "description": "Valid Credit/Debit Card Number (Luhn verified)",
                    "masked_preview": masked
                })
                highest_risk = "CRITICAL"

        # 2. Check Identity & Secrets
        for p_name, (pattern, risk, desc) in self.patterns.items():
            for m in pattern.finditer(text):
                val = m.group(0)
                if len(val) > 6:
                    preview = f"{val[:2]}****{val[-3:]}"
                else:
                    preview = "****"
                masked_text = masked_text.replace(val, preview)
                violations.append({
                    "type": p_name,
                    "risk": risk,
                    "description": desc,
                    "masked_preview": preview
                })
                if risk == "CRITICAL":
                    highest_risk = "CRITICAL"
                elif risk == "HIGH" and highest_risk != "CRITICAL":
                    highest_risk = "HIGH"

        return {
            "has_leak": len(violations) > 0,
            "violations_count": len(violations),
            "highest_risk": highest_risk,
            "violations": violations,
            "sanitized_text": masked_text
        }
