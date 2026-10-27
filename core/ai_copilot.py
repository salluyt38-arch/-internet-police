import urllib.request
import urllib.parse
import json
import os
import re
import time
from .database import get_setting, get_stats, get_recent_logs, log_audit

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?prior\s+guidelines",
    r"you\s+are\s+now\s+in\s+unrestricted\s+mode",
    r"system\s*prompt\s*override",
    r"bypass\s+safety\s+filters",
    r"<\s*system\s*>",
    r"\[\s*INST\s*\]",
    r"act\s+as\s+an\s+adversary\s+with\s+no\s+rules"
]

class InternetPoliceCopilot:
    """
    Module A: AI Security Assistant & Investigation Engine.
    Powered by Free LLM APIs (Groq, Gemini, OpenRouter, Ollama)
    with autonomous offline cybersecurity fallback.
    Includes anti-prompt-injection sanitization and structured incident report generation.
    """
    def __init__(self):
        pass

    def sanitize_prompt(self, user_prompt: str) -> tuple[str, bool]:
        """
        Detects and strips prompt injection attempts from logs, user inputs, or scraped target data.
        Returns (sanitized_prompt, was_flagged)
        """
        flagged = False
        cleaned = user_prompt
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, cleaned, re.IGNORECASE):
                flagged = True
                cleaned = re.sub(pattern, "[FILTERED_SECURITY_INJECTION_ATTEMPT]", cleaned, flags=re.IGNORECASE)

        # Strip control characters
        cleaned = "".join(ch for ch in cleaned if ord(ch) >= 32 or ch in "\n\r\t")
        return cleaned.strip(), flagged

    def call_groq(self, prompt: str, api_key: str, system_prompt: str) -> str:
        url = "https://api.groq.com/openai/v1/chat/completions"
        candidate_models = ["qwen/qwen3.8-27b", "openai/gpt-oss-120b", "openai/gpt-oss-20b", "llama-3.3-70b-versatile", "llama-3.1-8b-instant"]
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) InternetPolice/2.0"
        }
        last_error = None
        for model in candidate_models:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.4,
                "max_tokens": 1200
            }
            try:
                req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data["choices"][0]["message"]["content"]
            except Exception as e:
                last_error = e
                continue
        raise last_error if last_error else Exception("Groq connection failure")

    def call_gemini(self, prompt: str, api_key: str, system_prompt: str) -> str:
        api_key = api_key.strip()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        combined_prompt = f"System Instructions: {system_prompt}\n\nUser Security Question:\n{prompt}"
        payload = {"contents": [{"parts": [{"text": combined_prompt}]}]}
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) InternetPolice/2.0"
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"]

    def call_openrouter(self, prompt: str, api_key: str, system_prompt: str) -> str:
        url = "https://openrouter.ai/api/v1/chat/completions"
        payload = {
            "model": "deepseek/deepseek-r1:free",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        }
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) InternetPolice/2.0"
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]

    def call_ollama(self, prompt: str, model="llama3") -> str:
        url = "http://127.0.0.1:11434/api/generate"
        payload = {"model": model, "prompt": prompt, "stream": False}
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode()).get("response", "")

    def offline_police_agent(self, prompt: str) -> str:
        p_lower = prompt.lower()
        if "status" in p_lower or "report" in p_lower:
            stats = get_stats()
            return (
                f"🚨 **Autonomous Security Status Briefing:**\n\n"
                f"• Inspected Network Payloads: {stats['total_events']}\n"
                f"• Trackers & Telemetry Sinkholed: {stats['blocked_ads']}\n"
                f"• Neutralized Threats & Attacks: {stats['blocked_threats']}\n"
                f"• Data Loss Prevention (DLP) Shields: {stats['dlp_alerts']}\n"
                f"• WAF Zero-Trust Blocks: {stats['waf_blocks']}\n\n"
                f"24/7 background guard is fully active on all local devices."
            )
        elif "hack" in p_lower or "security" in p_lower:
            return (
                "🛡️ **Zero-Trust Security Principles:**\n\n"
                "1. **Never Trust, Always Verify**: Inspect all incoming and outgoing packets via WAF and DLP.\n"
                "2. **Encrypted DNS**: Quad9 DoH blocks malicious hostnames before a socket connection is formed.\n"
                "3. **Personal Data Loss Prevention**: Regex filters halt credit cards, PAN, and credentials from exfiltration."
            )
        else:
            return (
                f"👮 **Internet Police AI Security Assistant:**\n\n"
                f"Received security inquiry: '{prompt}'\n\n"
                "Autonomous local heuristic guard active. You can ask me to explain security alerts, "
                "analyze threat intelligence IOCs, verify suspicious URLs/hashes, or generate remediation reports."
            )

    def explain_alert(self, alert_data: dict) -> str:
        prompt = (
            f"Explain this security alert in simple, clear language with actionable remediation steps:\n"
            f"Alert Details:\n{json.dumps(alert_data, indent=2)}"
        )
        return self.ask(prompt)

    def generate_investigation_report(self, incident_title: str, findings: dict) -> str:
        prompt = (
            f"Generate a professional, structured SOC Incident Investigation Report for the following event:\n"
            f"Title: {incident_title}\n"
            f"Findings: {json.dumps(findings, indent=2)}\n\n"
            f"Include: Executive Summary, Severity Level, MITRE ATT&CK Mapping, Immediate Containment Steps, and Long-Term Hardening."
        )
        return self.ask(prompt)

    def ask(self, user_prompt: str, provider: str = None, api_key: str = None, actor: str = "User") -> str:
        sanitized_prompt, was_flagged = self.sanitize_prompt(user_prompt)
        if was_flagged:
            log_audit(actor, "Security", "PROMPT_INJECTION_BLOCKED", "LLM Gateway", "DENIED", "127.0.0.1", "Prompt injection pattern stripped")

        system_prompt = (
            "You are 'Internet Police' (इंटरनेट पुलिस), an elite Autonomous AI Cyber Commander guardian. "
            "Your mission is to defend user workstations, web servers, and mobile devices against cyber threats, data exfiltration, and attacks. "
            "Maintain an authoritative, precise, and helpful tone. Provide structured, technically accurate remediation steps. "
            "Never execute or propose destructive payloads, exploits, or unverified claims. Format key points using clean Markdown."
        )

        if not provider:
            provider = get_setting("ai_provider", "groq")
        if not api_key:
            api_key = get_setting("ai_api_key", "").strip()

        # Reject URL inputs as keys
        if api_key.startswith("http://") or api_key.startswith("https://"):
            return (
                "⚠️ **Notice:** You pasted a URL instead of an API key into the API key field.\n\n"
                "The Internet Police is operating securely on its offline heuristic engine. Please set your valid Groq (`gsk_...`) or Gemini key in Settings."
            )

        try:
            if (provider == "groq" or api_key.startswith("gsk_")) and api_key:
                return self.call_groq(sanitized_prompt, api_key, system_prompt)
            elif (provider == "gemini" or api_key.startswith("AIza")) and api_key:
                return self.call_gemini(sanitized_prompt, api_key, system_prompt)
            elif (provider == "openrouter" or api_key.startswith("sk-or-")) and api_key:
                return self.call_openrouter(sanitized_prompt, api_key, system_prompt)
            elif provider == "ollama":
                return self.call_ollama(sanitized_prompt)
        except Exception as e:
            return f"⚠️ [Police Dispatch Cloud Notice: {str(e)[:60]}]\n\n{self.offline_police_agent(sanitized_prompt)}"

        return self.offline_police_agent(sanitized_prompt)
