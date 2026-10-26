import http.server
import socketserver
import json
import urllib.parse
import os
import sys

from core.database import (
    init_db, log_event, get_stats, get_recent_logs,
    get_setting, set_setting, save_permission, are_all_permissions_granted
)
from core.police_engine import InternetPolice
from core.dns_sinkhole import DNSSinkhole
from core.dlp_guard import DLPGuard
from core.waf_shield import WAFShield
from core.threat_matrix import ThreatMatrix
from core.ai_copilot import InternetPoliceCopilot
from core.nightly_dispatch import NightlyDispatch
from core.voice_engine import HumanoidVoiceAgent, NEURAL_VOICES
import asyncio

UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")

class InternetPoliceHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UI_DIR, **kwargs)

    def do_GET(self):
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. Zero Trust WAF Inspection
        waf = getattr(self.server, "waf", None)
        if waf:
            waf_res = waf.inspect(client_ip, self.path, headers=dict(self.headers))
            if waf_res["blocked"]:
                log_event(client_ip, "WAF", self.path, "BLOCKED", waf_res["risk"], waf_res["reason"])
                self.send_json({"error": "Interception by Internet Police WAF", "details": waf_res}, status=403)
                return

        # 2. REST API Handlers
        if path == "/api/status":
            police = getattr(self.server, "police", None)
            rep = police.get_status_report() if police else {}
            rep["permissions_granted"] = are_all_permissions_granted()
            self.send_json(rep)
        elif path == "/api/stats":
            self.send_json(get_stats())
        elif path == "/api/logs":
            self.send_json(get_recent_logs(50))
        elif path == "/api/settings":
            self.send_json({
                "ai_provider": get_setting("ai_provider", "groq"),
                "ai_api_key": get_setting("ai_api_key", ""),
                "theme": get_setting("theme", "titanium"),
                "voice_enabled": get_setting("voice_enabled", "1") == "1"
            })
        elif path == "/api/dispatch/latest":
            dispatcher = getattr(self.server, "dispatcher", None)
            self.send_json(dispatcher.get_latest_dispatches(5) if dispatcher else [])
        elif path == "/api/voice/speak":
            # Real-time Neural Humanoid Audio Stream (MP3)
            query_params = urllib.parse.parse_qs(parsed.query)
            text_to_speak = query_params.get("text", [""])[0]
            voice_choice = query_params.get("voice", ["hi-IN-MadhurNeural"])[0]
            
            voice_agent = getattr(self.server, "voice_agent", None)
            if voice_agent and text_to_speak:
                try:
                    audio_bytes = asyncio.run(voice_agent.synthesize_speech(text_to_speak, voice=voice_choice))
                    self.send_response(200)
                    self.send_header("Content-Type", "audio/mpeg")
                    self.send_header("Content-Length", str(len(audio_bytes)))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(audio_bytes)
                    return
                except Exception as e:
                    self.send_json({"error": str(e)}, status=500)
                    return
            self.send_error(400, "Missing text parameter")
        else:
            if path == "/":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="ignore")

        # 1. Zero Trust WAF Inspection
        waf = getattr(self.server, "waf", None)
        if waf:
            waf_res = waf.inspect(client_ip, self.path, body=body, headers=dict(self.headers))
            if waf_res["blocked"]:
                log_event(client_ip, "WAF", self.path, "BLOCKED", waf_res["risk"], waf_res["reason"])
                self.send_json({"error": "Interception by Internet Police WAF", "details": waf_res}, status=403)
                return

        # 2. DLP Inspection (Check for PAN, Aadhaar, Credit Card leaks)
        dlp = getattr(self.server, "dlp", None)
        if dlp:
            dlp_res = dlp.scan(body)
            if dlp_res["has_leak"]:
                log_event(client_ip, "DLP", path, "ALERT", dlp_res["highest_risk"], f"Blocked PII leak: {dlp_res['violations_count']} items")

        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        # 3. Handlers
        if path == "/api/chat":
            copilot = getattr(self.server, "copilot", None)
            prompt = data.get("prompt", "").strip()
            resp_text = copilot.ask(prompt) if copilot else "Police Commander offline."
            self.send_json({"response": resp_text})

        elif path == "/api/voice/command":
            voice_agent = getattr(self.server, "voice_agent", None)
            transcript = data.get("transcript", "").strip()
            if voice_agent and transcript:
                res = voice_agent.execute_voice_command(transcript)
                self.send_json(res)
            else:
                self.send_json({"text": "वॉइस कमांड प्राप्त नहीं हुआ।", "voice_prompt": "कमांड समझ नहीं आई।"})

        elif path == "/api/permissions":
            if data.get("all_granted"):
                save_permission("dns_sinkhole", True)
                save_permission("dlp_guard", True)
                save_permission("waf_shield", True)
                save_permission("voice_agent", True)
                save_permission("nightly_dispatch", True)
                log_event(client_ip, "POLICE", "Device Authorization", "ALLOWED", "LOW", "All device permissions authorized by user")
            self.send_json({"status": "PERMISSIONS_GRANTED"})

        elif path == "/api/dispatch/generate":
            dispatcher = getattr(self.server, "dispatcher", None)
            res = dispatcher.generate_daily_summary() if dispatcher else {}
            log_event(client_ip, "POLICE", "21:00 Security Dispatch", "ALLOWED", "LOW", "Daily Nightly Intelligence Briefing dispatched")
            self.send_json(res)

        elif path == "/api/settings":
            for k, v in data.items():
                set_setting(k, v)
            self.send_json({"status": "SAVED"})

        else:
            self.send_error(404, "Endpoint Not Found")

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
