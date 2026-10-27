import http.server
import socketserver
import json
import urllib.parse
import os
import sys
import asyncio

from core.database import (
    init_db, log_event, get_stats, get_recent_logs,
    get_setting, set_setting, save_permission, are_all_permissions_granted,
    log_audit, get_recent_audits
)
from core.police_engine import InternetPolice
from core.dns_sinkhole import DNSSinkhole
from core.dlp_guard import DLPGuard
from core.waf_shield import WAFShield
from core.threat_matrix import ThreatMatrix
from core.ai_copilot import InternetPoliceCopilot
from core.nightly_dispatch import NightlyDispatch
from core.voice_engine import HumanoidVoiceAgent, NEURAL_VOICES
from core.device_agent import LocalDeviceAgent
from core.vault_engine import PasswordVaultEngine
from core.auth_rbac import authenticate_user, verify_token, check_permission, list_users, init_default_users, ROLES
from core.wazuh_adapter import WazuhAdapter
from core.scan_engine import AuthorizedScanEngine
from core.stix_intel import STIXIntelManager
from core.hitl_approvals import HITLApprovalManager

UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")

class InternetPoliceHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=UI_DIR, **kwargs)

    def get_auth_user(self):
        auth_header = self.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        else:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            token = query.get("token", [""])[0]

        session = verify_token(token)
        if session:
            return session
        # Default local session if accessed locally without token
        client_ip = self.client_address[0]
        if client_ip in ("127.0.0.1", "::1", "localhost"):
            return {"username": "admin", "role": "Admin", "ip": client_ip}
        return {"username": "anonymous", "role": "ReadOnly", "ip": client_ip}

    def do_GET(self):
        client_ip = self.client_address[0]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

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
            rep["wazuh"] = getattr(self.server, "wazuh", WazuhAdapter()).get_status()
            rep["hitl_pending"] = len(getattr(self.server, "hitl", HITLApprovalManager()).list_pending())
            self.send_json(rep)

        elif path == "/api/stats":
            self.send_json(get_stats())

        elif path == "/api/logs":
            self.send_json(get_recent_logs(50))

        elif path == "/api/audits":
            self.send_json(get_recent_audits(50))

        elif path == "/api/settings":
            self.send_json({
                "ai_provider": get_setting("ai_provider", "groq"),
                "ai_api_key": get_setting("ai_api_key", ""),
                "theme": get_setting("theme", "titanium"),
                "voice_enabled": get_setting("voice_enabled", "1") == "1",
                "wazuh_host": get_setting("wazuh_host", "https://127.0.0.1:55000"),
                "wazuh_user": get_setting("wazuh_user", "wazuh-wui"),
                "allowed_targets": get_setting("allowed_targets", "localhost, 127.0.0.1, ::1, example.com, scanme.nmap.org")
            })

        elif path == "/api/auth/me":
            user = self.get_auth_user()
            self.send_json(user)

        elif path == "/api/auth/users":
            user = self.get_auth_user()
            if not check_permission(user["role"], "Admin"):
                self.send_json({"error": "Unauthorized. Admin role required."}, status=403)
                return
            self.send_json(list_users())

        # Module B: Threat Reputation Lookup
        elif path == "/api/threat/lookup":
            target = query.get("target", [""])[0]
            threat = getattr(self.server, "threat", None)
            if threat and target:
                self.send_json(threat.scan_target(target))
            else:
                self.send_json({"error": "Missing target parameter"}, status=400)

        # Module C: Wazuh API Endpoints
        elif path == "/api/wazuh/status":
            wazuh = getattr(self.server, "wazuh", None)
            self.send_json(wazuh.get_status() if wazuh else {"connected": False, "status": "STANDALONE_MODE"})

        elif path == "/api/wazuh/alerts":
            wazuh = getattr(self.server, "wazuh", None)
            limit = int(query.get("limit", [25])[0])
            self.send_json(wazuh.get_alerts(limit=limit) if wazuh else [])

        elif path == "/api/wazuh/endpoints":
            wazuh = getattr(self.server, "wazuh", None)
            self.send_json(wazuh.get_endpoints() if wazuh else {})

        # Module D: HITL Approvals Queue
        elif path == "/api/hitl/pending":
            hitl = getattr(self.server, "hitl", None)
            self.send_json(hitl.list_pending() if hitl else [])

        elif path == "/api/hitl/all":
            hitl = getattr(self.server, "hitl", None)
            self.send_json(hitl.list_all() if hitl else [])

        # Module E: Authorized Security Testing
        elif path == "/api/scans/history":
            scan_engine = getattr(self.server, "scan_engine", None)
            self.send_json(scan_engine.list_history() if scan_engine else [])

        elif path == "/api/scans/allowed":
            scan_engine = getattr(self.server, "scan_engine", None)
            self.send_json({"allowed_targets": scan_engine.get_allowed_targets() if scan_engine else []})

        # Module F: Threat Intelligence STIX Indicators
        elif path == "/api/intel/indicators":
            stix = getattr(self.server, "stix", None)
            ioc_type = query.get("type", [None])[0]
            search = query.get("search", [None])[0]
            limit = int(query.get("limit", [50])[0])
            self.send_json(stix.list_indicators(ioc_type=ioc_type, search=search, limit=limit) if stix else [])

        elif path == "/api/dispatch/latest":
            dispatcher = getattr(self.server, "dispatcher", None)
            self.send_json(dispatcher.get_latest_dispatches(5) if dispatcher else [])

        elif path == "/api/device/vitals":
            device = getattr(self.server, "device", None)
            self.send_json(device.get_system_vitals() if device else {})

        elif path == "/api/device/connections":
            device = getattr(self.server, "device", None)
            self.send_json(device.scan_active_connections() if device else {})

        elif path == "/api/vault/credentials":
            vault = getattr(self.server, "vault", None)
            self.send_json(vault.list_credentials() if vault else [])

        elif path == "/api/voice/speak":
            text_to_speak = query.get("text", [""])[0]
            voice_choice = query.get("voice", ["hi-IN-MadhurNeural"])[0]
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

        # 2. DLP Inspection
        dlp = getattr(self.server, "dlp", None)
        if dlp:
            dlp_res = dlp.scan(body)
            if dlp_res["has_leak"]:
                log_event(client_ip, "DLP", path, "ALERT", dlp_res["highest_risk"], f"Blocked PII leak: {dlp_res['violations_count']} items")

        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        auth_user = self.get_auth_user()

        # 3. Authentication Handlers
        if path == "/api/auth/login":
            username = data.get("username", "")
            password = data.get("password", "")
            res = authenticate_user(username, password, client_ip=client_ip)
            status_code = 200 if res.get("success") else 401
            self.send_json(res, status=status_code)

        # Module A: AI Chat & Incident Reporting
        elif path == "/api/chat":
            copilot = getattr(self.server, "copilot", None)
            prompt = data.get("prompt", "").strip()
            resp_text = copilot.ask(prompt, actor=auth_user["username"]) if copilot else "Police Commander offline."
            self.send_json({"response": resp_text})

        elif path == "/api/ai/explain_alert":
            copilot = getattr(self.server, "copilot", None)
            alert = data.get("alert", {})
            resp_text = copilot.explain_alert(alert) if copilot else "AI Copilot unavailable."
            self.send_json({"explanation": resp_text})

        elif path == "/api/ai/report":
            copilot = getattr(self.server, "copilot", None)
            title = data.get("title", "Security Incident")
            findings = data.get("findings", {})
            report_text = copilot.generate_investigation_report(title, findings) if copilot else "Report generator offline."
            self.send_json({"report": report_text})

        # Module B: Threat Lookup
        elif path == "/api/threat/lookup":
            threat = getattr(self.server, "threat", None)
            target = data.get("target", "").strip()
            if threat and target:
                self.send_json(threat.scan_target(target))
            else:
                self.send_json({"error": "Missing target"}, status=400)

        # Module D: HITL Approvals
        elif path == "/api/hitl/create":
            hitl = getattr(self.server, "hitl", None)
            action_type = data.get("action_type", "GENERIC_ACTION")
            target = data.get("target", "localhost")
            risk_level = data.get("risk_level", "HIGH")
            details = data.get("details", "")
            res = hitl.create_request(action_type, target, risk_level, details, requested_by=auth_user["username"]) if hitl else {}
            self.send_json(res)

        elif path == "/api/hitl/resolve":
            if not check_permission(auth_user["role"], "Admin"):
                self.send_json({"error": "Unauthorized. Only Admin can resolve HITL action requests."}, status=403)
                return
            hitl = getattr(self.server, "hitl", None)
            request_id = data.get("request_id", "")
            decision = data.get("decision", "REJECTED")
            res = hitl.resolve(request_id, decision, resolved_by=auth_user["username"], client_ip=client_ip) if hitl else {}

            # If action was an authorized scan and got approved, execute it now
            if res.get("success") and res.get("decision") == "APPROVED" and res.get("action_type") == "SCAN_TARGET":
                scan_engine = getattr(self.server, "scan_engine", None)
                if scan_engine:
                    scan_engine.perform_scan(res["target"], authorized=True, performed_by=auth_user["username"], client_ip=client_ip)

            self.send_json(res)

        # Module E: Authorized Security Testing
        elif path == "/api/scans/perform":
            target = data.get("target", "").strip()
            authorized = data.get("authorized", False)
            require_hitl = data.get("require_hitl", True)

            # Check if user confirms written authorization
            if not authorized:
                self.send_json({
                    "status": "BLOCKED",
                    "error": "Scan rejected: You must affirmatively confirm written authorization to assess this target."
                }, status=400)
                return

            scan_engine = getattr(self.server, "scan_engine", None)
            if not scan_engine:
                self.send_json({"error": "Scan Engine not initialized"}, status=500)
                return

            # Target allowlist pre-validation
            if not scan_engine.is_target_allowed(target):
                self.send_json({
                    "status": "BLOCKED",
                    "error": f"UNAUTHORIZED TARGET: '{target}' is not in the authorized targets allowlist."
                }, status=403)
                return

            # If user is Analyst or require_hitl is true and user is not Admin, queue for HITL approval
            if require_hitl and not check_permission(auth_user["role"], "Admin"):
                hitl = getattr(self.server, "hitl", None)
                queued = hitl.create_request("SCAN_TARGET", target, "HIGH", f"Defensive audit requested by {auth_user['username']}", requested_by=auth_user["username"])
                self.send_json({
                    "status": "QUEUED_FOR_HITL",
                    "message": "Target authorized, but consequential scan requires Admin approval. Request submitted to HITL queue.",
                    "hitl_details": queued
                })
                return

            # Admin or immediate execution
            result = scan_engine.perform_scan(target, authorized=True, performed_by=auth_user["username"], client_ip=client_ip)
            self.send_json(result)

        # Module F: STIX 2.1 Threat Intel
        elif path == "/api/intel/add":
            if not check_permission(auth_user["role"], "Analyst"):
                self.send_json({"error": "Unauthorized. Analyst role required to add threat indicators."}, status=403)
                return
            stix = getattr(self.server, "stix", None)
            res = stix.add_indicator(
                ioc_type=data.get("type", "domain-name"),
                value=data.get("value", ""),
                confidence=int(data.get("confidence", 80)),
                severity=data.get("severity", "HIGH"),
                mitre_technique=data.get("mitre_technique", "T1071 - Application Layer Protocol"),
                description=data.get("description", "Manual entry"),
                source=data.get("source", "Analyst Submission"),
                added_by=auth_user["username"]
            ) if stix else {}
            self.send_json(res)

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

        elif path == "/api/device/flush_dns":
            device = getattr(self.server, "device", None)
            res = device.flush_dns_cache() if device else {"status": "OFFLINE"}
            self.send_json(res)

        elif path == "/api/device/lock":
            device = getattr(self.server, "device", None)
            res = device.lock_workstation() if device else {"status": "OFFLINE"}
            self.send_json(res)

        elif path == "/api/vault/audit":
            vault = getattr(self.server, "vault", None)
            pwd = data.get("password", "")
            res = vault.audit_password_strength(pwd) if vault else {}
            self.send_json(res)

        elif path == "/api/vault/credentials":
            vault = getattr(self.server, "vault", None)
            res = vault.save_credential(
                data.get("service", "App"),
                data.get("username", "User"),
                data.get("password", ""),
                data.get("master_password", "default_master_key")
            ) if vault else {}
            self.send_json(res)

        elif path == "/api/settings":
            if not check_permission(auth_user["role"], "Admin"):
                self.send_json({"error": "Admin permission required to update settings."}, status=403)
                return
            for k, v in data.items():
                set_setting(k, v)
            log_audit(auth_user["username"], "Admin", "SETTINGS_UPDATED", "System Settings", "SUCCESS", client_ip, f"Updated keys: {list(data.keys())}")
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
