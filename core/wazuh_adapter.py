import urllib.request
import urllib.parse
import ssl
import json
import base64
import time
from .database import get_setting, get_recent_logs, log_audit

class WazuhAdapter:
    """
    Wazuh REST API Client Adapter.
    Connects to Wazuh Manager API (:55000) for security alerts, endpoint inventory,
    and agent telemetry. Supports graceful standalone fallback when Wazuh is offline.
    """
    def __init__(self):
        self._token = None
        self._token_expiry = 0

    def _get_config(self):
        return {
            "host": get_setting("wazuh_host", "https://127.0.0.1:55000").rstrip("/"),
            "user": get_setting("wazuh_user", "wazuh-wui"),
            "password": get_setting("wazuh_pass", "").strip()
        }

    def _get_ssl_context(self):
        # SOC self-signed certificate handling
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def authenticate(self) -> bool:
        cfg = self._get_config()
        if not cfg["password"]:
            return False

        auth_url = f"{cfg['host']}/security/user/authenticate"
        auth_bytes = f"{cfg['user']}:{cfg['password']}".encode("utf-8")
        headers = {
            "Authorization": f"Basic {base64.b64encode(auth_bytes).decode('utf-8')}",
            "Content-Type": "application/json"
        }
        try:
            req = urllib.request.Request(auth_url, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=4, context=self._get_ssl_context()) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    token = data.get("data", {}).get("token")
                    if token:
                        self._token = token
                        self._token_expiry = time.time() + 900  # 15 minutes
                        return True
        except Exception:
            self._token = None
            return False
        return False

    def get_status(self) -> dict:
        cfg = self._get_config()
        if not cfg["password"]:
            return {
                "connected": False,
                "status": "STANDALONE_MODE",
                "host": cfg["host"],
                "message": "Wazuh integration in Standalone Mode. Local agent protection active."
            }

        if not self._token or time.time() > self._token_expiry:
            if not self.authenticate():
                return {
                    "connected": False,
                    "status": "UNREACHABLE",
                    "host": cfg["host"],
                    "message": "Unable to connect to Wazuh Manager API. Verify credentials & network."
                }

        return {
            "connected": True,
            "status": "ONLINE",
            "host": cfg["host"],
            "message": "Connected to live Wazuh Manager API."
        }

    def get_alerts(self, limit: int = 25) -> list[dict]:
        status = self.get_status()
        if not status["connected"]:
            # Fallback to local security logs translated into SOC alert schema
            local_logs = get_recent_logs(limit)
            transformed = []
            for item in local_logs:
                transformed.append({
                    "id": f"local_{item.get('id')}",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(item.get("timestamp", time.time()))),
                    "rule": {
                        "id": f"100{item.get('id', 0)}",
                        "level": 12 if item.get("risk_level") == "CRITICAL" else (8 if item.get("risk_level") == "HIGH" else 4),
                        "description": item.get("details", "Local Security Event"),
                        "subsystem": item.get("subsystem", "POLICE")
                    },
                    "agent": {
                        "id": "000",
                        "name": "Host-Workstation-Agent",
                        "ip": item.get("client_ip", "127.0.0.1")
                    },
                    "action": item.get("action", "ALERT"),
                    "source": "Native Host Agent (Standalone)"
                })
            return transformed

        # Live Wazuh Alerts
        url = f"{self._get_config()['host']}/alerts?limit={limit}"
        headers = {"Authorization": f"Bearer {self._token}"}
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5, context=self._get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("data", {}).get("affected_items", [])
        except Exception:
            return []

    def get_endpoints(self) -> dict:
        status = self.get_status()
        if not status["connected"]:
            return {
                "total": 1,
                "active": 1,
                "disconnected": 0,
                "agents": [
                    {
                        "id": "000",
                        "name": "Local-Endpoint-Master",
                        "ip": "127.0.0.1",
                        "status": "active",
                        "os": "Windows / Linux (Native Guard)",
                        "version": "InternetPolice v2.0"
                    }
                ]
            }

        url = f"{self._get_config()['host']}/agents/summary"
        headers = {"Authorization": f"Bearer {self._token}"}
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5, context=self._get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("data", {})
        except Exception:
            return {"total": 0, "active": 0, "disconnected": 0, "agents": []}
