import sys
import os
import threading
import time
import socketserver

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from core.database import init_db, get_setting, set_setting
from core.police_engine import InternetPolice
from core.dns_sinkhole import DNSSinkhole
from core.dlp_guard import DLPGuard
from core.waf_shield import WAFShield
from core.threat_matrix import ThreatMatrix
from core.ai_copilot import InternetPoliceCopilot
from core.nightly_dispatch import NightlyDispatch
from server import InternetPoliceHandler

def banner():
    print("""
 =========================================================================
   🚨 INTERNET POLICE : APPLE 17 SERIES CYBER GUARDIAN SUITE 🚨
 =========================================================================
  [+] Platform       : Cross-Device (Laptop, Phone, Desktop, iPad)
  [+] UI / Theme     : Apple iOS 17 Liquid Glass & Dynamic Island Active
  [+] AI Core        : Free LLM Model (Groq Llama/Qwen, Gemini, OpenRouter)
  [+] Voice Mode     : Jarvis Police Commander (Voice & Speech Recognition)
  [+] Daily Dispatch : Automated 21:00 Nightly Security Briefing Scheduled
  [+] Defense Rules  : Zero Trust, DNS Sinkhole, Quad9 DoH, DLP Guard Active
 =========================================================================
    """)

def run_nightly_scheduler(dispatcher):
    """Background worker checking time for 21:00 (9:00 PM) daily dispatch."""
    while True:
        try:
            now = time.localtime()
            if now.tm_hour == 21 and now.tm_min == 0:
                dispatcher.generate_daily_summary()
                time.sleep(70) # sleep past the minute
            time.sleep(25)
        except Exception:
            time.sleep(30)

def main():
    banner()
    init_db()

    # Pre-seed verified Groq key from aegis-guard if available
    try:
        aegis_db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "aegis-guard", "aegis.db")
        if os.path.exists(aegis_db) and not get_setting("ai_api_key"):
            import sqlite3
            c = sqlite3.connect(aegis_db).cursor()
            c.execute("SELECT value FROM settings WHERE key = 'ai_api_key'")
            row = c.fetchone()
            if row and row[0]:
                set_setting("ai_api_key", row[0])
                set_setting("ai_provider", "groq")
                print(f"[*] Pre-loaded verified Groq API Key into Internet Police suite.")
    except Exception:
        pass

    # Instantiate subsystems
    police = InternetPolice()
    dns = DNSSinkhole(host="127.0.0.1", port=int(get_setting("dns_port", 5353)))
    dlp = DLPGuard()
    waf = WAFShield(max_req_per_min=120)
    threat = ThreatMatrix()
    copilot = InternetPoliceCopilot()
    dispatcher = NightlyDispatch(ai_copilot=copilot)

    # 1. Start DNS Sinkhole thread
    dns_thread = threading.Thread(target=dns.start, daemon=True)
    dns_thread.start()

    # 2. Start Nightly Dispatcher scheduler thread
    scheduler_thread = threading.Thread(target=run_nightly_scheduler, args=(dispatcher,), daemon=True)
    scheduler_thread.start()

    # 3. Start Web Server
    web_port = int(get_setting("web_port", 8080))
    class PoliceServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        def __init__(self, addr, handler):
            super().__init__(addr, handler)
            self.police = police
            self.dns = dns
            self.dlp = dlp
            self.waf = waf
            self.threat = threat
            self.copilot = copilot
            self.dispatcher = dispatcher

    try:
        httpd = PoliceServer(("0.0.0.0", web_port), InternetPoliceHandler)
        print(f"[*] Internet Police Headquarters Live at : http://localhost:{web_port}")
        print(f"[*] Access from phone on local Wi-Fi     : http://<Your-Laptop-IP>:{web_port}")
        print(f"[*] DNS Sinkhole listening on            : 127.0.0.1:{get_setting('dns_port', 5353)} (UDP)")
        print("[*] 24/7 Background Patrol Armed. Press Ctrl+C to terminate.")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Internet Police...")
        dns.stop()
        httpd.shutdown()
        sys.exit(0)

if __name__ == "__main__":
    main()
